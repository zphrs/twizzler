use std::convert::Infallible;

use crate::{
    consts::SECTOR_SIZE,
    crypter::{Ivg, StatefulCrypter},
    io::{crypt::Error, DataSync, Io, Read, ReadAt, Seek, SeekFrom, Write, WriteAt},
    key::Key,
};

pub struct IvCryptIo<'a, IO, G, C, const BLOCK_SIZE: usize, const KEY_SIZE: usize> {
    pub io: IO,
    key: Key<KEY_SIZE>,
    ivg: &'a mut G,
    crypter: &'a C,
    offset: usize,
}

impl<'a, IO, G, C, const BLOCK_SIZE: usize, const KEY_SIZE: usize>
    IvCryptIo<'a, IO, G, C, BLOCK_SIZE, KEY_SIZE>
where
    IO: Io,
    G: Ivg + 'a,
    C: StatefulCrypter + 'a,
{
    pub fn new(
        mut io: IO,
        key: Key<KEY_SIZE>,
        ivg: &'a mut G,
        crypter: &'a C,
    ) -> Result<Self, <Self as Io>::Error>
    where
        IO: Seek,
    {
        let offset = io.stream_position().map_err(Error::IO)? as usize;
        Ok(Self {
            io,
            key,
            ivg,
            crypter,
            offset,
        })
    }

    fn sector_data_size() -> usize {
        SECTOR_SIZE - C::iv_length()
    }

    // This naming is just to match when we had blocks.
    fn padded_sector_size() -> usize {
        SECTOR_SIZE
    }

    fn logical_sector_index(offset: usize) -> usize {
        offset / Self::sector_data_size()
    }

    fn logical_sector_offset(offset: usize) -> usize {
        Self::logical_sector_index(offset) * Self::sector_data_size()
    }

    fn logical_sector_padding(offset: usize) -> usize {
        offset % Self::sector_data_size()
    }

    fn logical_sector_count(len: usize) -> usize {
        (len + (Self::sector_data_size() - 1)) / Self::sector_data_size()
    }

    fn logical_sector_iv_padding(sectors: usize) -> usize {
        sectors * C::iv_length()
    }

    fn real_sector_offset(offset: usize) -> usize {
        Self::logical_sector_index(offset) * Self::padded_sector_size()
    }

    fn real_sector_count(len: usize) -> usize {
        (len + (Self::padded_sector_size() - 1)) / Self::padded_sector_size()
    }

    fn read_inner(
        &mut self,
        buf: &mut [u8],
        origin: usize,
    ) -> Result<(usize, usize), <Self as Io>::Error>
    where
        IO: ReadAt,
    {
        // We might be reading from an offset that isn't sector-aligned. This
        // means we need to read in extra bytes to account for the padding in
        // the first sector that causes the unalignment.
        let padding = Self::logical_sector_padding(origin);
        let total_sectors = Self::logical_sector_count(padding + buf.len());
        let total_bytes = padding + buf.len() + Self::logical_sector_iv_padding(total_sectors);
        let start_offset = Self::real_sector_offset(origin);
        let start_sector = Self::logical_sector_index(origin);

        // Read in the requested bytes.
        let mut ct = vec![0; total_bytes];
        let n = self
            .io
            .read_at(&mut ct, start_offset as u64)
            .map_err(Error::IO)?;

        // Advance our offset, truncate the ciphertext.
        // We may have read less than the total.
        ct.truncate(n);

        // Decrypt each sector and copy the contents to the buffer.
        let mut ct_slice = ct.as_mut_slice();
        let mut pt = Vec::with_capacity(padding + buf.len());
        for _sector in start_sector.. {
            // Nothing left to decrypt.
            if ct_slice.is_empty() {
                break;
            }

            // Decrypt the sector.
            let len = ct_slice.len().min(Self::padded_sector_size());
            let (iv, data) = ct_slice[0..len].split_at_mut(C::iv_length());
            self.crypter
                .decrypt(&self.key, iv, data)
                .map_err(Error::Crypter)?;
            pt.extend_from_slice(&data);

            // Advance the slice.
            ct_slice = &mut ct_slice[len..];
        }

        // Copy over the truly read bytes.
        let count = pt[padding..].len();
        buf[..count].copy_from_slice(&pt[padding..]);

        Ok((count, origin + count))
    }

    fn write_inner(
        &mut self,
        buf: &[u8],
        origin: usize,
    ) -> Result<(usize, usize), <Self as Io>::Error>
    where
        IO: ReadAt + WriteAt,
    {
        // We might be writing from an offset that isn't sector-aligned. This
        // means that we need to rewrite the padding in the first sector that
        // causes the unalignment.
        let padding = Self::logical_sector_padding(origin);
        let total_sectors = Self::logical_sector_count(padding + buf.len());
        let total_bytes = padding + buf.len() + Self::logical_sector_iv_padding(total_sectors);
        let start_offset = Self::real_sector_offset(origin);

        let mut real_padding = 0;
        let mut pt = Vec::with_capacity(padding + buf.len());

        // We have padding we need to rewrite.
        if padding > 0 {
            let mut to_read = padding;
            let mut rewrite = vec![0; Self::sector_data_size()];
            while to_read > 0 {
                // Start reading at the logical sector.
                let read_offset = Self::logical_sector_offset(origin);

                // Read the padding bytes.
                let n = self.read_at(&mut rewrite[..to_read], read_offset as u64)?;
                if n == 0 {
                    break;
                }

                // Add the padding bytes.
                pt.extend_from_slice(&rewrite[..n]);
                to_read -= n;
                real_padding += n;
            }
        }

        // Copy in the bytes that we're trying to write.
        pt.extend_from_slice(buf);

        // If the end of the write isn't aligned, we have to rewrite the bytes
        // in the final block.
        let last_sector_index = Self::logical_sector_offset(pt.len());
        let last_sector_offset = Self::logical_sector_offset(origin) + last_sector_index;
        let extra = Self::logical_sector_padding(pt.len());
        let mut real_extra = 0;
        if extra > 0 {
            let mut rewrite = vec![0; Self::sector_data_size()];
            if let Ok(n) = self.read_at(&mut rewrite, last_sector_offset as u64) {
                if n > extra {
                    pt.extend_from_slice(&rewrite[extra..n]);
                    real_extra = rewrite[extra..n].len();
                }
            }
        }

        // Encrypt each block of plaintext.
        let mut iv = vec![0; C::iv_length()];
        let mut ct = Vec::with_capacity(total_bytes);
        let mut pt_slice = pt.as_mut_slice();
        while !pt_slice.is_empty() {
            // Add a new IV and block to the ciphertext.
            self.ivg.gen(&mut iv).map_err(Error::IV)?;
            let len = pt_slice.len().min(Self::sector_data_size());
            self.crypter
                .encrypt(&self.key, &iv, &mut pt_slice[..len])
                .map_err(Error::Crypter)?;
            ct.extend_from_slice(&iv);
            ct.extend_from_slice(&pt_slice[..len]);

            // Advance the slice.
            pt_slice = &mut pt_slice[len..];
        }

        // Write the ciphertext.
        let n = self
            .io
            .write_at(&ct, start_offset as u64)
            .map_err(Error::IO)?;

        // Get the actual bytes written.
        // We remove the padding at the front, the IV padding, and the truly
        // extra rewritten bytes at the end.
        let count = n.saturating_sub(
            real_padding + Self::logical_sector_iv_padding(Self::real_sector_count(n)) + real_extra,
        );
        self.offset = origin + count;

        Ok((count, origin + count))
    }
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
    C: StatefulCrypter,
    G: Ivg,
{
    type Error = Error<IO::Error, C::Error, G::Error, Infallible>;
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt,
    G: Ivg,
    C: StatefulCrypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.read_inner(buf, self.offset).map(|(n, offset)| {
            self.offset = offset;
            n
        })
    }
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> ReadAt
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt,
    G: Ivg,
    C: StatefulCrypter,
{
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, Self::Error> {
        self.read_inner(buf, offset as usize).map(|(n, _offset)| n)
    }
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt + WriteAt,
    G: Ivg,
    C: StatefulCrypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.write_inner(buf, self.offset).map(|(n, offset)| {
            self.offset = offset;
            n
        })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush().map_err(Error::IO)
    }
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> WriteAt
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt + WriteAt,
    G: Ivg,
    C: StatefulCrypter,
{
    fn write_at(&mut self, buf: &[u8], offset: u64) -> Result<usize, Self::Error> {
        self.write_inner(buf, offset as usize).map(|(n, _offset)| n)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush().map_err(Error::IO)
    }
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: Seek,
    G: Ivg,
    C: StatefulCrypter,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        let offset = self.io.seek(pos).map_err(Error::IO)?;
        self.offset = offset as usize;
        Ok(offset)
    }
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> DataSync
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: DataSync,
    G: Ivg,
    C: StatefulCrypter,
{
    fn sync_all(&self) -> Result<(), Self::Error> {
        self.io.sync_all().map_err(Error::IO)
    }

    fn sync_data(&self) -> Result<(), Self::Error> {
        self.io.sync_data().map_err(Error::IO)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use rand::{rngs::ThreadRng, Rng, RngCore};

    use crate::{
        consts::{BLOCK_SIZE, KEY_SIZE},
        crypter::{aes::Aes256Ctr, ivs::SequentialIvg},
        io::{crypt::testing::*, stdio::StdIo},
    };

    use super::*;

    struct Config {
        io: StdIo<File>,
        ivg: SequentialIvg,
        crypter: Aes256Ctr,
    }

    fn generate_conf(name: &str) -> (Config, String) {
        let file_path = format!("/tmp/{name}");

        let _ = fs::remove_file(&file_path);

        (
            Config {
                io: StdIo::new(
                    File::options()
                        .read(true)
                        .write(true)
                        .truncate(true)
                        .create(true)
                        .open(&file_path)
                        .unwrap(),
                ),
                ivg: SequentialIvg::default(),
                crypter: Aes256Ctr::default(),
            },
            file_path,
        )
    }

    fn generate_io<'a>(
        config: &'a mut Config,
    ) -> IvCryptIo<'_, &'a mut StdIo<File>, SequentialIvg, Aes256Ctr, BLOCK_SIZE, KEY_SIZE> {
        IvCryptIo::new(&mut config.io, ROOT_KEY, &mut config.ivg, &config.crypter).unwrap()
    }

    cryptio_padded_test_impl!(
        "ivcrypt",
        generate_conf,
        generate_io,
        Aes256Ctr::iv_length()
    );
}
