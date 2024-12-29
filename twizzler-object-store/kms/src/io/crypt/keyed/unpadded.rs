use std::convert::Infallible;

use crate::{
    crypter::StatefulCrypter,
    io::{
        crypt::{self, Error},
        DataSync, Io, Read, ReadAt, Seek, SeekFrom, Write, WriteAt,
    },
    key::Key,
};

pub struct CryptIo<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    pub io: IO,
    key: Key<KEY_SZ>,
    crypter: &'a C,
    offset: usize,
}

impl<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> CryptIo<'a, IO, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
    C: StatefulCrypter,
{
    pub fn new(mut io: IO, key: Key<KEY_SZ>, crypter: &'a C) -> Result<Self, <Self as Io>::Error>
    where
        IO: Seek,
    {
        let offset = io.stream_position().map_err(Error::IO)? as usize;
        Ok(Self {
            io,
            key,
            crypter,
            offset,
        })
    }

    fn logical_block_index(&self, offset: usize) -> usize {
        offset / BLK_SZ
    }

    fn logical_block_offset(&self, offset: usize) -> usize {
        self.logical_block_index(offset) * BLK_SZ
    }

    fn logical_block_padding(&self, offset: usize) -> usize {
        offset % BLK_SZ
    }

    fn read_inner(
        &mut self,
        buf: &mut [u8],
        origin: usize,
    ) -> Result<(usize, usize), <Self as Io>::Error>
    where
        IO: ReadAt,
    {
        // We might be reading from an offset that isn't block-aligned. This
        // means we need to read in extra bytes to account for the padding in
        // the first block that causes the unalignment.
        let padding = self.logical_block_padding(origin);
        let total = padding + buf.len();
        let start_offset = self.logical_block_offset(origin);
        let start_block = self.logical_block_index(origin);

        // Read in the requested bytes.
        let mut ct = vec![0; total];
        let n = self
            .io
            .read_at(&mut ct, start_offset as u64)
            .map_err(Error::IO)?;

        // Advance our offset, truncate the ciphertext.
        // We may have read less than the total.
        ct.truncate(n);

        // Decrypt each block and copy the contents to the buffer.
        let mut ct_slice = ct.as_mut_slice();
        let mut pt = Vec::with_capacity(padding + buf.len());
        for _block in start_block.. {
            // Nothing left to decrypt.
            if ct_slice.is_empty() {
                break;
            }

            // Decrypt the block.
            let len = ct_slice.len().min(BLK_SZ);
            let data = &mut ct_slice[..len];
            self.crypter
                .onetime_decrypt(&self.key, data)
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
        // We might be writing from an offset that isn't block-aligned. This
        // means that we need to rewrite the padding in the first block that
        // causes the unalignment.
        let padding = self.logical_block_padding(origin);
        let total = padding + buf.len();
        let start_offset = self.logical_block_offset(origin);

        let mut real_padding = 0;
        let mut pt = Vec::with_capacity(padding + buf.len());

        // We have padding we need to rewrite.
        if padding > 0 {
            let mut to_read = padding;
            let mut rewrite = [0; BLK_SZ];
            while to_read > 0 {
                // Start reading at the logical block.
                let read_offset = self.logical_block_offset(origin);

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
        let last_block_index = self.logical_block_offset(pt.len());
        let last_block_offset = self.logical_block_offset(origin) + last_block_index;
        let extra = self.logical_block_padding(pt.len());
        let mut real_extra = 0;
        if extra > 0 {
            let mut rewrite = [0; BLK_SZ];
            if let Ok(n) = self.read_at(&mut rewrite, last_block_offset as u64) {
                if n > extra {
                    pt.extend_from_slice(&rewrite[extra..n]);
                    real_extra = rewrite[extra..n].len();
                }
            }
        }

        // Encrypt each block of plaintext.
        let mut ct = Vec::with_capacity(total);
        let mut pt_slice = pt.as_mut_slice();
        while !pt_slice.is_empty() {
            // Add a new IV and block to the ciphertext.
            let len = pt_slice.len().min(BLK_SZ);
            self.crypter
                .onetime_encrypt(&self.key, &mut pt_slice[..len])
                .map_err(Error::Crypter)?;
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
        // We remove the padding at the front and the truly extra rewritten
        // bytes at the end.
        let count = n.saturating_sub(real_padding + real_extra);
        self.offset = origin + count;

        Ok((count, origin + count))
    }
}

impl<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Io for CryptIo<'a, IO, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
    C: StatefulCrypter,
{
    type Error = Error<IO::Error, C::Error, Infallible, Infallible>;
}

impl<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
    for CryptIo<'a, IO, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt + Seek,
    C: StatefulCrypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.read_inner(buf, self.offset).map(|(n, offset)| {
            self.offset = offset;
            n
        })
    }
}

impl<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> ReadAt
    for CryptIo<'a, IO, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt,
    C: StatefulCrypter,
{
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, Self::Error> {
        self.read_inner(buf, offset as usize).map(|(n, _offset)| n)
    }
}

impl<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
    for CryptIo<'a, IO, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt + WriteAt,
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

impl<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> WriteAt
    for CryptIo<'a, IO, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt + WriteAt,
    C: StatefulCrypter,
{
    fn write_at(&mut self, buf: &[u8], offset: u64) -> Result<usize, Self::Error> {
        self.write_inner(buf, offset as usize).map(|(n, _offset)| n)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush().map_err(Error::IO)
    }
}

impl<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek
    for CryptIo<'a, IO, C, BLK_SZ, KEY_SZ>
where
    IO: Seek,
    C: StatefulCrypter,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        let offset = self.io.seek(pos).map_err(Error::IO)?;
        self.offset = offset as usize;
        Ok(offset)
    }
}

impl<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> DataSync
    for CryptIo<'a, IO, C, BLK_SZ, KEY_SZ>
where
    IO: DataSync,
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
    use anyhow::Result;
    use rand::rngs::ThreadRng;
    use tempfile::NamedTempFile;

    use crate::{
        consts::{BLOCK_SIZE, KEY_SIZE},
        crypter::aes::Aes256Ctr,
        io::stdio::StdIo,
        key::KeyGenerator,
    };

    use super::*;

    #[test]
    fn it_works() -> Result<()> {
        let mut rng = ThreadRng::default();
        let crypter = Aes256Ctr::new();

        let key = rng.gen_key();

        let mut io = CryptIo::<StdIo<NamedTempFile>, Aes256Ctr, BLOCK_SIZE, KEY_SIZE>::new(
            StdIo::new(NamedTempFile::new()?),
            key,
            &crypter,
        )
        .unwrap();

        // let data1 = vec!['a' as u8; 8192];
        // io.seek(SeekFrom::Start(0))?;
        // io.write_all(&data1)?;

        // let mut data2 = vec![];
        // io.seek(SeekFrom::Start(0))?;
        // io.read_to_end(&mut data2)?;

        // assert_eq!(data1, data2);

        Ok(())
    }

    #[test]
    fn it_works_at() -> Result<()> {
        // let mut rng = ThreadRng::default();
        // let crypter = Aes256Ctr::new();

        // let key = rng.gen_key();

        // let mut io = CryptIo::<StdIo<NamedTempFile>, Aes256Ctr, BLOCK_SIZE, KEY_SIZE>::new(
        //     StdIo::new(NamedTempFile::new()?),
        //     key,
        //     &crypter,
        // )
        // .unwrap();

        // let data1 = vec!['a' as u8; 8192];
        // io.write_all_at(&data1, 0)?;

        // let mut data2 = vec![];
        // io.read_to_end_at(&mut data2, 0)?;

        // assert_eq!(data1, data2);

        Ok(())
    }
}
