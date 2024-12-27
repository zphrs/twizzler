use std::{convert::Infallible, ops::Range};

use crate::{
    consts::{SECTOR_SIZE, SPECULATION_CHUNK_SIZE, VERSION_SIZE},
    crypter::{Ivg, StatefulCrypter},
    io::{ReadAt, WriteAt},
    key::Key,
    AffineKeyManagementScheme,
};

use super::Error;

pub struct VersionedPreCryptAt<'a, IO, C, const BLOCK_SIZE: usize, const KEY_SIZE: usize> {
    io: IO,
    recrypter: PreRecrypter<'a, C, KEY_SIZE>,
}

impl<'a, IO, C, const BLOCK_SIZE: usize, const KEY_SIZE: usize>
    VersionedPreCryptAt<'a, IO, C, BLOCK_SIZE, KEY_SIZE>
where
    IO: ReadAt + WriteAt,
    C: StatefulCrypter + 'a,
{
    pub fn new<G, K>(
        version: u64,
        len: usize,
        origin: usize,
        raw_io: IO,
        kms: &mut K,
        crypter: &'a C,
        for_write: bool,
    ) -> Result<Self, Error<IO::Error, C::Error, G::Error, K::Error>>
    where
        K: AffineKeyManagementScheme<G, C, KEY_SIZE, KeyId = u64>,
        G: Ivg,
    {
        // Get the range of sectors and blocks that the IO covers.
        // We add one to the end block since we want it to be non-inclusive.
        let (start_sector, end_sector) = Self::sector_range(origin, len);
        let start_block = Self::logical_sector_to_block(start_sector);
        let end_block = Self::logical_sector_to_block(end_sector) + 1;
        // eprintln!("START_SECTOR: {start_sector}, END_SECTOR: {end_sector}");
        // eprintln!("START_BLOCK: {start_block}, END_BLOCK: {end_block}");

        // Convert speculation range to blocks.
        // We add one to the end block since we want it to be non-inclusive.
        let (spec_start_sector, spec_end_sector) = Self::speculation_range(origin, len);
        let spec_start_block = Self::logical_sector_to_block(spec_start_sector);
        let spec_end_block = Self::logical_sector_to_block(spec_end_sector) + 1;
        // eprintln!("SPEC RANGE: offset={origin}, len={len}, start_block={spec_start_sector}, end_block={spec_end_sector}");

        assert!(
            spec_start_sector <= start_sector && end_sector <= spec_end_sector,
            "OFFSET {origin}, LEN {len}, START {start_sector}, END {end_sector}, SPEC_START {spec_start_sector}, SPEC_END {spec_end_sector}",
        );

        // If this is intended for a write, we don't need to derive any read keys.
        let read_keys = if for_write {
            vec![]
        } else {
            kms.derive_read_key_many(start_block as u64, end_block as u64)
                .map_err(Error::KMS)?
        };

        // We need write keys on read as well as writes since some blocks might
        // be overwritten in-place.
        let write_keys = kms
            .derive_write_key_many(
                start_block as u64,
                end_block as u64,
                Some((spec_start_block as u64, spec_end_block as u64)),
            )
            .map_err(Error::KMS)?;

        let recrypter = PreRecrypter {
            version,
            block_range: start_block..end_block,
            read_keys,
            write_keys,
            crypter,
        };

        Ok(Self {
            io: raw_io,
            recrypter,
        })
    }

    const fn sector_data_size() -> usize {
        SECTOR_SIZE - VERSION_SIZE
    }

    // This naming is just to match when we had blocks.
    const fn padded_sector_size() -> usize {
        SECTOR_SIZE
    }

    const fn logical_sector_index(offset: usize) -> usize {
        offset / Self::sector_data_size()
    }

    const fn logical_sector_offset(offset: usize) -> usize {
        Self::logical_sector_index(offset) * Self::sector_data_size()
    }

    const fn logical_sector_padding(offset: usize) -> usize {
        offset % Self::sector_data_size()
    }

    const fn logical_sector_count(len: usize) -> usize {
        (len + (Self::sector_data_size() - 1)) / Self::sector_data_size()
    }

    const fn logical_sector_version_padding(sectors: usize) -> usize {
        sectors * VERSION_SIZE
    }

    const fn logical_sector_to_block(sector: usize) -> usize {
        (sector * Self::sector_data_size()) / BLOCK_SIZE
    }

    const fn real_sector_offset(offset: usize) -> usize {
        Self::logical_sector_index(offset) * Self::padded_sector_size()
    }

    const fn real_sector_count(len: usize) -> usize {
        (len + (Self::padded_sector_size() - 1)) / Self::padded_sector_size()
    }

    const fn sector_range(offset: usize, len: usize) -> (usize, usize) {
        let padding = Self::logical_sector_padding(offset);
        let sectors = Self::logical_sector_count(padding + len);
        let start_sector = Self::logical_sector_index(offset);
        (start_sector, start_sector + sectors)
    }

    const fn speculation_range(offset: usize, len: usize) -> (usize, usize) {
        let chunk_index = offset / SPECULATION_CHUNK_SIZE;
        let chunk_padding = offset % SPECULATION_CHUNK_SIZE;
        let chunk_offset = chunk_index * SPECULATION_CHUNK_SIZE;
        let chunks_needed =
            (chunk_padding + len + (SPECULATION_CHUNK_SIZE - 1)) / SPECULATION_CHUNK_SIZE;
        Self::sector_range(chunk_offset, chunks_needed * SPECULATION_CHUNK_SIZE)
    }

    pub fn read_at(
        &mut self,
        buf: &mut [u8],
        origin: usize,
    ) -> Result<usize, Error<IO::Error, C::Error, Infallible, Infallible>>
    where
        IO: ReadAt,
    {
        // We might be reading from an offset that isn't sector-aligned. This
        // means we need to read in extra bytes to account for the padding in
        // the first sector that causes the unalignment.
        let padding = Self::logical_sector_padding(origin);
        let total_sectors = Self::logical_sector_count(padding + buf.len());
        let total_bytes = padding + buf.len() + Self::logical_sector_version_padding(total_sectors);
        let start_offset = Self::real_sector_offset(origin);
        let start_sector = Self::logical_sector_index(origin);

        // Read in the requested bytes.
        let mut ct = vec![0; total_bytes];
        let n = self
            .io
            .read_at(&mut ct, start_offset as u64)
            .map_err(Error::IO)?;

        // Truncate the ciphertext. We may have read less than the total.
        ct.truncate(n);

        // Decrypt each sector and copy the contents to the buffer.
        let mut ct_slice = ct.as_mut_slice();
        let mut pt = Vec::with_capacity(padding + buf.len());
        for sector in start_sector.. {
            // The block the sectors falls under.
            let block = Self::logical_sector_to_block(sector);

            // Nothing left to decrypt.
            if ct_slice.is_empty() {
                break;
            }

            // Decrypt the sector.
            let len = ct_slice.len().min(Self::padded_sector_size());
            let (version, data) = ct_slice[0..len].split_at_mut(VERSION_SIZE);
            let version = u64::from_le_bytes(version.try_into().unwrap());
            self.recrypter
                .decrypt(version, data, block)
                .map_err(Error::Crypter)?;
            pt.extend_from_slice(data);

            // Advance the slice.
            ct_slice = &mut ct_slice[len..];
        }

        // Copy over the truly read bytes.
        let count = pt[padding..].len();
        buf[..count].copy_from_slice(&pt[padding..]);

        Ok(count)
    }

    pub fn write_at(
        &mut self,
        buf: &[u8],
        origin: usize,
    ) -> Result<usize, Error<IO::Error, C::Error, Infallible, Infallible>>
    where
        IO: ReadAt + WriteAt,
    {
        // We might be writing from an offset that isn't sector-aligned. This
        // means that we need to rewrite the padding in the first sector that
        // causes the unalignment.
        let padding = Self::logical_sector_padding(origin);
        let total_sectors = Self::logical_sector_count(padding + buf.len());
        let total_bytes = padding + buf.len() + Self::logical_sector_version_padding(total_sectors);
        let start_offset = Self::real_sector_offset(origin);
        let mut start_sector = Self::logical_sector_index(origin);

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
                let n = self.read_at(&mut rewrite[..to_read], read_offset)?;
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
            if let Ok(n) = self.read_at(&mut rewrite, last_sector_offset) {
                if n > extra {
                    pt.extend_from_slice(&rewrite[extra..n]);
                    real_extra = rewrite[extra..n].len();
                }
            }
        }

        // Encrypt each sector of plaintext.
        let mut ct = Vec::with_capacity(total_bytes);
        let mut pt_slice = pt.as_mut_slice();
        while !pt_slice.is_empty() {
            // The block that the sector falls under.
            let block = Self::logical_sector_to_block(start_sector);

            // Add a new IV and sector to the ciphertext.
            let len = pt_slice.len().min(Self::sector_data_size());
            self.recrypter
                .encrypt(&mut pt_slice[..len], block)
                .map_err(Error::Crypter)?;
            ct.extend_from_slice(&self.recrypter.version.to_le_bytes());
            ct.extend_from_slice(&pt_slice[..len]);
            start_sector += 1;

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
            real_padding
                + Self::logical_sector_version_padding(Self::real_sector_count(n))
                + real_extra,
        );

        Ok(count)
    }
}

struct PreRecrypter<'a, C, const KEY_SIZE: usize> {
    pub version: u64,
    pub block_range: Range<usize>,
    pub read_keys: Vec<(u64, Key<KEY_SIZE>)>,
    pub write_keys: Vec<(u64, Key<KEY_SIZE>)>,
    pub crypter: &'a C,
}

impl<C: StatefulCrypter, const KEY_SIZE: usize> PreRecrypter<'_, C, KEY_SIZE> {
    fn encrypt(&mut self, data: &mut [u8], block: usize) -> Result<(), C::Error> {
        assert!(
            self.block_range.contains(&block),
            "out-of-bounds block for encrypter: {block}, range: {:?}",
            self.block_range
        );

        let (_, key) = self
            .write_keys
            .get(block - self.block_range.start)
            .expect(&format!("missing block key: {block}"));

        self.crypter.onetime_encrypt(key, data)
    }

    fn decrypt(&mut self, version: u64, data: &mut [u8], block: usize) -> Result<(), C::Error> {
        assert!(
            self.block_range.contains(&block),
            "out-of-bounds for decrypter: {block}, range: {:?}",
            self.block_range
        );

        // If the block's version is greater than our current version, then the
        // key that decrypts is write key (produced by the KMS's KDF).
        let (_, key) = if version < self.version {
            self.read_keys
                .get(block - self.block_range.start)
                .expect(&format!(
                "missing block read key: {block}, block version: {version}, current version: {}",
                self.version
            ))
        } else {
            self.write_keys
                .get(block - self.block_range.start)
                .expect(&format!(
                "missing block write key: {block}, block version: {version}, current version: {}",
                self.version
            ))
        };

        self.crypter.onetime_decrypt(key, data)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        marker::PhantomData,
    };

    use rand::{rngs::ThreadRng, Rng, RngCore};

    use crate::{
        ahashmap::AffineKeyMap,
        consts::{BLOCK_SIZE, KEY_SIZE},
        crypter::{aes::Aes256Ctr, ivs::SequentialIvg},
        io::{stdio::StdIo, Io, Read, Seek, SeekFrom, Write},
        kdf::blake3::Blake3KDF,
    };

    use super::{super::testing::*, *};

    pub struct VersionedTwoStageIo<'a, IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize>
    where
        KMS: AffineKeyManagementScheme<G, C, KEY_SZ>,
    {
        version: u64,
        io: IO,
        kms: &'a mut KMS,
        crypter: &'a C,
        cursor: usize,
        _pd: PhantomData<G>,
    }

    impl<'a, IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize>
        VersionedTwoStageIo<'a, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: Seek,
        KMS: AffineKeyManagementScheme<G, C, KEY_SZ>,
        G: Ivg,
        C: StatefulCrypter,
    {
        pub fn new(
            mut io: IO,
            kms: &'a mut KMS,
            crypter: &'a C,
            version: u64,
        ) -> Result<Self, <Self as Io>::Error> {
            let cursor = io.stream_position().map_err(Error::IO)?;
            Ok(Self {
                version,
                io,
                kms,
                crypter,
                cursor: cursor as usize,
                _pd: PhantomData,
            })
        }
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
        for VersionedTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: Io,
        KMS: AffineKeyManagementScheme<G, C, KEY_SZ>,
        G: Ivg,
        C: StatefulCrypter,
    {
        type Error = Error<IO::Error, C::Error, G::Error, KMS::Error>;
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
        for VersionedTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: ReadAt + WriteAt,
        KMS: AffineKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
        G: Ivg,
        C: StatefulCrypter,
    {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let n = self.read_at(buf, self.cursor as u64)?;
            self.cursor += n;
            Ok(n)
        }
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> ReadAt
        for VersionedTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: ReadAt + WriteAt,
        KMS: AffineKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
        G: Ivg,
        C: StatefulCrypter,
    {
        fn read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, Self::Error> {
            let mut pre = VersionedPreCryptAt::<_, _, BLK_SZ, KEY_SZ>::new(
                self.version,
                buf.len(),
                offset as usize,
                &mut self.io,
                self.kms,
                self.crypter,
                false,
            )?;

            pre.read_at(buf, offset as usize)
                .map_err(|_| Error::PreCrypt)
        }
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
        for VersionedTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: ReadAt + WriteAt,
        KMS: AffineKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
        G: Ivg,
        C: StatefulCrypter,
    {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            let n = self.write_at(buf, self.cursor as u64)?;
            self.cursor += n;
            Ok(n)
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            self.io.flush().map_err(Error::IO)
        }
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> WriteAt
        for VersionedTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: ReadAt + WriteAt,
        KMS: AffineKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
        G: Ivg,
        C: StatefulCrypter,
    {
        fn write_at(&mut self, buf: &[u8], offset: u64) -> Result<usize, Self::Error> {
            let mut pre = VersionedPreCryptAt::<_, _, BLK_SZ, KEY_SZ>::new(
                self.version,
                buf.len(),
                offset as usize,
                &mut self.io,
                self.kms,
                self.crypter,
                true,
            )?;

            let n = pre
                .write_at(buf, offset as usize)
                .map_err(|_| Error::PreCrypt)?;

            Ok(n)
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            self.io.flush().map_err(Error::IO)
        }
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek
        for VersionedTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: Seek,
        KMS: AffineKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
        G: Ivg,
        C: StatefulCrypter,
    {
        fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
            let cursor = self.io.seek(pos).map_err(Error::IO)?;
            self.cursor = cursor as usize;
            Ok(cursor)
        }
    }

    struct Config {
        io: StdIo<File>,
        kms: AffineKeyMap<Blake3KDF, ThreadRng, KEY_SIZE>,
        crypter: Aes256Ctr,
    }

    fn generate_conf(name: &str) -> (Config, String) {
        let wal_path = format!("/tmp/{name}.log");
        let file_path = format!("/tmp/{name}");

        let _ = fs::remove_file(&wal_path);
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
                kms: AffineKeyMap::new(ThreadRng::default()),
                crypter: Aes256Ctr::default(),
            },
            file_path,
        )
    }

    // fn generate_io<'a>(
    //     config: &'a mut Config,
    // ) -> VersionedTwoStageIo<
    //     '_,
    //     &'a mut StdIo<File>,
    //     AffineKeyMap<Blake3KDF, ThreadRng, KEY_SIZE>,
    //     SequentialIvg,
    //     Aes256Ctr,
    //     BLOCK_SIZE,
    //     KEY_SIZE,
    // > {
    //     VersionedTwoStageIo::new(&mut config.io, &mut config.kms, &config.crypter, 0).unwrap()
    // }

    // cryptio_padded_test_impl!(
    //     "twostage-versioned",
    //     generate_conf,
    //     generate_io,
    //     std::mem::size_of::<u64>()
    // );
}
