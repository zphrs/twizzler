use std::{convert::Infallible, ops::Range};

use crate::{
    crypter::{Ivg, StatefulCrypter},
    io::{ReadAt, WriteAt},
    key::{Key, KeyWrapper},
    wal::SecureWAL,
    JournalEntry, UnstableKeyManagementScheme,
};

use super::Error;

struct PreRecrypter<'a, C, const KEY_SZ: usize> {
    read_keys: Vec<Key<KEY_SZ>>,
    write_keys: Vec<Key<KEY_SZ>>,
    block_range: Range<usize>,
    crypter: &'a C,
}

impl<C, const KEY_SZ: usize> PreRecrypter<'_, C, KEY_SZ> {
    fn get_block_write_key(&self, block: usize) -> Key<KEY_SZ> {
        self.write_keys[block - self.block_range.start]
    }
}

impl<C: StatefulCrypter, const KEY_SZ: usize> PreRecrypter<'_, C, KEY_SZ> {
    fn onetime_encrypt(&mut self, data: &mut [u8], block: usize) -> Result<(), C::Error> {
        assert!(
            self.block_range.contains(&block),
            "out-of-bounds sector for encrypter: {block}, range: {:?}",
            self.block_range
        );

        let key = &self.write_keys[block - self.block_range.start];
        self.crypter.onetime_encrypt(key, data)
    }

    fn onetime_decrypt(&mut self, data: &mut [u8], block: usize) -> Result<(), C::Error> {
        assert!(
            self.block_range.contains(&block),
            "out-of-bounds sector for decrypter: {block}, range: {:?}",
            self.block_range
        );

        let key = &self.read_keys[block - self.block_range.start];
        self.crypter.onetime_decrypt(key, data)
    }
}

pub struct JournaledPreCryptAt<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    root_key: Key<KEY_SZ>,
    io: IO,
    inode: u64,
    kms_wal: &'a SecureWAL<JournalEntry<KEY_SZ>, G, C, KEY_SZ>,
    recrypter: PreRecrypter<'a, C, KEY_SZ>,
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize>
    JournaledPreCryptAt<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt + WriteAt,
    G: Ivg + 'a,
    C: StatefulCrypter + 'a,
{
    pub fn new<KMS>(
        root_key: Key<KEY_SZ>,
        inode: u64,
        len: usize,
        origin: usize,
        raw_io: IO,
        kms: &mut KMS,
        kms_wal: &'a SecureWAL<KMS::LogEntry, G, C, KEY_SZ>,
        for_read: bool,
        crypter: &'a C,
    ) -> Result<Self, Error<IO::Error, C::Error, G::Error, KMS::Error>>
    where
        KMS: UnstableKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
    {
        let block_range = Self::block_range(len, origin);

        let (read_keys, write_keys) = if for_read {
            let mut read_keys = Vec::with_capacity(block_range.len());
            let write_keys = vec![];

            for block in block_range.clone() {
                let key = match kms.derive(block as u64).map_err(Error::KMS)? {
                    Some(key) => key,
                    None => break,
                };
                read_keys.push(key);
            }

            (read_keys, write_keys)
        } else {
            let mut read_keys = Vec::with_capacity(block_range.len());
            let mut write_keys = Vec::with_capacity(block_range.len());

            for block in block_range.clone() {
                let key = match kms.derive(block as u64).map_err(Error::KMS)? {
                    Some(key) => key,
                    None => break,
                };
                read_keys.push(key);
            }

            for block in block_range.clone() {
                let key = kms.derive_mut(block as u64).map_err(Error::KMS)?;
                write_keys.push(key);
            }

            (read_keys, write_keys)
        };

        Ok(Self {
            root_key,
            io: raw_io,
            inode,
            kms_wal,
            recrypter: PreRecrypter {
                read_keys,
                write_keys,
                block_range,
                crypter,
            },
        })
    }

    fn logical_block_index(offset: usize) -> usize {
        offset / BLK_SZ
    }

    fn logical_block_offset(offset: usize) -> usize {
        Self::logical_block_index(offset) * BLK_SZ
    }

    fn logical_block_padding(offset: usize) -> usize {
        offset % BLK_SZ
    }

    fn logical_block_count(len: usize) -> usize {
        (len + (BLK_SZ - 1)) / BLK_SZ
    }

    fn block_range(len: usize, offset: usize) -> Range<usize> {
        let padding = Self::logical_block_padding(offset);
        let blocks = Self::logical_block_count(padding + len);
        let start_block = Self::logical_block_index(offset);
        start_block..start_block + blocks
    }

    pub fn read_at(
        &mut self,
        buf: &mut [u8],
        origin: usize,
    ) -> Result<usize, Error<IO::Error, C::Error, Infallible, Infallible>>
    where
        IO: ReadAt,
    {
        // We might be reading from an offset that isn't block-aligned. This
        // means we need to read in extra bytes to account for the padding in
        // the first block that causes the unalignment.
        let padding = Self::logical_block_padding(origin);
        let total = padding + buf.len();
        let start_offset = Self::logical_block_offset(origin);
        let start_block = Self::logical_block_index(origin);

        // Read in the requested bytes.
        let mut ct = vec![0; total];
        let n = self
            .io
            .read_at(&mut ct, start_offset as u64)
            .map_err(Error::IO)?;

        // Truncate the ciphertext. We may have read less than the total.
        ct.truncate(n);

        // Decrypt each block and copy the contents to the buffer.
        let mut ct_slice = ct.as_mut_slice();
        let mut pt = Vec::with_capacity(padding + buf.len());
        for block in start_block.. {
            // Nothing left to decrypt.
            if ct_slice.is_empty() {
                break;
            }

            // Decrypt the block.
            let len = ct_slice.len().min(BLK_SZ);
            let data = &mut ct_slice[..len];
            self.recrypter
                .onetime_decrypt(data, block)
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
    ) -> Result<
        (usize, Vec<JournalEntry<KEY_SZ>>),
        Error<IO::Error, C::Error, Infallible, Infallible>,
    >
    where
        IO: ReadAt + WriteAt,
    {
        // We might be writing from an offset that isn't block-aligned. This
        // means that we need to rewrite the padding in the first block that
        // causes the unalignment.
        let padding = Self::logical_block_padding(origin);
        let total = padding + buf.len();
        let start_offset = Self::logical_block_offset(origin);
        let mut start_block = Self::logical_block_index(origin);

        let mut real_padding = 0;
        let mut pt = Vec::with_capacity(padding + buf.len());

        // We have padding we need to rewrite.
        if padding > 0 {
            let mut to_read = padding;
            let mut rewrite = [0; BLK_SZ];
            while to_read > 0 {
                // Start reading at the logical block.
                let read_offset = Self::logical_block_offset(origin);

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
        let last_block_index = Self::logical_block_offset(pt.len());
        let last_block_offset = Self::logical_block_offset(origin) + last_block_index;
        let extra = Self::logical_block_padding(pt.len());
        let mut real_extra = 0;
        if extra > 0 {
            let mut rewrite = [0; BLK_SZ];
            if let Ok(n) = self.read_at(&mut rewrite, last_block_offset) {
                if n > extra {
                    pt.extend_from_slice(&rewrite[extra..n]);
                    real_extra = rewrite[extra..n].len();
                }
            }
        }

        // Journal and encrypt each block of plaintext
        let mut journal_entries = Vec::with_capacity(total / BLK_SZ);
        let mut ct = Vec::with_capacity(total);
        let mut pt_slice = pt.as_mut_slice();
        while !pt_slice.is_empty() {
            // Journal the block.
            let len = pt_slice.len().min(BLK_SZ);
            let entry = JournalEntry::Update {
                id: self.inode,
                block: start_block as u64,
                key: KeyWrapper(self.recrypter.get_block_write_key(start_block)),
                data: pt_slice[..len].to_vec(),
            };
            journal_entries.push(entry.clone());
            self.kms_wal.append(entry);
            self.kms_wal
                .persist(self.root_key)
                .map_err(|_| Error::MetadataWALPersist)?;

            // Add a new block to the ciphertext.
            self.recrypter
                .onetime_encrypt(&mut pt_slice[..len], start_block)
                .map_err(Error::Crypter)?;
            ct.extend_from_slice(&pt_slice[..len]);
            start_block += 1;

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
        let count = n.saturating_sub(real_padding + real_extra);

        Ok((count, journal_entries))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use rand::{rngs::ThreadRng, Rng, RngCore};

    use crate::{
        consts::{BLOCK_SIZE, KEY_SIZE},
        crypter::{aes::Aes256Ctr, ivs::SequentialIvg},
        hashmap::UnstableKeyMap,
        io::{stdio::StdIo, Io, Read, Seek, SeekFrom, Write},
        KeyManagementScheme,
    };

    use super::{super::testing::*, *};

    pub struct JournaledTwoStageIo<'a, IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize>
    where
        KMS: UnstableKeyManagementScheme<G, C, KEY_SZ>,
    {
        inode: u64,
        io: IO,
        kms: &'a mut KMS,
        crypter: &'a C,
        kms_wal: &'a SecureWAL<KMS::LogEntry, G, C, KEY_SZ>,
        root_key: Key<KEY_SZ>,
        cursor: usize,
    }

    impl<'a, IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize>
        JournaledTwoStageIo<'a, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: Seek,
        KMS: UnstableKeyManagementScheme<G, C, KEY_SZ>,
        G: Ivg,
        C: StatefulCrypter,
    {
        pub fn new(
            inode: u64,
            mut io: IO,
            kms: &'a mut KMS,
            crypter: &'a C,
            kms_wal: &'a SecureWAL<KMS::LogEntry, G, C, KEY_SZ>,
            root_key: Key<KEY_SZ>,
        ) -> Result<Self, <Self as Io>::Error> {
            let cursor = io.stream_position().map_err(Error::IO)?;
            Ok(Self {
                inode,
                io,
                kms,
                crypter,
                kms_wal,
                root_key,
                cursor: cursor as usize,
            })
        }
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
        for JournaledTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: Io,
        KMS: UnstableKeyManagementScheme<G, C, KEY_SZ>,
        G: Ivg,
        C: StatefulCrypter,
    {
        type Error = Error<IO::Error, C::Error, G::Error, KMS::Error>;
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
        for JournaledTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: ReadAt + WriteAt,
        KMS: UnstableKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
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
        for JournaledTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: ReadAt + WriteAt,
        KMS: UnstableKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
        G: Ivg,
        C: StatefulCrypter,
    {
        fn read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, Self::Error> {
            let mut pre = JournaledPreCryptAt::<_, _, _, BLK_SZ, KEY_SZ>::new(
                self.root_key,
                self.inode,
                buf.len(),
                offset as usize,
                &mut self.io,
                self.kms,
                self.kms_wal,
                true,
                self.crypter,
            )?;

            pre.read_at(buf, offset as usize)
                .map_err(|_| Error::PreCrypt)
        }
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
        for JournaledTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: ReadAt + WriteAt,
        KMS: UnstableKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
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
        for JournaledTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: ReadAt + WriteAt,
        KMS: UnstableKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
        G: Ivg,
        C: StatefulCrypter,
    {
        fn write_at(&mut self, buf: &[u8], offset: u64) -> Result<usize, Self::Error> {
            let mut pre = JournaledPreCryptAt::<_, _, _, BLK_SZ, KEY_SZ>::new(
                self.root_key,
                self.inode,
                buf.len(),
                offset as usize,
                &mut self.io,
                self.kms,
                self.kms_wal,
                false,
                self.crypter,
            )?;

            let (n, journal_entries) = pre
                .write_at(buf, offset as usize)
                .map_err(|_| Error::PreCrypt)?;

            for entry in journal_entries {
                self.kms.sync(&entry).map_err(Error::KMS)?;
            }

            Ok(n)
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            self.io.flush().map_err(Error::IO)
        }
    }

    impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek
        for JournaledTwoStageIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
    where
        IO: Seek,
        KMS: UnstableKeyManagementScheme<G, C, KEY_SZ, KeyId = u64>,
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
        kms: UnstableKeyMap<ThreadRng, KEY_SIZE>,
        wal: SecureWAL<
            <UnstableKeyMap<ThreadRng, KEY_SIZE> as KeyManagementScheme>::LogEntry,
            SequentialIvg,
            Aes256Ctr,
            KEY_SIZE,
        >,
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
                kms: UnstableKeyMap::default(),
                wal: SecureWAL::open(&wal_path, ROOT_KEY).unwrap(),
                crypter: Aes256Ctr::default(),
            },
            file_path,
        )
    }

    fn generate_io<'a>(
        config: &'a mut Config,
    ) -> JournaledTwoStageIo<
        '_,
        &'a mut StdIo<File>,
        UnstableKeyMap<ThreadRng, KEY_SIZE>,
        SequentialIvg,
        Aes256Ctr,
        BLOCK_SIZE,
        KEY_SIZE,
    > {
        JournaledTwoStageIo::new(
            0,
            &mut config.io,
            &mut config.kms,
            &config.crypter,
            &config.wal,
            ROOT_KEY,
        )
        .unwrap()
    }

    cryptio_unpadded_test_impl!("twostage-journaled", generate_conf, generate_io);
}
