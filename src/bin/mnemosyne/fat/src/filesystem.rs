use std::mem::MaybeUninit;

use chacha20::cipher::{KeyInit, StreamCipher, StreamCipherSeek};
use kms::{
    crypter::{aes::Aes256Ctr, ivs::SequentialIvg, Ivg, StatefulCrypter},
    hasher::sha3::{Sha3_256, SHA3_256_MD_SIZE},
    khf::{self, Khf},
    wal::SecureWAL,
    KeyManagementScheme, StableKeyManagementScheme,
};
use layout::{io::SeekFrom, ApplyLayout, Frame, Read, Seek, Write, IO};
use rand::rngs::ThreadRng;

use crate::{
    block_io::BlockIO,
    schema::{self, FATEntry, FileSystemFrame},
};

#[derive(Debug)]
pub enum FSError<E> {
    ObjNotFound,
    Full,
    OutOfBounds,
    UnexpectedEof,
    WriteZero,
    IO(E),
    Khf(khf::Error<<SequentialIvg as Ivg>::Error, <Aes256Ctr as StatefulCrypter>::Error>),
}

impl<E> From<E> for FSError<E> {
    fn from(value: E) -> Self {
        Self::IO(value)
    }
}

pub struct FileSystem<S> {
    pub disk: S, // todo pub
    khf: Khf<rand::rngs::ThreadRng, SequentialIvg, Aes256Ctr, Sha3_256, { SHA3_256_MD_SIZE }>,
    wal: SecureWAL<<Khf<ThreadRng, SequentialIvg, Aes256Ctr, Sha3_256, SHA3_256_MD_SIZE> as KeyManagementScheme>::LogEntry, SequentialIvg, Aes256Ctr, SHA3_256_MD_SIZE>
}

impl<S: Read + Write + Seek + IO> FileSystem<S> {
    const MAGIC_NUM: u64 = 0x1e0_15_c001;
    const WAL_KEY: [u8; SHA3_256_MD_SIZE] = [0; SHA3_256_MD_SIZE];

    pub fn open(disk: S) -> Self {
        Self {
            disk,
            khf: Khf::new(), // TODO: make this persist with serde
            wal: SecureWAL::open("", Self::WAL_KEY).unwrap(),
        }
    }

    pub fn create(mut disk: S, block_size: u32) -> Result<Self, S::Error> {
        let block_count = disk.stream_len()? / block_size as u64;

        let mut frame = schema::FileSystem::apply_layout(&mut disk, 0)?;

        let super_block = schema::Superblock {
            magic: Self::MAGIC_NUM,
            block_size,
            block_count,
        };

        frame.set_super_block(&super_block)?;
        frame.fat()?.set_len(block_count)?;
        frame.set_super_block_cp(&super_block)?;

        let padding = block_size as u64 - frame.obj_lookup()?.offset() % block_size as u64;
        let mut obj_lookup = frame.obj_lookup()?;
        obj_lookup.set_len(padding + block_size as u64)?;
        for i in 0..obj_lookup.len() {
            obj_lookup.set(i, FATEntry::None)?;
        }

        let reserved_len = frame.rest()?.offset() / block_size as u64 + 1;
        let mut fat = frame.fat()?;
        for i in 0..reserved_len {
            fat.set(i, FATEntry::Reserved)?;
        }
        for i in reserved_len..block_count {
            fat.set(i, FATEntry::None)?;
        }

        Ok(Self {
            disk,
            khf: Khf::new(),
            wal: SecureWAL::open("", Self::WAL_KEY).unwrap(),
        })
    }

    pub fn frame(&mut self) -> Result<FileSystemFrame<'_, S>, S::Error> {
        schema::FileSystem::apply_layout(&mut self.disk, 0)
    }

    pub(crate) fn alloc_block(&mut self) -> Result<u64, FSError<S::Error>> {
        let mut frame = self.frame()?;
        let mut fat = frame.fat()?;

        let free_head = fat.get(0)?.unwrap().ok_or(FSError::Full)?;
        let next_free = fat.get(free_head)?;
        fat.set(0, next_free)?;
        fat.set(free_head, FATEntry::None)?;

        Ok(free_head)
    }

    pub(crate) fn free_block(&mut self, block: u64) -> Result<(), FSError<S::Error>> {
        let mut frame = self.frame()?;
        let mut fat = frame.fat()?;

        let free_head = fat.get(0)?;
        fat.set(block, FATEntry::None)?;
        fat.set(0, FATEntry::Block(block))?;

        Ok(())
    }

    pub fn unlink_object(&mut self, obj_id: u128) -> Result<(), FSError<S::Error>> {
        self.khf
            .delete(&self.wal, obj_id)
            .map_err(|e| FSError::Khf(e))?;
        let mut frame = self.frame()?;
        let mut obj_lookup = frame.obj_lookup()?;
        let hash: u64 = (obj_id % obj_lookup.len() as u128) as u64;
        let bucket_start = obj_lookup.get(hash)?.unwrap();
        let Some(bucket_start) = bucket_start else {
            return Err(FSError::ObjNotFound);
        };
        drop(obj_lookup);
        drop(frame);
        let mut bucket_blocks = BlockIO::from_block(self, bucket_start, false)?;
        let blocks = bucket_blocks.get_all_allocated_blocks()?.to_owned();
        for block in blocks {
            self.free_block(block)?;
        }
        let mut frame = self.frame()?;
        let mut obj_lookup = frame.obj_lookup()?;
        obj_lookup.set(hash, FATEntry::None);
        Ok(())
    }

    pub fn create_object(&mut self, obj_id: u128, size: u64) -> Result<bool, FSError<S::Error>> {
        let mut frame = self.frame()?;
        let mut obj_lookup = frame.obj_lookup()?;

        let hash = obj_id as u64 % obj_lookup.len();
        let bucket_start = obj_lookup.get(hash)?.unwrap();
        drop(obj_lookup);
        drop(frame);

        self.khf
            .derive_mut(&self.wal, obj_id)
            .map_err(|e| FSError::Khf(e))?;

        let mut new = false;
        let mut bucket_blocks = match bucket_start {
            Some(bucket_start) => BlockIO::from_block(self, bucket_start, false)?,
            None => {
                let bio = BlockIO::create(self, None)?.start_block(); // TODO
                let mut frame = self.frame()?;
                let mut obj_lookup = frame.obj_lookup()?;
                obj_lookup.set(hash, FATEntry::Block(bio))?;

                new = true;

                BlockIO::from_block(self, bio, false)?
            }
        };

        let bucket_start = bucket_blocks.start_block();

        let mut bucket = bucket_blocks.as_frame::<schema::ObjLookupBucket>()?;
        if new {
            bucket.set_len(0)?;
        }

        for i in 0..bucket.len() {
            let entry = bucket.get(i)?;
            if entry.object_id == obj_id {
                return Ok(false);
            }
        }

        let obj_start_block = self.alloc_block()?;
        // let mut oio = BlockIO::from_block(self, obj_start_block, false)?;
        // oio.write_all(&[obj_id as u8].repeat(size as usize))?;

        let mut bucket_blocks = BlockIO::from_block(self, bucket_start, false)?;
        let mut bucket = bucket_blocks.as_frame::<schema::ObjLookupBucket>()?;

        bucket.set_len(bucket.len() + 1)?;
        bucket.set(
            bucket.len() - 1,
            schema::ONode {
                object_id: obj_id,
                size,
                first_block: obj_start_block,
                reserved: Default::default(),
            },
        )?;

        Ok(true)
    }

    pub fn read_exact(
        &mut self,
        obj_id: u128,
        buf: &mut [u8],
        off: u64,
    ) -> Result<(), FSError<S::Error>> {
        let mut frame = self.frame()?;
        let mut obj_lookup = frame.obj_lookup()?;
        let bucket_start = obj_lookup.get(obj_id as u64 % obj_lookup.len())?;

        let bucket_start = match bucket_start {
            FATEntry::Block(b) => b,
            _ => return Err(FSError::ObjNotFound),
        };

        let mut bucket_blocks = BlockIO::from_block(self, bucket_start, true)?;
        let mut bucket = bucket_blocks.as_frame::<schema::ObjLookupBucket>()?;

        let mut data_start = None;
        for i in 0..bucket.len() {
            let entry = bucket.get(i)?;
            if entry.object_id == obj_id {
                data_start = Some(entry.first_block);
                break;
            }
        }

        let mut data_blocks =
            BlockIO::from_block(self, data_start.ok_or(FSError::ObjNotFound)?, true)?;
        data_blocks.seek(SeekFrom::Start(off))?;
        data_blocks.read_exact(buf)?;

        // let key = self
        //     .khf
        //     .derive(obj_id)?
        //     .expect("A key should exist if the object exists.");
        // let cipher = chacha20::ChaCha20::from_core(key);
        // cipher.seek(off);
        // cipher.apply_keystream(&mut buf);

        Ok(())
    }

    pub fn write_all(
        &mut self,
        obj_id: u128,
        buf: &[u8],
        off: u64,
    ) -> Result<(), FSError<S::Error>> {
        let mut frame = self.frame()?;
        let mut obj_lookup = frame.obj_lookup()?;
        let bucket_start = obj_lookup.get(obj_id as u64 % obj_lookup.len())?;

        let bucket_start = match bucket_start {
            FATEntry::Block(b) => b,
            _ => return Err(FSError::ObjNotFound),
        };

        let mut bucket_blocks = BlockIO::from_block(self, bucket_start, true)?;
        let mut bucket = bucket_blocks.as_frame::<schema::ObjLookupBucket>()?;

        let mut data_start = None;
        for i in 0..bucket.len() {
            let entry = bucket.get(i)?;
            if entry.object_id == obj_id {
                data_start = Some(entry.first_block);
                break;
            }
        }

        // let key = self
        //     .khf
        //     .derive(obj_id)?
        //     .expect("A key should exist if the object exists.");
        // let cipher = chacha20::ChaCha20::from_core(key);
        // cipher.seek(off);
        // let buf = buf.to_owned();
        // cipher.apply_keystream(&mut buf);

        let mut data_blocks =
            BlockIO::from_block(self, data_start.ok_or(FSError::ObjNotFound)?, true)?;
        data_blocks.seek(SeekFrom::Start(off))?;
        data_blocks.write_all(buf)?;

        Ok(())
    }
}
