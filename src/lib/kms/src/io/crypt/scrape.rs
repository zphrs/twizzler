use std::{
    fs::File,
    io::{BufReader, Read, Result},
    marker::PhantomData,
    path::Path,
};

use crate::{consts::SECTOR_SIZE, crypter::StatefulCrypter};

pub struct ModifiedBlockScraper<C, const BLOCK_SIZE: usize> {
    pd: PhantomData<C>,
}

impl<C: StatefulCrypter, const BLOCK_SIZE: usize> ModifiedBlockScraper<C, BLOCK_SIZE> {
    fn sector_data_size() -> usize {
        SECTOR_SIZE - C::iv_length()
    }

    fn padded_sector_size() -> usize {
        SECTOR_SIZE
    }

    fn logical_sector_to_block(sector: usize) -> usize {
        (sector * Self::sector_data_size()) / BLOCK_SIZE
    }

    pub fn scrape(path: impl AsRef<Path>) -> Result<Vec<u64>> {
        let mut file = BufReader::new(File::open(path.as_ref())?);

        let mut sector = 0;
        let mut modified_blocks = vec![];
        let mut buf = vec![0; Self::padded_sector_size()];

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }

            let (iv, _data) = buf.split_at(C::iv_length());
            if iv.last().map(|byte| byte & 0x80 > 0).unwrap_or(false) {
                let sector_block = Self::logical_sector_to_block(sector) as u64;
                if modified_blocks
                    .last()
                    .map(|block| sector_block != *block)
                    .unwrap_or(true)
                {
                    modified_blocks.push(sector_block);
                }
            }

            sector += 1;
        }

        Ok(modified_blocks)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::ThreadRng;

    use crate::{
        consts::{BLOCK_SIZE, KEY_SIZE},
        crypter::{aes::Aes256Ctr, ivs::SequentialIvg},
        hashmap::StableKeyMap,
        io::{crypt::keyed::IvCryptIo, stdio::StdIo, WriteAt},
        wal::SecureWAL,
    };

    use super::{super::speculative::tests::SpeculativeTwoStageIo, *};

    const NUM_BLOCKS: usize = 16;
    const ROOT_KEY: [u8; KEY_SIZE] = [0; KEY_SIZE];

    fn write_block(mut writer: impl WriteAt, block: usize) {
        let buf = [0; BLOCK_SIZE];
        writer.write_at(&buf, (block * BLOCK_SIZE) as u64).unwrap();
    }

    fn write_nblocks(mut writer: impl WriteAt, nblocks: usize) {
        for block in 0..nblocks {
            write_block(&mut writer, block);
        }
    }

    #[test]
    fn it_works() {
        let base_path = "/tmp/cryptio-test-modified-block-scraper";
        let file_path = format!("{base_path}.dat");
        let wal_path = format!("{base_path}.log");

        // First, write the modified blocks.
        {
            let mut kms = StableKeyMap::<ThreadRng, KEY_SIZE>::default();
            let kms_wal = SecureWAL::open(&wal_path, ROOT_KEY).unwrap();
            let mut ivg = SequentialIvg::default();
            let crypter = Aes256Ctr::default();
            let mut writer = SpeculativeTwoStageIo::<_, _, _, _, BLOCK_SIZE, KEY_SIZE>::new(
                StdIo::new(
                    File::options()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&file_path)
                        .unwrap(),
                ),
                &mut kms,
                &mut ivg,
                &crypter,
                &kms_wal,
                ROOT_KEY,
            )
            .unwrap();

            write_nblocks(&mut writer, NUM_BLOCKS);
        }

        let modified_blocks =
            ModifiedBlockScraper::<Aes256Ctr, BLOCK_SIZE>::scrape(&file_path).unwrap();
        assert_eq!(modified_blocks, (0..NUM_BLOCKS as u64).collect::<Vec<_>>());

        // Overwrite the first couple blocks.
        {
            let mut ivg = SequentialIvg::default();
            let crypter = Aes256Ctr::default();
            let mut writer =
                IvCryptIo::<StdIo<File>, SequentialIvg, Aes256Ctr, BLOCK_SIZE, KEY_SIZE>::new(
                    StdIo::new(
                        File::options()
                            .read(true)
                            .write(true)
                            .open(&file_path)
                            .unwrap(),
                    ),
                    ROOT_KEY,
                    &mut ivg,
                    &crypter,
                )
                .unwrap();

            for block in modified_blocks.iter().filter(|block| **block % 2 == 0) {
                write_block(&mut writer, *block as usize);
            }
        }

        let modified_blocks =
            ModifiedBlockScraper::<Aes256Ctr, BLOCK_SIZE>::scrape(&file_path).unwrap();
        assert_eq!(
            modified_blocks,
            (0..NUM_BLOCKS as u64)
                .filter(|block| *block % 2 != 0)
                .collect::<Vec<_>>()
        );
    }
}
