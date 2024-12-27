// #![cfg_attr(not(test), no_std)]
#![feature(lazy_cell)]

use std::{
    borrow::BorrowMut,
    io::{Read, Write},
    sync::{LazyLock, Mutex, OnceLock},
};

mod disk;
mod nvme;
use disk::Disk;
use fatfs::{
    ChronoTimeProvider, FileSystem, FsOptions, LossyOemCpConverter, Seek,
    StdIoWrapper,
};
static mut DISK: OnceLock<Disk> = OnceLock::new();
static FS: LazyLock<
    Mutex<
        FileSystem<
            StdIoWrapper<&mut disk::Disk>,
            ChronoTimeProvider,
            LossyOemCpConverter,
        >,
    >,
> = LazyLock::new(|| {
    let options = FsOptions::new();
    let mut_disk;
    // SAFETY: this is the only place that disk is mutated
    // and this runs only once, when FS is first used.
    unsafe {
        let _ = DISK.set(Disk::new().unwrap());
        mut_disk = DISK.get_mut().unwrap();
    };
    Mutex::new(fatfs::FileSystem::new(mut_disk, options).unwrap())
});

pub fn get_obj_path(obj_id: u128) -> String {
    let stringified_id = format!("{:0>32x}", obj_id);
    let first_char = stringified_id.chars().next().unwrap();
    format!("/objects/{}/{}", first_char, stringified_id)
}

pub fn unlink_object(obj_id: u128) -> Result<(), std::io::Error> {
    let fs = FS.lock().unwrap();
    fs.root_dir().remove(&get_obj_path(obj_id))?;
    Ok(())
}
pub fn create_object(obj_id: u128) -> Result<bool, std::io::Error> {
    let fs = FS.lock().unwrap();
    let mut file = fs.root_dir().create_file(&get_obj_path(obj_id))?;
    file.truncate()?;
    Ok(true)
}
pub fn read_exact(
    obj_id: u128,
    buf: &mut [u8],
    off: u64,
) -> Result<(), std::io::Error> {
    let fs = FS.lock().unwrap();
    let mut file = fs.root_dir().open_file(&get_obj_path(obj_id))?;
    file.seek(fatfs::SeekFrom::Start(off))?;
    file.read_exact(buf)
}
pub fn write_all(
    obj_id: u128,
    buf: &[u8],
    off: u64,
) -> Result<(), std::io::Error> {
    let fs = FS.lock().unwrap();
    let mut file = fs.root_dir().open_file(&get_obj_path(obj_id))?;
    file.seek(fatfs::SeekFrom::Start(off))?;
    file.write_all(buf)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{File, OpenOptions},
        io::{BufReader, Read, Seek, Write},
    };

    struct FileDisk(File);

    #[derive(Debug)]
    struct DiskError(std::io::Error);

    impl IoError for DiskError {
        fn is_interrupted(&self) -> bool {
            self.0.kind() == std::io::ErrorKind::Interrupted
        }

        fn new_unexpected_eof_error() -> Self {
            Self(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
        }

        fn new_write_zero_error() -> Self {
            Self(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write whole buffer",
            ))
        }
    }
    impl IoBase for FileDisk {
        type Error = DiskError;
    }

    impl fatfs::Read for FileDisk {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let res = self.0.read(buf).map_err(|err| DiskError(err))?;
            Ok(res)
        }
    }

    impl fatfs::Write for FileDisk {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            let res = self.0.write(buf).map_err(|err| DiskError(err))?;
            Ok(res)
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            let res = self.0.flush().map_err(|err| DiskError(err))?;
            Ok(res)
        }
    }

    impl fatfs::Seek for FileDisk {
        fn seek(&mut self, pos: fatfs::SeekFrom) -> Result<u64, Self::Error> {
            let std_seek = match pos {
                fatfs::SeekFrom::Start(off) => std::io::SeekFrom::Start(off),
                fatfs::SeekFrom::End(off) => std::io::SeekFrom::End(off),
                fatfs::SeekFrom::Current(off) => {
                    std::io::SeekFrom::Current(off)
                }
            };
            let out = &self.0.seek(std_seek).map_err(|err| DiskError(err))?;
            Ok(*out)
        }
    }
    use fatfs::{
        format_volume, FileSystem, FormatVolumeOptions, IoBase, IoError,
        Write as _,
    };

    #[test]
    pub fn fat() {
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open("fat.img")
            .unwrap();
        file.write_all(&vec![0u8; 2usize.pow(32)]).unwrap();
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut img_file = FileDisk(file);
        let format_options =
            FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat32);
        format_volume(&mut img_file, format_options).unwrap();
        let fs = FileSystem::new(img_file, fatfs::FsOptions::new()).unwrap();
        let root_dir = fs.root_dir();
        let mut file = root_dir.create_file("hello.txt").unwrap();
        file.write_all(b"Hello World!").unwrap();
    }
    #[test]
    pub fn print_fat() {
        let file = OpenOptions::new().read(true).open("fat.img").unwrap();
        let mut buf_reader = BufReader::new(file);
        let mut disk = vec![0u8; 2usize.pow(32)];
        buf_reader.read_exact(&mut disk).unwrap();
        // let no_zeros = disk.chunk_by(|a, b| a == b).map(|n| {
        //     if (n)[0] != 0 || n.len() < 32 {
        //         format!(
        //             "{}",
        //             n.iter()
        //                 .map(|n| format!("{}", n))
        //                 .collect::<Vec<String>>()
        //                 .join("")
        //         )
        //     } else {
        //         format!("\n({} zeroes)\n", n.len())
        //     }
        // });

        for byte in disk {
            print!("{byte}")
        }
        println!("");
    }
}
