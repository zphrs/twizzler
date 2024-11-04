use std::{
    fs::{File as StdFile, FileTimes, Metadata, OpenOptions as StdOpenOptions, Permissions},
    io::{Read, Result, Seek, SeekFrom, Write},
    path::Path,
    process::Stdio,
    time::SystemTime,
};

#[derive(Debug)]
pub struct File(StdFile);

impl File {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        StdFile::create(path).map(Self)
    }

    pub fn create_new(path: impl AsRef<Path>) -> Result<Self> {
        StdFile::create_new(path).map(Self)
    }

    pub fn metadata(&self) -> Result<Metadata> {
        self.0.metadata()
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        StdFile::open(path).map(Self)
    }

    pub fn options() -> OpenOptions {
        OpenOptions::new()
    }

    pub fn set_len(&self, size: u64) -> Result<()> {
        self.0.set_len(size)
    }

    pub fn set_modified(&self, time: SystemTime) -> Result<()> {
        self.0.set_modified(time)
    }

    pub fn set_permissions(&self, perm: Permissions) -> Result<()> {
        self.0.set_permissions(perm)
    }

    pub fn set_times(&self, times: FileTimes) -> Result<()> {
        self.0.set_times(times)
    }

    pub fn sync_all(&self) -> Result<()> {
        Ok(())
    }

    pub fn sync_data(&self) -> Result<()> {
        Ok(())
    }

    pub fn try_clone(&self) -> Result<Self> {
        self.0.try_clone().map(Self)
    }
}

impl From<File> for Stdio {
    fn from(value: File) -> Self {
        value.0.into()
    }
}

impl Read for &File {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Read::read(&mut &self.0, buf)
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for &File {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        Seek::seek(&mut &self.0, pos)
    }
}

impl Seek for File {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.0.seek(pos)
    }
}

impl Write for &File {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Write::write(&mut &self.0, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Write::flush(&mut &self.0)
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

#[derive(Clone, Debug)]
pub struct OpenOptions(StdOpenOptions);

impl OpenOptions {
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.0.append(append);
        self
    }

    pub fn create(&mut self, create: bool) -> &mut Self {
        self.0.create(create);
        self
    }

    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.0.create_new(create_new);
        self
    }

    pub fn new() -> Self {
        Self(StdOpenOptions::new())
    }

    pub fn open(&self, path: impl AsRef<Path>) -> Result<File> {
        self.0.open(path).map(File)
    }

    pub fn read(&mut self, read: bool) -> &mut Self {
        self.0.read(read);
        self
    }

    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.0.truncate(truncate);
        self
    }

    pub fn write(&mut self, write: bool) -> &mut Self {
        self.0.write(write);
        self
    }
}
