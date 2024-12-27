use super::{Io, Read, ReadAt, Seek, SeekFrom, Write, WriteAt};

pub struct StatIo<T> {
    inner: T,
    read_count: u64,
    write_count: u64,
    seek_count: u64,
}

impl<T> StatIo<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            read_count: 0,
            write_count: 0,
            seek_count: 0,
        }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn to_inner(self) -> T {
        self.inner
    }

    pub fn read_count(&self) -> u64 {
        self.read_count
    }

    pub fn write_count(&self) -> u64 {
        self.write_count
    }

    pub fn seek_count(&self) -> u64 {
        self.seek_count
    }
}

impl<T: Io> Io for StatIo<T> {
    type Error = T::Error;
}

impl<T: Read> Read for StatIo<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = self.inner.read(buf)?;
        self.read_count += n as u64;
        Ok(n)
    }
}

impl<T: ReadAt> ReadAt for StatIo<T> {
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, Self::Error> {
        let n = self.inner.read_at(buf, offset)?;
        self.read_count += n as u64;
        Ok(n)
    }
}

impl<T: Write> Write for StatIo<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let n = self.inner.write(buf)?;
        self.write_count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush()
    }
}

impl<T: WriteAt> WriteAt for StatIo<T> {
    fn write_at(&mut self, buf: &[u8], offset: u64) -> Result<usize, Self::Error> {
        let n = self.inner.write_at(buf, offset)?;
        self.write_count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush()
    }
}

impl<T: Seek> Seek for StatIo<T> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.seek_count += 1;
        self.inner.seek(pos.into())
    }
}
