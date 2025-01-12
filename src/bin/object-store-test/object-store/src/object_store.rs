use std::{
    collections::HashSet,
    hash::Hash,
    io::{Error, Read, Seek, SeekFrom, Write},
    sync::{Arc, LazyLock, Mutex, OnceLock},
};

use fatfs::{DefaultTimeProvider, Dir, Extent, IoBase, LossyOemCpConverter};
// use kms::{
//     crypter::{aes::Aes256Ctr, ivs::SequentialIvg}, hasher::sha3::{Sha3_256,
// SHA3_256_MD_SIZE}, khf::{Khf, KhfBuilder}, wal::{Io, SecureWAL}, StableKeyManagementScheme,
//     KeyManagementScheme
// };
use rand::rngs::OsRng;

use crate::disk::{Disk, FS};
fn get_dir_path<'a>(
    fs: &'a mut fatfs::FileSystem<Disk, DefaultTimeProvider, LossyOemCpConverter>,
    encoded_obj_id: &EncodedObjectId,
) -> Result<Dir<'a, Disk, DefaultTimeProvider, LossyOemCpConverter>, Error> {
    let subdir = fs
        .root_dir()
        .create_dir("ids")?
        .create_dir(&encoded_obj_id[0..1])?;
    Ok(subdir)
}

type EncodedObjectId = String;

fn encode_obj_id(obj_id: u128) -> EncodedObjectId {
    format!("{:0>32x}", obj_id)
}

pub fn unlink_object(obj_id: u128) -> Result<(), Error> {
    let b64 = encode_obj_id(obj_id);
    let mut fs = FS.lock().unwrap();
    let subdir = get_dir_path(&mut fs, &b64)?;
    subdir.remove(&b64)?;
    Ok(())
}

/// Returns true if file was created and false if the file already existed.
pub fn create_object(obj_id: u128) -> Result<bool, Error> {
    let b64 = encode_obj_id(obj_id);
    let mut fs = FS.lock().unwrap();
    let subdir = get_dir_path(&mut fs, &b64)?;
    // try to open it to check if it exists.
    let res = subdir.open_file(&b64);
    match res {
        Ok(_) => Ok(false),
        Err(e) => match e {
            fatfs::Error::NotFound => {
                subdir.create_file(&b64);
                Ok(true)
            }
            _ => Err(e.into()),
        },
    }
}
pub fn read_exact(obj_id: u128, buf: &mut [u8], off: u64) -> Result<(), Error> {
    let b64 = encode_obj_id(obj_id);
    let mut fs = FS.lock().unwrap();
    let subdir = get_dir_path(&mut fs, &b64)?;
    let mut file = subdir.open_file(&b64)?;
    file.seek(std::io::SeekFrom::Start(off))?;
    file.read_exact(buf)?;
    Ok(())
}

#[derive(Clone)]
struct WrappedExtent(Extent);

impl PartialEq for WrappedExtent {
    fn eq(&self, other: &Self) -> bool {
        self.0.offset == other.0.offset && self.0.size == other.0.size
    }
}
impl Eq for WrappedExtent {}

impl From<Extent> for WrappedExtent {
    fn from(value: Extent) -> Self {
        WrappedExtent(value)
    }
}

impl WrappedExtent {
    pub fn into_inner(self) -> Extent {
        self.0
    }
}

impl Hash for WrappedExtent {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.offset.hash(state);
        self.0.size.hash(state);
    }
}

pub fn write_all(obj_id: u128, buf: &[u8], off: u64) -> Result<(), Error> {
    let b64 = encode_obj_id(obj_id);
    let mut fs = FS.lock().unwrap();
    let subdir = get_dir_path(&mut fs, &b64)?;
    let mut file = subdir.open_file(&b64)?;
    file.seek(std::io::SeekFrom::Start(off))?;
    let extents_before: HashSet<WrappedExtent> = file
        .extents()
        .map(|v| v.map(WrappedExtent::from))
        .try_collect()?;
    file.write_all(buf)?;
    let extents_after: HashSet<WrappedExtent> = file
        .extents()
        .map(|v| v.map(WrappedExtent::from))
        .try_collect()?;
    for extent in extents_before.difference(&extents_after) {
        let inner = extent.clone().into_inner();
    }
    // let mut khf = KHF.lock().unwrap();
    // let mut log = &LOG;
    // khf.derive_mut(log, obj_id);
    Ok(())
}
