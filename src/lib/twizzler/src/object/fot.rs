use std::sync::atomic::AtomicU32;

use thiserror::Error;

bitflags::bitflags! {
    #[repr(C)]
    #[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Hash)]
    pub struct FotFlags : u32 {
        const RESERVED = 1;
        const ACTIVE = 2;
        const RESOLVER = 4;
    }
}

pub type ResolverFn = extern "C" fn(ResolveRequest) -> Result<FotResolve, FotError>;

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Error)]
pub enum FotError {
    #[error("invalid FOT index")]
    InvalidIndex,
    #[error("invalid FOT entry")]
    InvalidFotEntry,
}

pub struct ResolveRequest {}

pub struct FotResolve {}

#[repr(C)]
pub struct FotEntry {
    pub values: [u64; 2],
    pub resolver: u64,
    pub flags: AtomicU32,
}
