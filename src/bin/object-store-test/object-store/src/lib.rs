#![feature(iterator_try_collect)]
mod disk;
mod fs;
mod nvme;
mod object_store;

pub use object_store::{create_object, read_exact, unlink_object, write_all};
