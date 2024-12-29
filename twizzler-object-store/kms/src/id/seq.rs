use std::{collections::HashSet, hash::Hash, ops::AddAssign};

use num_traits::PrimInt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::IdAllocator;

#[derive(Deserialize, Serialize, Default)]
pub struct SequentialIdAllocator<T: PrimInt + Hash> {
    curr: T,
    reserved: HashSet<T>,
}

impl<T: PrimInt + Hash> SequentialIdAllocator<T> {
    pub fn new() -> Self {
        Self {
            curr: T::zero(),
            reserved: HashSet::new(),
        }
    }

    pub fn with_reserved(reserved: impl IntoIterator<Item = T>) -> Self {
        Self {
            curr: T::zero(),
            reserved: HashSet::from_iter(reserved),
        }
    }
}

impl<T> IdAllocator for SequentialIdAllocator<T>
where
    T: PrimInt + AddAssign + Hash,
{
    type Id = T;
    type Error = Error;

    fn alloc(&mut self) -> Result<Self::Id, Self::Error> {
        if self.curr == T::max_value() {
            Err(Error::OutOfIds)
        } else {
            while self.reserved.contains(&self.curr) {
                self.curr += T::one();
            }
            let id = self.curr;
            self.curr += T::one();
            Ok(id)
        }
    }

    fn dealloc(&mut self, id: Self::Id) -> Result<(), Self::Error> {
        self.reserved.remove(&id);
        Ok(())
    }

    fn reserve(&mut self, id: Self::Id) -> Result<(), Self::Error> {
        self.reserved.insert(id);
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("cannot allocate any more IDs")]
    OutOfIds,
}
