use std::{collections::HashSet, convert::Infallible};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::IdAllocator;

#[derive(Deserialize, Serialize, Default)]
pub struct UuidAllocator {
    reserved: HashSet<Uuid>,
}

impl IdAllocator for UuidAllocator {
    type Id = Uuid;
    type Error = Infallible;

    fn reserve(&mut self, id: Self::Id) -> Result<(), Self::Error> {
        self.reserved.insert(id);
        Ok(())
    }

    fn alloc(&mut self) -> Result<Self::Id, Self::Error> {
        loop {
            let id = Uuid::new_v4();
            if !self.reserved.contains(&id) {
                return Ok(id);
            }
        }
    }

    fn dealloc(&mut self, _id: Self::Id) -> Result<(), Self::Error> {
        Ok(())
    }
}
