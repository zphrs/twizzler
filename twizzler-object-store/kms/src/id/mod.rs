pub mod seq;
pub mod uuid;

use std::{collections::HashMap, fmt::Debug, hash::Hash};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An `IdAllocator` oversees the allocation and deallocation of IDs.
pub trait IdAllocator {
    /// The type of ID.
    type Id: Copy;
    /// Associated error type.
    type Error: std::error::Error;

    /// Allocates an ID.
    fn alloc(&mut self) -> Result<Self::Id, Self::Error>;

    /// Deallocates an ID.
    fn dealloc(&mut self, id: Self::Id) -> Result<(), Self::Error>;

    /// Reserves an ID.
    fn reserve(&mut self, id: Self::Id) -> Result<(), Self::Error>;
}

#[derive(Deserialize, Serialize)]
pub struct IdManager<T, A>
where
    A: IdAllocator,
{
    #[serde(bound(serialize = "A::Id: Serialize + Hash + Eq, T: Serialize + Hash + Eq"))]
    #[serde(bound(
        deserialize = "A::Id: Deserialize<'de> + Hash + Eq, T: Deserialize<'de> + Hash + Eq"
    ))]
    src_to_dst: HashMap<T, A::Id>,
    #[serde(bound(serialize = "A::Id: Serialize + Hash + Eq, T: Serialize + Hash + Eq"))]
    #[serde(bound(
        deserialize = "A::Id: Deserialize<'de> + Hash + Eq, T: Deserialize<'de> + Hash + Eq"
    ))]
    dst_to_src: HashMap<A::Id, T>,
    #[serde(bound(serialize = "A: Serialize"))]
    #[serde(bound(deserialize = "A: Deserialize<'de>"))]
    id_allocator: A,
}

#[derive(Error, Debug)]
pub enum Error<T: Debug, D: Debug, A: std::error::Error> {
    #[error("missing source mapping (src_id = {0})")]
    MissingSourceMapping(T),

    #[error("missing destination mapping (dst_id = {0})")]
    MissingDestinationMapping(D),

    #[error(transparent)]
    IdAllocator(A),
}

impl<T, A> IdManager<T, A>
where
    A: IdAllocator,
{
    pub fn new(id_allocator: A) -> Self {
        Self {
            src_to_dst: HashMap::new(),
            dst_to_src: HashMap::new(),
            id_allocator,
        }
    }

    pub fn contains(&mut self, src_id: T) -> bool
    where
        T: Hash + Eq,
    {
        self.src_to_dst.contains_key(&src_id)
    }

    pub fn add(&mut self, src_id: T) -> Result<A::Id, Error<T, A::Id, A::Error>>
    where
        A::Id: Hash + Eq + Debug,
        T: Copy + Hash + Eq + Debug,
    {
        if let Some(dst_id) = self.src_to_dst.get(&src_id) {
            Ok(*dst_id)
        } else {
            let dst_id = self.id_allocator.alloc().map_err(Error::IdAllocator)?;
            self.src_to_dst.insert(src_id, dst_id);
            self.dst_to_src.insert(dst_id, src_id);
            Ok(dst_id)
        }
    }

    pub fn add_mapping(
        &mut self,
        src_id: T,
        dst_id: A::Id,
    ) -> Result<Option<A::Id>, Error<T, A::Id, A::Error>>
    where
        A::Id: Hash + Eq + Debug,
        T: Copy + Hash + Eq + Debug,
    {
        self.id_allocator
            .reserve(dst_id)
            .map_err(Error::IdAllocator)?;

        let res = if let Some(old_dst_id) = self.src_to_dst.get_mut(&src_id) {
            let old = *old_dst_id;
            *old_dst_id = dst_id;

            self.dst_to_src.remove(&old);
            self.dst_to_src.insert(dst_id, src_id);

            Some(old)
        } else {
            self.src_to_dst.insert(src_id, dst_id);
            self.dst_to_src.insert(dst_id, src_id);

            None
        };

        Ok(res)
    }

    pub fn remove(&mut self, src_id: T) -> Result<A::Id, Error<T, A::Id, A::Error>>
    where
        A::Id: Hash + Eq + Debug,
        T: Hash + Eq + Debug,
    {
        if let Some(dst_id) = self.src_to_dst.remove(&src_id) {
            self.dst_to_src.remove(&dst_id);
            self.id_allocator
                .dealloc(dst_id)
                .map_err(Error::IdAllocator)?;
            Ok(dst_id)
        } else {
            Err(Error::MissingSourceMapping(src_id))
        }
    }

    pub fn swap(&mut self, old_src_id: T, new_src_id: T) -> Result<(), Error<T, A::Id, A::Error>>
    where
        A::Id: Hash + Eq + Debug,
        T: Copy + Hash + Eq + Debug,
    {
        let dst_id = self
            .src_to_dst
            .remove(&old_src_id)
            .ok_or(Error::MissingSourceMapping(old_src_id))?;

        self.src_to_dst.insert(new_src_id, dst_id);
        self.dst_to_src.insert(dst_id, new_src_id);

        Ok(())
    }

    pub fn reserve(&mut self, dst_id: A::Id) -> Result<(), Error<T, A::Id, A::Error>>
    where
        A::Id: Debug,
        T: Debug,
    {
        self.id_allocator
            .reserve(dst_id)
            .map_err(Error::IdAllocator)
    }

    pub fn resolve_src_id(&self, src_id: T) -> Result<A::Id, Error<T, A::Id, A::Error>>
    where
        A::Id: Debug,
        T: Hash + Eq + Debug,
    {
        self.src_to_dst
            .get(&src_id)
            .map(|dst_id| *dst_id)
            .ok_or(Error::MissingSourceMapping(src_id))
    }

    pub fn resolve_dst_id(&self, dst_id: A::Id) -> Result<T, Error<T, A::Id, A::Error>>
    where
        A::Id: Hash + Eq + Debug,
        T: Copy + Debug,
    {
        self.dst_to_src
            .get(&dst_id)
            .map(|src_id| *src_id)
            .ok_or(Error::MissingDestinationMapping(dst_id))
    }

    pub fn dump(&self) -> ()
    where
        A::Id: Hash + Eq + Debug,
        T: Copy + Hash + Eq + Debug,
    {
	println!("IdMapper src_to_dst:");
	for (key, value) in &self.src_to_dst {
	    println!("{:?}: {:?}", key, value);
	}

	println!("IdMapper dst_to_src:");
	for (key, value) in &self.dst_to_src {
	    println!("{:?}: {:?}", key, value);
	}
    }
}

impl<T, A: Default> Default for IdManager<T, A>
where
    A: IdAllocator,
{
    fn default() -> Self {
        Self::new(A::default())
    }
}
