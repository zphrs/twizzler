use std::{
    cell::RefCell,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};

use lru_mem::{HeapSize, InsertError, LruCache};
use path_macro::path;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    crypter::{Ivg, StatefulCrypter},
    hasher::Hasher,
    key::{Key, KeyGenerator},
    PersistableKeyManagementScheme,
};

use super::{mapped::MappedKhf, Error, DEFAULT_MEMORY_LIMIT};

struct MappedKhfLink<R, G, C, H, const N: usize> {
    key: Key<N>,
    inner: Rc<RefCell<MappedKhf<R, G, C, H, N>>>,
}

impl<R, G, C, H, const N: usize> HeapSize for MappedKhfLink<R, G, C, H, N> {
    fn heap_size(&self) -> usize {
        self.key.heap_size() + self.inner.borrow().heap_size()
    }
}

impl<R, G, C, H, const N: usize> From<InsertError<u64, MappedKhfLink<R, G, C, H, N>>>
    for Error<G::Error, C::Error>
where
    G: Ivg,
    C: StatefulCrypter,
{
    fn from(value: InsertError<u64, MappedKhfLink<R, G, C, H, N>>) -> Self {
        match value {
            InsertError::EntryTooLarge {
                key: _,
                value: _,
                entry_size: _,
                max_size: _,
            } => Error::LruMem("entry too large".into()),
        }
    }
}

pub struct PersistentArena<R, G, C, H, const N: usize> {
    pub dir: PathBuf,
    khfs: LruCache<u64, MappedKhfLink<R, G, C, H, N>>,
    memory_limit: usize,
}

impl<R, G, C, H, const N: usize> PersistentArena<R, G, C, H, N> {
    pub fn khf_path(dir: impl AsRef<Path>, khf_id: u64) -> PathBuf {
        path![dir.as_ref() / format!("{khf_id}.khf")]
    }
}

impl<R, G, C, H, const N: usize> PersistentArena<R, G, C, H, N>
where
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self::with_memory_limit(DEFAULT_MEMORY_LIMIT, dir)
    }

    pub fn with_memory_limit(memory_limit: usize, dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().into(),
            khfs: LruCache::new(memory_limit),
            memory_limit,
        }
    }

    pub fn contains(&self, khf_id: u64) -> bool {
        self.khfs.contains(&khf_id) || fs::metadata(Self::khf_path(&self.dir, khf_id)).is_ok()
    }

    fn find_evictable_lru(&self) -> Result<u64, Error<G::Error, C::Error>> {
        self.khfs
            .iter()
            .filter_map(|(khf_id, khfref)| khfref.inner.try_borrow_mut().is_ok().then_some(*khf_id))
            .next()
            .ok_or(Error::EvictionImpossible)
    }

    fn evict_lru(&mut self) -> Result<(), Error<G::Error, C::Error>> {
        let khf_id = self.find_evictable_lru()?;
        if let Some(khfref) = self.khfs.remove(&khf_id) {
            khfref
                .inner
                .borrow_mut()
                .persist(khfref.key, Self::khf_path(&self.dir, khf_id))?;
        }
        Ok(())
    }

    fn reserve_memory(&mut self, extra_overhead: usize) -> Result<(), Error<G::Error, C::Error>> {
        while self.khfs.current_size() + extra_overhead > self.khfs.max_size() {
            self.evict_lru()?;
        }
        Ok(())
    }

    pub fn insert(
        &mut self,
        khf: MappedKhf<R, G, C, H, N>,
        key: Key<N>,
        extra_overhead: usize,
    ) -> Result<(), Error<G::Error, C::Error>> {
        let khf_id = khf.khf_id;

        let entry = MappedKhfLink {
            key,
            inner: Rc::new(RefCell::new(khf)),
        };

        self.reserve_memory(lru_mem::entry_size(&khf_id, &entry) + extra_overhead)?;

        self.khfs.insert(khf_id, entry)?;

        Ok(())
    }

    pub fn get(&mut self, khf_id: u64) -> Option<Rc<RefCell<MappedKhf<R, G, C, H, N>>>> {
        self.khfs
            .get(&khf_id)
            .map(|khfref| Rc::clone(&khfref.inner))
    }

    pub fn load(
        &mut self,
        khf_id: u64,
        key: Key<N>,
        extra_overhead: usize,
    ) -> Result<Rc<RefCell<MappedKhf<R, G, C, H, N>>>, Error<G::Error, C::Error>> {
        let path = Self::khf_path(&self.dir, khf_id);

        if !self.khfs.contains(&khf_id) {
            // Can't load if it hasn't been persisted.
            if fs::metadata(&path).is_err() {
                return Err(Error::LoadObjectKhf);
            }

            let khf = MappedKhf::load(key, &path)?;
            self.insert(khf, key, extra_overhead)?;
        }

        Ok(self
            .khfs
            .get(&khf_id)
            .map(|khfref| Rc::clone(&khfref.inner))
            .unwrap())
    }

    pub fn remove(&mut self, khf_id: u64) -> Result<(), Error<G::Error, C::Error>> {
        self.khfs.remove(&khf_id);

        let path = Self::khf_path(&self.dir, khf_id);
        if fs::metadata(&path).is_ok() {
            fs::remove_file(&path)?;
        }

        Ok(())
    }

    pub fn rebase(&mut self, dir: impl AsRef<Path>) -> Result<(), Error<G::Error, C::Error>> {
        self.dir = dir.as_ref().into();
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
struct State {
    dir: PathBuf,
    memory_bound: usize,
}

impl<'de, R, G, C, H, const N: usize> Serialize for PersistentArena<R, G, C, H, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let state = State {
            dir: self.dir.clone(),
            memory_bound: self.memory_limit,
        };
        state.serialize(serializer)
    }
}

impl<'de, R, G, C, H, const N: usize> Deserialize<'de> for PersistentArena<R, G, C, H, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let state = State::deserialize(deserializer)?;
        Ok(Self {
            dir: state.dir,
            khfs: LruCache::new(state.memory_bound),
            memory_limit: state.memory_bound,
        })
    }
}
