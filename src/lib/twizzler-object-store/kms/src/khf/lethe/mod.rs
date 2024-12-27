mod arena;
mod logging;
mod mapped;

use std::{
    cell::RefCell,
    collections::HashSet,
    fs::{self, File},
    marker::PhantomData,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    rc::Rc,
};

use arena::PersistentArena;
use lru::LruCache;
use lru_mem::MemSize;
use mapped::MappedKhf;
use path_macro::path;
use serde::{Deserialize, Serialize};

use crate::{
    crypter::{Ivg, StatefulCrypter},
    hasher::Hasher,
    id::{seq::SequentialIdAllocator, IdManager},
    io::{crypt::OneshotCryptIo, stdio::StdIo, Read, Write},
    kdf::KeyDerivationFunction,
    key::{Key, KeyGenerator},
    kms::{
        AffineKeyManagementScheme, InstrumentedKeyManagementScheme, KeyManagementScheme,
        LocalizedKeyManagementScheme, PersistableKeyManagementScheme,
        SpeculativeKeyManagementScheme, StableKeyManagementScheme, StableLogEntry,
    },
    wal::SecureWAL,
};

use super::{error::Error, khf::KhfStats};

// Each mapped KHF has its own KHF ID and object ID.
// We'll just pray that we never use u64::MAX as an actual object ID.
const DEFAULT_SYSTEM_KHF_KHF_ID: u64 = 0;
const DEFAULT_SYSTEM_KHF_OBJ_ID: u64 = u64::MAX;
const DEFAULT_SYSTEM_KHF_KEY_ID: (u64, u64) =
    (DEFAULT_SYSTEM_KHF_KHF_ID, DEFAULT_SYSTEM_KHF_OBJ_ID);

const DEFAULT_SYSTEM_KHF_FANOUTS: &[u64] = &[4, 4, 4, 4];
const DEFAULT_OBJECT_KHF_FANOUTS: &[u64] = &[4, 4, 4, 4];

const DEFAULT_MEMORY_LIMIT: usize = 1 << 32;
const DEFAULT_KEY_CACHE_LIMIT: usize = 1 << 20;
const DEFAULT_KHF_SPEC_INTERVAL_LIMIT: usize = 1 << 20;

pub struct LetheBuilder<K, R, G, C, H, const N: usize> {
    system_khf_fanouts: Vec<u64>,
    object_khf_fanouts: Vec<u64>,
    memory_limit: usize,
    fragmented: bool,
    _pd: PhantomData<(K, R, G, C, H)>,
}

impl<K, R, G, C, H, const N: usize> LetheBuilder<K, R, G, C, H, N>
where
    K: KeyDerivationFunction<N>,
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    pub fn new() -> Self {
        Self {
            system_khf_fanouts: DEFAULT_SYSTEM_KHF_FANOUTS.to_vec(),
            object_khf_fanouts: DEFAULT_OBJECT_KHF_FANOUTS.to_vec(),
            memory_limit: DEFAULT_MEMORY_LIMIT,
            fragmented: false,
            _pd: PhantomData,
        }
    }

    pub fn system_khf_fanouts(&mut self, fanouts: &[u64]) -> &mut Self {
        self.system_khf_fanouts = fanouts.to_vec();
        self
    }

    pub fn object_khf_fanouts(&mut self, fanouts: &[u64]) -> &mut Self {
        self.object_khf_fanouts = fanouts.to_vec();
        self
    }

    pub fn memory_limit(&mut self, memory_limit: usize) -> &mut Self {
        self.memory_limit = memory_limit;
        self
    }

    pub fn fragmented(&mut self, fragmented: bool) -> &mut Self {
        self.fragmented = fragmented;
        self
    }

    pub fn build(&mut self, dir: impl AsRef<Path>) -> Lethe<K, R, G, C, H, N> {
        let mut rng = R::default();
        Lethe {
            arena: PersistentArena::with_memory_limit(self.memory_limit, dir),
            id_manager: IdManager::new(SequentialIdAllocator::with_reserved([
                DEFAULT_SYSTEM_KHF_KHF_ID,
            ])),
            system_khf: MappedKhf::options()
                .fanouts(&self.system_khf_fanouts)
                .fragmented(self.fragmented)
                .with_rng(DEFAULT_SYSTEM_KHF_KHF_ID, DEFAULT_SYSTEM_KHF_OBJ_ID),
            system_khf_fanouts: self.system_khf_fanouts.to_vec(),
            object_khf_fanouts: self.object_khf_fanouts.to_vec(),
            root_key_kdf: K::with_key(rng.gen_key()),
            spanning_root_key_kdf: K::with_key(rng.gen_key()),
            fragmented: self.fragmented,
            write_cache: key_cache_default(),
            read_cache: key_cache_default(),
            speculated_key_intervals: khf_spec_interval_cache_default(),
            dirty_object_khfs: HashSet::new(),
            rng,
            ivg: G::default(),
            crypter: C::default(),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Lethe<K, R, G, C, H, const N: usize> {
    #[serde(bound(serialize = "PersistentArena<R, G, C, H, N>: Serialize"))]
    #[serde(bound(deserialize = "PersistentArena<R, G, C, H, N>: Deserialize<'de>"))]
    pub(crate) arena: PersistentArena<R, G, C, H, N>,
    pub(crate) id_manager: IdManager<u64, SequentialIdAllocator<u64>>,
    #[serde(bound(serialize = "MappedKhf<R, G, C, H, N>: Serialize"))]
    #[serde(bound(deserialize = "MappedKhf<R, G, C, H, N>: Deserialize<'de>"))]
    pub(crate) system_khf: MappedKhf<R, G, C, H, N>,
    pub(crate) system_khf_fanouts: Vec<u64>,
    pub(crate) object_khf_fanouts: Vec<u64>,
    pub(crate) root_key_kdf: K,
    pub(crate) spanning_root_key_kdf: K,
    pub(crate) fragmented: bool,
    #[serde(skip)]
    #[serde(default = "key_cache_default")]
    pub(crate) write_cache: LruCache<(u64, u64), Key<N>>,
    #[serde(skip)]
    #[serde(default = "key_cache_default")]
    pub(crate) read_cache: LruCache<(u64, u64), Key<N>>,
    #[serde(skip)]
    #[serde(default = "khf_spec_interval_cache_default")]
    pub(crate) speculated_key_intervals: LruCache<u64, HashSet<(u64, u64)>>,
    #[serde(skip)]
    pub(crate) dirty_object_khfs: HashSet<u64>,
    #[serde(skip)]
    pub(crate) rng: R,
    #[serde(skip)]
    pub(crate) ivg: G,
    #[serde(skip)]
    pub(crate) crypter: C,
}

fn key_cache_default<const N: usize>() -> LruCache<(u64, u64), Key<N>> {
    LruCache::new(NonZeroUsize::new(DEFAULT_KEY_CACHE_LIMIT).unwrap())
}

fn khf_spec_interval_cache_default() -> LruCache<u64, HashSet<(u64, u64)>> {
    LruCache::new(NonZeroUsize::new(DEFAULT_KHF_SPEC_INTERVAL_LIMIT).unwrap())
}

// This is just an approximation.
fn key_cache_heapsize<const N: usize>(cache: &LruCache<(u64, u64), Key<N>>) -> usize {
    cache.len() * (std::mem::size_of::<(u64, u64)>() + std::mem::size_of::<Key<N>>())
}

impl<K, R, G, C, H, const N: usize> Lethe<K, R, G, C, H, N> {
    pub fn new(dir: impl AsRef<Path>) -> Self
    where
        K: KeyDerivationFunction<N>,
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        Self::options().build(dir)
    }

    pub fn new_fragmented(dir: impl AsRef<Path>) -> Self
    where
        K: KeyDerivationFunction<N>,
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        Self::options().fragmented(true).build(dir)
    }

    pub fn options() -> LetheBuilder<K, R, G, C, H, N>
    where
        K: KeyDerivationFunction<N>,
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        LetheBuilder::new()
    }

    pub(crate) fn metadata_path(dir: &Path) -> PathBuf {
        path![dir / "state"]
    }

    pub(crate) fn total_key_cache_heapsize(&self) -> usize {
        key_cache_heapsize(&self.write_cache) + key_cache_heapsize(&self.read_cache)
    }

    pub(crate) fn get_object_khf(
        &mut self,
        obj_id: u64,
    ) -> Result<Option<Rc<RefCell<MappedKhf<R, G, C, H, N>>>>, Error<G::Error, C::Error>>
    where
        K: KeyDerivationFunction<N>,
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        // Resolve the object ID to KHF ID.
        let khf_id = self.id_manager.resolve_src_id(obj_id)?;

        // Get the object KHF that provides the block key. If it hasn't been
        // loaded yet, we derive the read key using the inner `derive()` call on
        // the system KHF.
        let khf = match self.arena.get(khf_id) {
            Some(khf) => Some(khf),
            None => self
                .arena
                .load(
                    khf_id,
                    self.system_khf
                        .derive_inner(khf_id, Some(&mut self.read_cache))
                        .ok_or(Error::NonExistentKey)?,
                    self.system_khf.mem_size() + self.total_key_cache_heapsize(),
                )
                .ok(),
        };

        Ok(khf)
    }

    pub(crate) fn get_object_khf_mut(
        &mut self,
        obj_id: u64,
    ) -> Result<Rc<RefCell<MappedKhf<R, G, C, H, N>>>, Error<G::Error, C::Error>>
    where
        K: KeyDerivationFunction<N, KeyId = (u64, u64)>,
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        // Get the KHF ID the object maps to, or allocate a new one.
        let khf_id = match self.id_manager.resolve_src_id(obj_id) {
            Ok(khf_id) => khf_id,
            Err(_) => {
                // Create a new mapping.
                let khf_id = self.id_manager.add(obj_id)?;

                // Create the KHF.
                let root_key = self.root_key_kdf.derive(DEFAULT_SYSTEM_KHF_KEY_ID);
                let spanning_root_key =
                    self.spanning_root_key_kdf.derive(DEFAULT_SYSTEM_KHF_KEY_ID);
                let khf = MappedKhf::options()
                    .fanouts(&self.object_khf_fanouts)
                    .fragmented(self.fragmented)
                    .with_keys(khf_id, obj_id, root_key, spanning_root_key);

                // Add the KHF to the arena.
                self.arena.insert(
                    khf,
                    self.system_khf.derive_mut_inner_unlogged(
                        khf_id,
                        Some(&mut self.write_cache),
                        Some(&mut self.read_cache),
                    ),
                    self.system_khf.mem_size(),
                )?;

                khf_id
            }
        };

        // Get the KHF. This should always yield us a KHF since we just
        // allocated one if it's missing.
        let khf = match self.arena.get(khf_id) {
            Some(khf) => {
                self.system_khf.mark_key_inner(khf_id);
                Some(khf)
            }
            None => self
                .arena
                .load(
                    khf_id,
                    self.system_khf.derive_mut_inner_unlogged(
                        khf_id,
                        Some(&mut self.write_cache),
                        Some(&mut self.read_cache),
                    ),
                    self.system_khf.mem_size() + self.total_key_cache_heapsize(),
                )
                .ok(),
        }
        .ok_or(Error::LoadObjectKhf)?;

        Ok(khf)
    }
}

impl<K, R, G, C, H, const N: usize> KeyManagementScheme for Lethe<K, R, G, C, H, N>
where
    K: KeyDerivationFunction<N>,
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    type KeyId = (u64, u64);
    type LogEntry = StableLogEntry;
    type Error = Error<G::Error, C::Error>;
}

impl<K, R, G, C, H, const N: usize> StableKeyManagementScheme<G, C, N> for Lethe<K, R, G, C, H, N>
where
    K: KeyDerivationFunction<N, KeyId = (u64, u64)>,
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    fn derive(&mut self, (obj_id, block): Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
        #[cfg(feature = "lethe-caching")]
        {
            // Get the KHF ID the object maps to.
            // We might have already cached this key.
            let khf_id = self.id_manager.resolve_src_id(obj_id)?;
            if let Some(key) = self.read_cache.get(&(khf_id, block)) {
                return Ok(Some(*key));
            }
        }

        // Get the object KHF that provides the block key.
        // If there isn't a KHF, then we don't technically don't cover the key.
        let khf = match self.get_object_khf(obj_id)? {
            Some(khf) => khf,
            None => return Ok(None),
        };

        // Need the borrow to last.
        let mut khf = khf.borrow_mut();
        Ok(khf.derive_inner(block, Some(&mut self.read_cache)))
    }

    fn ranged_derive(
        &mut self,
        (obj_id, start_block): Self::KeyId,
        (_obj_id, end_block): Self::KeyId,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        // Get the object KHF that provides the block key.
        // If there isn't a KHF, then we don't technically don't cover these keys.
        let khf = match self.get_object_khf(obj_id)? {
            Some(khf) => khf,
            None => return Ok(vec![]),
        };

        // Need the borrow to last.
        let mut khf = khf.borrow_mut();
        let keys = khf.ranged_derive_inner(start_block, end_block, Some(&mut self.read_cache));

        Ok(keys
            .into_iter()
            .map(|(block, key)| ((obj_id, block), key))
            .collect())
    }

    fn derive_mut(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        (obj_id, block): Self::KeyId,
    ) -> Result<Key<N>, Self::Error> {
        #[cfg(feature = "lethe-caching")]
        {
            // We might have already cached this key, but only if the object to
            // KHF ID mapping exists. If it doesn't, then this is a key for a
            // new object.
            if let Ok(khf_id) = self.id_manager.resolve_src_id(obj_id) {
                if let Some(key) = self.write_cache.get(&(khf_id, block)) {
                    return Ok(*key);
                }
            }
        }

        // Get the object KHF that provides the block key.
        let khf = self.get_object_khf_mut(obj_id)?;
        let mut khf = khf.borrow_mut();

        // Mark KHF as dirty.
        self.dirty_object_khfs.insert(obj_id);

        // Get the interval tree for the KHF.
        let speculated_key_intervals = self
            .speculated_key_intervals
            .get_or_insert_mut(khf.khf_id, || HashSet::default());

        // Using `derive_mut` on the object KHF yields the desired block key,
        // and updates it to provide a new block key at the next `update`.
        Ok(khf.derive_mut_inner(
            wal,
            block,
            Some(speculated_key_intervals),
            Some(&mut self.write_cache),
            Some(&mut self.read_cache),
        ))
    }

    fn ranged_derive_mut(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        (obj_id, start_block): Self::KeyId,
        (_obj_id, end_block): Self::KeyId,
        spec_bounds: Option<(Self::KeyId, Self::KeyId)>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        // Get the object KHF that provides the block key.
        let khf = self.get_object_khf_mut(obj_id)?;
        let mut khf = khf.borrow_mut();

        // Mark KHF as dirty.
        self.dirty_object_khfs.insert(obj_id);

        // Get the interval tree for the KHF.
        let speculated_key_intervals = self
            .speculated_key_intervals
            .get_or_insert_mut(khf.khf_id, || HashSet::default());

        // Speculatively derive the keys with the object KHF.
        let keys = khf.ranged_derive_mut_inner(
            wal,
            start_block,
            end_block,
            spec_bounds.map(|((_, spec_start), (_, spec_end))| (spec_start, spec_end)),
            Some(speculated_key_intervals),
            Some(&mut self.write_cache),
            Some(&mut self.read_cache),
        );

        Ok(keys
            .into_iter()
            .map(|(block, key)| ((obj_id, block), key))
            .collect())
    }

    fn delete(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        (obj_id, block): Self::KeyId,
    ) -> Result<(), Self::Error> {
        // Get the object KHF that provides the block key.
        // I'm not sure if it matters that this may allocate a new object KHF,
        // but I don't think it ever happens.
        let khf = self.get_object_khf_mut(obj_id)?;
        let mut khf = khf.borrow_mut();

        // Mark KHF as dirty.
        self.dirty_object_khfs.insert(obj_id);

        // Need the borrow to last.
        Ok(khf.delete_inner(wal, block))
    }

    fn update(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        // Make a copy of the WAL.
        let wal: Vec<_> = wal.into_iter().map(|entry| entry.clone()).collect();

        // Go through the WAL entries and create a log for the system KHF.
        let mut system_khf_wal = vec![];
        for entry in &wal {
            match entry {
                StableLogEntry::UpdateRange {
                    id: obj_id,
                    start_block: _,
                    end_block: _,
                } => {
                    if let Ok(khf_id) = self.id_manager.resolve_src_id(*obj_id) {
                        system_khf_wal.push(StableLogEntry::Update {
                            id: DEFAULT_SYSTEM_KHF_OBJ_ID,
                            block: khf_id,
                        });
                    }
                }
                StableLogEntry::Update {
                    id: obj_id,
                    block: _,
                } => {
                    if let Ok(khf_id) = self.id_manager.resolve_src_id(*obj_id) {
                        system_khf_wal.push(StableLogEntry::Update {
                            id: DEFAULT_SYSTEM_KHF_OBJ_ID,
                            block: khf_id,
                        });
                    }
                }
                StableLogEntry::Delete {
                    id: obj_id,
                    block: _,
                } => {
                    if let Ok(khf_id) = self.id_manager.resolve_src_id(*obj_id) {
                        system_khf_wal.push(StableLogEntry::Update {
                            id: DEFAULT_SYSTEM_KHF_OBJ_ID,
                            block: khf_id,
                        });
                    }
                }
                StableLogEntry::DeleteObject { id: obj_id } => {
                    if let Ok(khf_id) = self.id_manager.remove(*obj_id) {
                        let _ = self.arena.remove(khf_id);
                        system_khf_wal.push(StableLogEntry::Delete {
                            id: DEFAULT_SYSTEM_KHF_OBJ_ID,
                            block: khf_id,
                        });
                    }
                }
            }
        }

        let mut updated_keys = vec![];

        // Updating the system KHF should give us a list of updated object KHFs
        // and their respective keys.
        for (khf_id, khf_key) in self.system_khf.update_inner(system_khf_wal.iter()) {
            // We must have deallocated the KHF if we error when resolving.
            let Ok(obj_id) = self.id_manager.resolve_dst_id(khf_id) else {
                continue;
            };

            // We already have the key, so we won't bother with `get_object_khf_mut()`.
            let khf = match self.arena.get(khf_id) {
                Some(khf) => khf,
                None => self.arena.load(
                    khf_id,
                    khf_key,
                    self.system_khf.mem_size() + self.total_key_cache_heapsize(),
                )?,
            };

            // Update the object KHF with a filtered WAL.
            let mut khf = khf.borrow_mut();
            let mut keys = khf.update_inner(wal.iter().filter(|entry| match entry {
                StableLogEntry::UpdateRange {
                    id,
                    start_block: _,
                    end_block: _,
                } => *id == obj_id,
                StableLogEntry::Update { id, block: _ } => *id == obj_id,
                StableLogEntry::Delete { id, block: _ } => *id == obj_id,
                StableLogEntry::DeleteObject { id: _ } => false,
            }));

            // Add the keys.
            updated_keys.extend(keys.drain(..).map(|(block, key)| ((obj_id, block), key)))
        }

        // We need new KDFs for the epoch.
        self.root_key_kdf = K::with_key(self.rng.gen_key());
        self.spanning_root_key_kdf = K::with_key(self.rng.gen_key());

        #[cfg(feature = "lethe-interval-tracking")]
        self.speculated_key_intervals.clear();

        #[cfg(feature = "lethe-caching")]
        {
            self.write_cache.clear();
            self.read_cache.clear();
        }

        Ok(updated_keys)
    }
}

impl<K, R, G, C, H, const N: usize> AffineKeyManagementScheme<G, C, N> for Lethe<K, R, G, C, H, N>
where
    K: KeyDerivationFunction<N, KeyId = (u64, u64)>,
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    fn derive_read_key(&mut self, _key_id: Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
        todo!()
    }

    fn derive_read_key_many(
        &mut self,
        (_obj_id, _start_block): Self::KeyId,
        (_, _end_block): Self::KeyId,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        todo!()
    }

    fn derive_write_key(&mut self, _key_id: Self::KeyId) -> Result<Key<N>, Self::Error> {
        todo!()
    }

    fn derive_write_key_many(
        &mut self,
        _start_key_id: Self::KeyId,
        _end_key_id: Self::KeyId,
        _spec_bounds: Option<(Self::KeyId, Self::KeyId)>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        todo!()
    }

    fn delete(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
        _key_id: Self::KeyId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn update(&mut self, _entries: &[Self::LogEntry]) -> Result<(), Self::Error> {
        todo!()
    }
}

impl<K, R, G, C, H, const N: usize> SpeculativeKeyManagementScheme<G, C, N>
    for Lethe<K, R, G, C, H, N>
where
    K: KeyDerivationFunction<N, KeyId = (u64, u64)>,
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    fn speculate_range(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
        (_obj_id, _start_block): Self::KeyId,
        (_, _end_block): Self::KeyId,
    ) -> Result<(), Self::Error> {
        todo!()
        // #[cfg(feature = "lethe-interval-tracking")]
        // {
        //     let khf_id = self.id_manager.resolve_src_id(obj_id)?;

        //     // There exists a `speculate_range_inner()` function on the inner mapped
        //     // KHF, but that may require an unnecessary load. This is code
        //     // duplication for the sake of efficiency (sad).
        //     let speculated_key_intervals = self
        //         .speculated_key_intervals
        //         .get_or_insert_mut(khf_id, || HashSet::default());

        //     if !speculated_key_intervals.contains(&(start_block, end_block)) {
        //         speculated_key_intervals.insert((start_block, end_block));
        //         wal.append(StableLogEntry::UpdateRange {
        //             id: obj_id,
        //             start_block,
        //             end_block,
        //         });
        //     }
        // }

        // #[cfg(not(feature = "lethe-interval-tracking"))]
        // wal.append(StableLogEntry::UpdateRange {
        //     id: obj_id,
        //     start_block,
        //     end_block,
        // });

        // Ok(())
    }
}

impl<K, R, G, C, H, const N: usize> PersistableKeyManagementScheme<N> for Lethe<K, R, G, C, H, N>
where
    for<'de> K: KeyDerivationFunction<N, KeyId = (u64, u64)> + Serialize + Deserialize<'de>,
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    fn persist(&mut self, root_key: Key<N>, dir: impl AsRef<Path>) -> Result<(), Self::Error> {
        fs::create_dir_all(dir.as_ref())?;

        // Persist dirty object KHFs.
        for obj_id in self.dirty_object_khfs.clone() {
            // If we don't get a KHF from this, it might've been removed and
            // never persisted, so we ignore it.
            let khf = match self.get_object_khf(obj_id) {
                Ok(Some(khf)) => khf,
                _ => continue,
            };

            // Get the object KHF's key.
            let mut khf = khf.borrow_mut();
            let khf_id = khf.khf_id;
            let khf_key = self.system_khf.derive_mut_inner_unlogged(
                khf_id,
                Some(&mut self.write_cache),
                Some(&mut self.read_cache),
            );

            // Persist the object KHF.
            let khf_path = PersistentArena::<R, G, C, H, N>::khf_path(&dir, khf_id);
            khf.persist(khf_key, khf_path)?;
        }

        // We should have persisted all the dirty object KHFs.
        self.dirty_object_khfs.clear();

        // Serialize state.
        let ser = bincode::serialize(self)?;

        // Persist state.
        let state_path = Self::metadata_path(dir.as_ref());
        let mut io = OneshotCryptIo::new(
            StdIo::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&state_path)?,
            ),
            root_key,
            &mut self.ivg,
            &self.crypter,
        );
        io.write_all(&ser).map_err(|_| Error::Persist)?;

        Ok(())
    }

    fn load(root_key: Key<N>, path: impl AsRef<Path>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if fs::metadata(&path).is_err() {
            return Ok(Self::new(&path));
        }

        let mut ser = vec![];
        let mut ivg = G::default();
        let crypter = C::default();

        let mut io = OneshotCryptIo::new(
            StdIo::new(
                File::options()
                    .read(true)
                    .open(Self::metadata_path(path.as_ref()))?,
            ),
            root_key,
            &mut ivg,
            &crypter,
        );

        io.read_to_end(&mut ser).map_err(|_| Error::Load)?;

        Ok(bincode::deserialize(&ser)?)
    }

    fn rebase(&mut self, dir: impl AsRef<Path>) -> Result<(), Self::Error> {
        self.arena.rebase(dir)
    }
}

impl<K, R, G, C, H, const N: usize> LocalizedKeyManagementScheme<G, C, N>
    for Lethe<K, R, G, C, H, N>
where
    K: KeyDerivationFunction<N, KeyId = (u64, u64)>,
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    type ObjectId = u64;

    fn delete_object(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        obj_id: Self::ObjectId,
    ) -> Result<(), Self::Error> {
        let khf_id = match self.id_manager.remove(obj_id) {
            Ok(khf_id) => khf_id,
            Err(_) => return Ok(()),
        };

        self.system_khf.delete_inner_unlogged(khf_id);
        self.arena.remove(khf_id)?;

        // Remove KHF from dirty ones; we don't need to persist it anymore.
        self.dirty_object_khfs.remove(&khf_id);

        wal.append(StableLogEntry::DeleteObject { id: obj_id });

        Ok(())
    }

    fn truncate_object(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        obj_id: Self::ObjectId,
        num_keys: u64,
    ) -> Result<(), Self::Error> {
        let khf = self.get_object_khf_mut(obj_id)?;
        let mut khf = khf.borrow_mut();

        // Mark KHF as dirty.
        self.dirty_object_khfs.insert(obj_id);

        // We truncate keys by removing them off the end.
        for block in (num_keys..khf.num_keys()).rev() {
            khf.delete_inner(wal, block);
        }

        Ok(())
    }
}

#[derive(Serialize)]
pub struct LetheStats {
    pub system_khf_stats: KhfStats,
    pub object_khf_stats: Vec<(u64, KhfStats)>,
}

impl<K, R, G, C, H, const N: usize> InstrumentedKeyManagementScheme for Lethe<K, R, G, C, H, N>
where
    K: KeyDerivationFunction<N, KeyId = u64>,
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    type Stats = LetheStats;

    // TODO: Need to figure out what exactly to report.
    fn report_stats(&mut self) -> Result<Self::Stats, Self::Error> {
        Ok(LetheStats {
            system_khf_stats: self.system_khf.report_stats()?,
            object_khf_stats: Vec::new(),
        })
    }
}

// #[cfg(test)]
// mod tests {
//     use std::collections::HashMap;

//     use crypter::{aes::Aes256Ctr, ivs::SequentialIvg};
//     use hasher::sha3::{Sha3_256, SHA3_256_MD_SIZE};
//     use kms::kdf::{Blake3KDF, LocalizedBlake3KDF};
//     use rand::rngs::ThreadRng;

//     use super::*;

//     #[test]
//     fn it_works() {
//         let test = "lethe_test_it_works";
//         let kms = format!("/tmp/{test}.kms");
//         let wal = format!("/tmp/{test}.log");

//         let _ = fs::remove_dir_all(&kms);
//         let _ = fs::remove_file(&kms);
//         let _ = fs::remove_file(&wal);

//         let mut lethe = Lethe::<
//             LocalizedBlake3KDF,
//             ThreadRng,
//             SequentialIvg,
//             Aes256Ctr,
//             Sha3_256,
//             SHA3_256_MD_SIZE,
//         >::new(&kms);
//         let mut wal = SecureWAL::open(&wal, [0; SHA3_256_MD_SIZE]).unwrap();

//         let old_keys = (0..10)
//             .map(|block| ((0, block), lethe.derive_mut(&mut wal, (0, block)).unwrap()))
//             .collect::<HashMap<_, _>>();
//         // eprintln!("derived old keys");

//         let update = HashMap::from_iter(lethe.update(&mut wal).unwrap());
//         assert_eq!(update, old_keys);
//         // eprintln!("updated");

//         let new_keys = (0..10)
//             .map(|block| ((0, block), lethe.derive_mut(&mut wal, (0, block)).unwrap()))
//             .collect::<HashMap<_, _>>();
//         // eprintln!("derived new keys");

//         assert_ne!(old_keys, new_keys);

//         wal.persist([0; SHA3_256_MD_SIZE]).unwrap();
//     }

//     #[test]
//     fn it_works_speculatively() {
//         let test = "lethe_test_it_works_speculatively";
//         let kms = format!("/tmp/{test}.kms");
//         let wal = format!("/tmp/{test}.log");

//         let _ = fs::remove_dir_all(&kms);
//         let _ = fs::remove_file(&kms);
//         let _ = fs::remove_file(&wal);

//         let mut lethe = Lethe::<
//             LocalizedBlake3KDF,
//             ThreadRng,
//             SequentialIvg,
//             Aes256Ctr,
//             Sha3_256,
//             SHA3_256_MD_SIZE,
//         >::new(&kms);
//         let wal = SecureWAL::open(&wal, [0; SHA3_256_MD_SIZE]).unwrap();

//         lethe.speculate_range(&wal, (0, 0), (0, 10)).unwrap();

//         let old_keys: Vec<_> = (0..10)
//             .map(|block| lethe.derive_mut(&wal, (0, block)).unwrap())
//             .collect();

//         let update = lethe.update(&wal).unwrap();
//         assert_eq!(update.len(), old_keys.len());

//         let new_keys = (0..10)
//             .map(|block| lethe.derive_mut(&wal, (0, block)).unwrap())
//             .collect::<Vec<_>>();

//         assert_ne!(old_keys, new_keys);

//         wal.persist([0; SHA3_256_MD_SIZE]).unwrap();
//     }

//     #[test]
//     fn observable_speculation() {
//         let test = "lethe_observable_speculation";
//         let kms = format!("/tmp/{test}.kms");
//         let wal = format!("/tmp/{test}.log");

//         let _ = fs::remove_dir_all(&kms);
//         let _ = fs::remove_file(&kms);
//         let _ = fs::remove_file(&wal);

//         let mut lethe = Lethe::<
//             LocalizedBlake3KDF,
//             ThreadRng,
//             SequentialIvg,
//             Aes256Ctr,
//             Sha3_256,
//             SHA3_256_MD_SIZE,
//         >::new(&kms);
//         let wal = SecureWAL::open(&wal, [0; SHA3_256_MD_SIZE]).unwrap();

//         lethe.speculate_range(&wal, (0, 0), (0, 10)).unwrap();

//         let derive_mut_keys = lethe
//             .ranged_derive_mut(&wal, (0, 0), (0, 10), None)
//             .unwrap();
//         let derive_keys = lethe.ranged_derive((0, 0), (0, 10)).unwrap();

//         // for block in 0..10 {
//         //     eprintln!(
//         //         "speculated = {}, derived = {}",
//         //         hex::encode(&derive_mut_keys[block]),
//         //         hex::encode(&derive_keys[block])
//         //     );
//         // }

//         assert_eq!(derive_mut_keys, derive_keys);
//     }

//     #[test]
//     fn crash_recovery() {
//         let test = "lethe_crash_recovery";
//         let kms = format!("/tmp/{test}.kms");
//         let wal = format!("/tmp/{test}.log");

//         let _ = fs::remove_dir_all(&kms);
//         let _ = fs::remove_file(&kms);
//         let _ = fs::remove_file(&wal);

//         let root_key = [0; SHA3_256_MD_SIZE];

//         let mut lethe = Lethe::<
//             LocalizedBlake3KDF,
//             ThreadRng,
//             SequentialIvg,
//             Aes256Ctr,
//             Sha3_256,
//             SHA3_256_MD_SIZE,
//         >::new(&kms);
//         let wal = SecureWAL::open(&wal, root_key).unwrap();

//         let keys: HashMap<_, _> = lethe
//             .ranged_derive_mut(&wal, (0, 0), (0, 10), None)
//             .unwrap()
//             .into_iter()
//             .collect();

//         lethe.persist(root_key, &kms).unwrap();

//         let mut lethe = Lethe::<
//             LocalizedBlake3KDF,
//             ThreadRng,
//             SequentialIvg,
//             Aes256Ctr,
//             Sha3_256,
//             SHA3_256_MD_SIZE,
//         >::load(root_key, &kms)
//         .unwrap();

//         let update = HashMap::from_iter(lethe.update(&wal).unwrap());

//         assert_eq!(keys, update);
//     }
// }
