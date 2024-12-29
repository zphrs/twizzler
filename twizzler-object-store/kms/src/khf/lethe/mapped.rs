use std::{collections::HashSet, fs::File, path::Path};

use lru_mem::HeapSize;
use serde::{Deserialize, Serialize};

use crate::{
    crypter::{aes::Aes256Ctr, ivs::SequentialIvg, Ivg, StatefulCrypter},
    hasher::Hasher,
    io::{crypt::OneshotCryptIo, stdio::StdIo, Read, Write},
    key::{Key, KeyGenerator},
    khf::{Error, Khf, KhfBuilder, KhfStats, Pos},
    wal::SecureWAL,
    InstrumentedKeyManagementScheme, KeyManagementScheme, PersistableKeyManagementScheme,
    StableLogEntry,
};

#[derive(Deserialize, Serialize)]
pub struct MappedKhf<R, G, C, H, const N: usize> {
    #[serde(bound(serialize = "Khf<R, G, C, H, N>: Serialize"))]
    #[serde(bound(deserialize = "Khf<R, G, C, H, N>: Deserialize<'de>"))]
    pub(crate) inner: Khf<R, G, C, H, N>,
    pub(crate) khf_id: u64,
    pub(crate) obj_id: u64,
}

impl<R, G, C, H, const N: usize> HeapSize for MappedKhf<R, G, C, H, N> {
    fn heap_size(&self) -> usize {
        self.inner.heap_size() + self.khf_id.heap_size()
    }
}

impl<R, G, C, H, const N: usize> MappedKhf<R, G, C, H, N> {
    pub fn new(khf_id: u64, obj_id: u64) -> Self
    where
        R: KeyGenerator<N> + Default,
        G: Default,
        C: Default,
    {
        Self::options().with_rng(khf_id, obj_id)
    }

    pub fn with_keys(khf_id: u64, obj_id: u64, root_key: Key<N>, spanning_root_key: Key<N>) -> Self
    where
        R: Default,
        G: Default,
        C: Default,
    {
        Self::options().with_keys(khf_id, obj_id, root_key, spanning_root_key)
    }

    pub fn with_fanouts(khf_id: u64, obj_id: u64, fanouts: &[u64]) -> Self
    where
        R: KeyGenerator<N> + Default,
        G: Default,
        C: Default,
    {
        Self::options().fanouts(fanouts).with_rng(khf_id, obj_id)
    }

    pub fn options() -> MappedKhfBuilder<R, G, C, H, N> {
        MappedKhfBuilder::new()
    }

    pub fn num_keys(&self) -> u64 {
        self.inner.num_keys()
    }

    pub fn num_roots(&self) -> u64 {
        self.inner.num_roots()
    }

    pub fn is_consolidated(&self) -> bool {
        self.inner.is_consolidated()
    }

    pub fn mark_key_inner(&mut self, key_id: u64) {
        self.inner.mark_key_inner(key_id)
    }

    pub fn derive_inner(
        &mut self,
        key_id: u64,
        mut _read_cache: Option<&mut LruCache<Pos, Key<N>>>,
    ) -> Option<Key<N>>
    where
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        #[cfg(feature = "lethe-caching")]
        if let Some(read_cache) = _read_cache.as_mut() {
            if let Some(key) = read_cache.get(&(self.khf_id, key_id)) {
                return Some(*key);
            }
        }

        let key = self.inner.derive_inner(key_id);

        #[cfg(feature = "lethe-caching")]
        if let Some(read_cache) = _read_cache.as_mut() {
            if let Some(key) = key {
                read_cache.push((self.khf_id, key_id), key);
            }
        }

        key
    }

    pub fn ranged_derive_inner(
        &mut self,
        start_key_id: u64,
        end_key_id: u64,
        mut _read_cache: Option<&mut LruCache<Pos, Key<N>>>,
    ) -> Vec<(u64, Key<N>)>
    where
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        let keys: Vec<_> = self
            .inner
            .ranged_derive_inner(start_key_id, end_key_id)
            .collect();

        #[cfg(feature = "lethe-caching")]
        if let Some(read_cache) = _read_cache.as_mut() {
            for (block, key) in &keys {
                read_cache.push((self.khf_id, *block), *key);
            }
        }

        keys
    }

    pub fn derive_mut_inner(
        &mut self,
        wal: &SecureWAL<StableLogEntry, G, C, N>,
        key_id: u64,
        mut _speculated_key_intervals: Option<&mut HashSet<(u64, u64)>>,
        mut _write_cache: Option<&mut LruCache<Pos, Key<N>>>,
        mut _read_cache: Option<&mut LruCache<Pos, Key<N>>>,
    ) -> Key<N>
    where
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        #[cfg(feature = "lethe-caching")]
        if let Some(write_cache) = _write_cache.as_mut() {
            if let Some(key) = write_cache.get(&(self.khf_id, key_id)) {
                return *key;
            }
        }

        #[cfg(feature = "lethe-interval-tracking")]
        {
            // TODO: We currently don't have a fast way to check if a single
            // block was speculated.
            wal.append(StableLogEntry::Update {
                id: self.obj_id,
                block: key_id,
            });
        }

        #[cfg(not(feature = "lethe-interval-tracking"))]
        wal.append(StableLogEntry::Update {
            id: self.obj_id,
            block: key_id,
        });

        let key = self.inner.derive_mut_inner(key_id);

        #[cfg(feature = "lethe-caching")]
        {
            if let Some(write_cache) = _write_cache.as_mut() {
                write_cache.push((self.khf_id, key_id), key);
            }

            if let Some(read_cache) = _read_cache.as_mut() {
                read_cache.push((self.khf_id, key_id), key);
            }
        }

        key
    }

    pub fn ranged_derive_mut_inner(
        &mut self,
        wal: &SecureWAL<StableLogEntry, G, C, N>,
        start_block: u64,
        end_block: u64,
        _spec_bounds: Option<(u64, u64)>,
        mut _speculated_key_ids: Option<&mut HashSet<(u64, u64)>>,
        mut _write_cache: Option<&mut LruCache<Pos, Key<N>>>,
        mut _read_cache: Option<&mut LruCache<Pos, Key<N>>>,
    ) -> Vec<(u64, Key<N>)>
    where
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        let (update_start_block, update_end_block) =
            _spec_bounds.unwrap_or((start_block, end_block));

        #[cfg(feature = "lethe-interval-tracking")]
        {
            if let Some(speculated_key_ids) = _speculated_key_ids.as_mut() {
                // Insert returns true if the set didn't contain the range previously.
                if speculated_key_ids.insert((update_start_block, update_end_block)) {
                    wal.append(StableLogEntry::UpdateRange {
                        id: self.obj_id,
                        start_block: update_start_block,
                        end_block: update_end_block,
                    });
                }
            } else {
                wal.append(StableLogEntry::UpdateRange {
                    id: self.obj_id,
                    start_block: update_start_block,
                    end_block: update_end_block,
                });
            }
        }

        #[cfg(not(feature = "lethe-interval-tracking"))]
        wal.append(StableLogEntry::UpdateRange {
            id: self.obj_id,
            start_block: update_start_block,
            end_block: update_end_block,
        });

        // We only want the specified keys, not the speculated ones.
        let keys: Vec<_> = self
            .inner
            .ranged_derive_mut_inner(start_block, end_block)
            .collect();

        #[cfg(feature = "lethe-caching")]
        {
            if let Some(write_cache) = _write_cache.as_mut() {
                for (block, key) in &keys {
                    write_cache.push((self.khf_id, *block), *key);
                }
            }

            if let Some(read_cache) = _read_cache.as_mut() {
                for (block, key) in &keys {
                    read_cache.push((self.khf_id, *block), *key);
                }
            }
        }

        keys
    }

    pub fn derive_mut_inner_unlogged(
        &mut self,
        key_id: u64,
        mut _write_cache: Option<&mut LruCache<Pos, Key<N>>>,
        mut _read_cache: Option<&mut LruCache<Pos, Key<N>>>,
    ) -> Key<N>
    where
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        #[cfg(feature = "lethe-caching")]
        if let Some(write_cache) = _write_cache.as_mut() {
            if let Some(key) = write_cache.get(&(self.khf_id, key_id)) {
                return *key;
            }
        }

        let key = self.inner.derive_mut_inner(key_id);

        #[cfg(feature = "lethe-caching")]
        {
            if let Some(write_cache) = _write_cache.as_mut() {
                write_cache.push((self.khf_id, key_id), key);
            }

            if let Some(read_cache) = _read_cache.as_mut() {
                read_cache.push((self.khf_id, key_id), key);
            }
        }

        key
    }

    pub fn delete_inner(&mut self, wal: &SecureWAL<StableLogEntry, G, C, N>, key_id: u64) {
        if self.inner.delete_key_inner(key_id) {
            // This means that we deleted a key through truncation.
            wal.append(StableLogEntry::Delete {
                id: self.obj_id,
                block: key_id,
            });
        } else {
            // This means that we're trying to delete a key in the middle of the
            // forest. We can achieve the same result by updating the key, which
            // is handled in the update procedure.
            wal.append(StableLogEntry::Update {
                id: self.obj_id,
                block: key_id,
            });
        }
    }

    pub fn delete_inner_unlogged(&mut self, key_id: u64) -> bool {
        self.inner.delete_key_inner(key_id)
    }

    pub fn update_inner<'a>(
        &mut self,
        wal: impl Iterator<Item = &'a StableLogEntry>,
    ) -> Vec<(u64, Key<N>)>
    where
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        let mut updated_keys = HashSet::new();

        // Replay the log.
        for entry in wal {
            match *entry {
                StableLogEntry::UpdateRange {
                    id: _,
                    start_block: start_key_id,
                    end_block: end_key_id,
                } => {
                    for key_id in start_key_id..end_key_id {
                        self.inner.mark_key_inner(key_id);
                        updated_keys.insert(key_id);
                    }
                }
                StableLogEntry::Update {
                    id: _,
                    block: key_id,
                } => {
                    self.inner.mark_key_inner(key_id);
                    updated_keys.insert(key_id);
                }
                StableLogEntry::Delete {
                    id: _,
                    block: key_id,
                } => {
                    self.inner.delete_key_inner(key_id);
                    updated_keys.remove(&key_id);
                }
                StableLogEntry::DeleteObject { id: _ } => {
                    unreachable!()
                }
            }
        }

        self.inner.update_inner(&updated_keys)
    }

    pub fn speculate_range_inner(
        &mut self,
        wal: &SecureWAL<StableLogEntry, G, C, N>,
        start_block: u64,
        end_block: u64,
        mut _speculated_key_intervals: Option<&mut HashSet<(u64, u64)>>,
    ) where
        R: KeyGenerator<N> + Default,
        G: Ivg + Default,
        C: StatefulCrypter + Default,
        H: Hasher<N>,
    {
        #[cfg(feature = "lethe-interval-tracking")]
        {
            if let Some(intervals) = _speculated_key_intervals.as_mut() {
                // Insert returns true if the set didn't contain the range previously.
                if intervals.insert((start_block, end_block)) {
                    wal.append(StableLogEntry::UpdateRange {
                        id: self.obj_id,
                        start_block: start_block,
                        end_block: end_block,
                    });
                }
            } else {
                wal.append(StableLogEntry::UpdateRange {
                    id: self.obj_id,
                    start_block: start_block,
                    end_block: end_block,
                });
            }
        }

        #[cfg(not(feature = "lethe-interval-tracking"))]
        wal.append(StableLogEntry::UpdateRange {
            id: self.khf_id,
            start_block: start_block,
            end_block: end_block,
        });
    }
}

pub struct MappedKhfBuilder<R, G, C, H, const N: usize> {
    inner: KhfBuilder<R, G, C, H, N>,
}

impl<R, G, C, H, const N: usize> MappedKhfBuilder<R, G, C, H, N> {
    pub fn new() -> Self {
        Self {
            inner: KhfBuilder::new(),
        }
    }

    pub fn fanouts(&mut self, fanouts: &[u64]) -> &mut Self {
        self.inner.fanouts(fanouts);
        self
    }

    pub fn fragmented(&mut self, fragmented: bool) -> &mut Self {
        self.inner.fragmented(fragmented);
        self
    }

    pub fn with_rng(&mut self, khf_id: u64, obj_id: u64) -> MappedKhf<R, G, C, H, N>
    where
        R: KeyGenerator<N> + Default,
        G: Default,
        C: Default,
    {
        let mut rng = R::default();
        let root_key = rng.gen_key();
        let spanning_root_key = rng.gen_key();
        self.with_keys(khf_id, obj_id, root_key, spanning_root_key)
    }

    pub fn with_keys(
        &mut self,
        khf_id: u64,
        obj_id: u64,
        root_key: Key<N>,
        spanning_root_key: Key<N>,
    ) -> MappedKhf<R, G, C, H, N>
    where
        R: Default,
        G: Default,
        C: Default,
    {
        MappedKhf {
            inner: self.inner.with_keys(root_key, spanning_root_key),
            khf_id,
            obj_id,
        }
    }
}

impl<R, G, C, H, const N: usize> Clone for MappedKhf<R, G, C, H, N>
where
    R: Default,
    G: Default,
    C: Default,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            khf_id: self.khf_id,
            obj_id: self.obj_id,
        }
    }
}

impl<R, G, C, H, const N: usize> KeyManagementScheme for MappedKhf<R, G, C, H, N>
where
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    type KeyId = u64;
    type LogEntry = StableLogEntry;
    type Error = Error<G::Error, C::Error>;
}

// impl<R, G, C, H, const N: usize> StableKeyManagementScheme<G, C, N> for MappedKhf<R, G, C, H, N>
// where
//     R: KeyGenerator<N> + Default,
//     G: Ivg + Default,
//     C: StatefulCrypter + Default,
//     H: Hasher<N>,
// {
//     fn derive(&mut self, key_id: Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
//         Ok(self.derive_inner(key_id, None))
//     }

//     fn ranged_derive(
//         &mut self,
//         start_key_id: Self::KeyId,
//         end_key_id: Self::KeyId,
//     ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
//         Ok(self.ranged_derive_inner(start_key_id, end_key_id, None))
//     }

//     fn derive_mut(
//         &mut self,
//         wal: &SecureWAL<Self::LogEntry, G, C, N>,
//         key_id: Self::KeyId,
//     ) -> Result<Key<N>, Self::Error> {
//         Ok(self.derive_mut_inner(wal, key_id, None, None, None))
//     }

//     fn ranged_derive_mut(
//         &mut self,
//         wal: &SecureWAL<Self::LogEntry, G, C, N>,
//         start_key_id: Self::KeyId,
//         end_key_id: Self::KeyId,
//         spec_bounds: Option<(Self::KeyId, Self::KeyId)>,
//     ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
//         Ok(self.ranged_derive_mut_inner(
//             wal,
//             start_key_id,
//             end_key_id,
//             spec_bounds,
//             None,
//             None,
//             None,
//         ))
//     }

//     fn delete(
//         &mut self,
//         wal: &SecureWAL<Self::LogEntry, G, C, N>,
//         key_id: Self::KeyId,
//     ) -> Result<(), Self::Error> {
//         Ok(self.delete_inner(wal, key_id))
//     }

//     fn update(
//         &mut self,
//         wal: &SecureWAL<Self::LogEntry, G, C, N>,
//     ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
//         Ok(self.update_inner(wal))
//     }
// }

// impl<R, G, C, H, const N: usize> SpeculativeKeyManagementScheme<G, C, N>
//     for MappedKhf<R, G, C, H, N>
// where
//     R: KeyGenerator<N> + Default,
//     G: Ivg + Default,
//     C: StatefulCrypter + Default,
//     H: Hasher<N>,
// {
//     fn speculate_range(
//         &mut self,
//         wal: &SecureWAL<Self::LogEntry, G, C, N>,
//         start_key_id: Self::KeyId,
//         end_key_id: Self::KeyId,
//     ) -> Result<(), Self::Error> {
//         Ok(self.speculate_range_inner(wal, start_key_id, end_key_id, None))
//     }
// }

impl<R, G, C, H, const N: usize> PersistableKeyManagementScheme<N> for MappedKhf<R, G, C, H, N>
where
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    fn persist(&mut self, root_key: Key<N>, path: impl AsRef<Path>) -> Result<(), Self::Error> {
        let ser = bincode::serialize(self)?;

        let mut io = OneshotCryptIo::new(
            StdIo::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)?,
            ),
            root_key,
            &mut self.inner.ivg,
            &mut self.inner.crypter,
        );

        Ok(io.write_all(&ser).map_err(|_| Error::Persist)?)
    }

    fn load(root_key: Key<N>, path: impl AsRef<Path>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut ser = vec![];
        let mut ivg = SequentialIvg::default();
        let crypter = Aes256Ctr::default();

        let mut io = OneshotCryptIo::new(
            StdIo::new(File::options().read(true).open(path)?),
            root_key,
            &mut ivg,
            &crypter,
        );

        io.read_to_end(&mut ser).map_err(|_| Error::Load)?;

        Ok(bincode::deserialize(&ser)?)
    }
}

impl<R, G, C, H, const N: usize> InstrumentedKeyManagementScheme for MappedKhf<R, G, C, H, N>
where
    R: KeyGenerator<N> + Default,
    G: Ivg + Default,
    C: StatefulCrypter + Default,
    H: Hasher<N>,
{
    type Stats = KhfStats;

    fn report_stats(&mut self) -> Result<Self::Stats, Self::Error> {
        self.inner.report_stats()
    }
}
