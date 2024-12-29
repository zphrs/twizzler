use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
};

use crate::{
    key::{Key, KeyGenerator},
    wal::SecureWAL,
};

use super::{
    JournalEntry, KeyManagementScheme, SpeculativeKeyManagementScheme, StableKeyManagementScheme,
    StableLogEntry, UnstableKeyManagementScheme,
};

pub struct StableKeyMap<R, const N: usize> {
    keys: HashMap<u64, Key<N>>,
    updated_keys: HashSet<u64>,
    rng: R,
}

impl<R, const N: usize> Default for StableKeyMap<R, N>
where
    R: KeyGenerator<N> + Default,
{
    fn default() -> Self {
        Self {
            keys: HashMap::new(),
            updated_keys: HashSet::new(),
            rng: R::default(),
        }
    }
}

impl<R, const N: usize> KeyManagementScheme for StableKeyMap<R, N> {
    type KeyId = u64;
    type LogEntry = StableLogEntry;
    type Error = Infallible;
}

impl<R, G, C, const N: usize> StableKeyManagementScheme<G, C, N> for StableKeyMap<R, N>
where
    R: KeyGenerator<N>,
{
    fn derive(&mut self, key_id: Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
        Ok(self.keys.get(&key_id).map(|key| *key))
    }

    fn ranged_derive(
        &mut self,
        start_key_id: Self::KeyId,
        end_key_id: Self::KeyId,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        let mut keys = vec![];

        for key_id in start_key_id..end_key_id {
            if let Some(key) = <Self as StableKeyManagementScheme<G, C, N>>::derive(self, key_id)? {
                keys.push((key_id, key));
            } else {
                break;
            }
        }

        Ok(keys)
    }

    fn derive_mut(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
        key_id: Self::KeyId,
    ) -> Result<Key<N>, Self::Error> {
        self.updated_keys.insert(key_id);

        Ok(*self
            .keys
            .entry(key_id)
            .or_insert_with(|| self.rng.gen_key()))
    }

    fn ranged_derive_mut(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        start_key_id: Self::KeyId,
        end_key_id: Self::KeyId,
        _spec_bounds: Option<(Self::KeyId, Self::KeyId)>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        let mut keys = vec![];

        for key_id in start_key_id..end_key_id {
            let key = self.derive_mut(wal, key_id)?;
            keys.push((key_id, key));
        }

        Ok(keys)
    }

    fn delete(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
        key_id: Self::KeyId,
    ) -> Result<(), Self::Error> {
        self.keys.remove(&key_id);
        self.updated_keys.remove(&key_id);
        Ok(())
    }

    fn update(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        let mut res = vec![];

        for key_id in &self.updated_keys {
            if let Some(key) = self.keys.get_mut(key_id) {
                res.push((*key_id, *key));
                *key = self.rng.gen_key();
            }
        }

        Ok(res)
    }
}

impl<R, G, C, const N: usize> SpeculativeKeyManagementScheme<G, C, N> for StableKeyMap<R, N>
where
    R: KeyGenerator<N>,
{
    fn speculate_range(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
        _start_key_id: Self::KeyId,
        _end_key_id: Self::KeyId,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct UnstableKeyMap<R, const N: usize> {
    keys: HashMap<u64, Key<N>>,
    rng: R,
}

impl<R, const N: usize> Default for UnstableKeyMap<R, N>
where
    R: KeyGenerator<N> + Default,
{
    fn default() -> Self {
        Self {
            keys: HashMap::new(),
            rng: R::default(),
        }
    }
}

impl<R, const N: usize> KeyManagementScheme for UnstableKeyMap<R, N> {
    type KeyId = u64;
    type LogEntry = JournalEntry<N>;
    type Error = Infallible;
}

impl<R, G, C, const N: usize> UnstableKeyManagementScheme<G, C, N> for UnstableKeyMap<R, N>
where
    R: KeyGenerator<N>,
{
    fn derive(&mut self, key_id: Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
        Ok(self.keys.get(&key_id).map(|key| *key))
    }

    fn derive_mut(&mut self, key_id: Self::KeyId) -> Result<Key<N>, Self::Error> {
        let key = self.rng.gen_key();
        Ok(*self
            .keys
            .entry(key_id)
            .and_modify(|old_key| *old_key = key)
            .or_insert(key))
    }

    fn sync(&mut self, _entry: &Self::LogEntry) -> Result<(), Self::Error> {
        Ok(())
    }

    fn delete(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
        key_id: Self::KeyId,
    ) -> Result<(), Self::Error> {
        self.keys.remove(&key_id);
        Ok(())
    }

    fn update(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
    ) -> Result<Vec<(Self::KeyId, (Key<N>, Vec<u8>))>, Self::Error> {
        Ok(vec![])
    }
}
