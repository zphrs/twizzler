use std::{collections::HashMap, convert::Infallible};

use super::{
    AffineKeyManagementScheme, KeyManagementScheme, LocalizedKeyManagementScheme,
    PersistableKeyManagementScheme, StableLogEntry,
};
use crate::{
    kdf::KeyDerivationFunction,
    key::{Key, KeyGenerator},
    khf::KhfKeyId,
    wal::SecureWAL,
};

pub struct AffineKeyMap<KDF, R, const N: usize> {
    keys: HashMap<KhfKeyId, Key<N>>,
    kdf: KDF,
    rng: R,
}

impl<KDF, R, const N: usize> AffineKeyMap<KDF, R, N>
where
    KDF: KeyDerivationFunction<N>,
    R: KeyGenerator<N>,
{
    pub fn new(mut rng: R) -> Self {
        Self {
            keys: HashMap::new(),
            kdf: KDF::with_key(rng.gen_key()),
            rng,
        }
    }
}

impl<KDF, R, const N: usize> KeyManagementScheme for AffineKeyMap<KDF, R, N> {
    type KeyId = KhfKeyId;
    type LogEntry = StableLogEntry;
    type Error = Infallible;
}

impl<KDF, R, G, C, const N: usize> AffineKeyManagementScheme<G, C, N> for AffineKeyMap<KDF, R, N>
where
    KDF: KeyDerivationFunction<N, KeyId = Self::KeyId>,
    R: KeyGenerator<N>,
{
    fn derive_read_key(&mut self, key_id: Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
        Ok(self.keys.get(&key_id).map(|key| *key))
    }

    fn derive_read_key_many(
        &mut self,
        start_key_id: Self::KeyId,
        end_key_id: Self::KeyId,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        let mut keys = vec![];

        for key_id in start_key_id..end_key_id {
            if let Some(key) =
                <Self as AffineKeyManagementScheme<G, C, N>>::derive_read_key(self, key_id)?
            {
                keys.push((key_id, key));
            } else {
                break;
            }
        }

        Ok(keys)
    }

    fn derive_write_key(&mut self, key_id: Self::KeyId) -> Result<Key<N>, Self::Error> {
        Ok(self.kdf.derive(key_id))
    }

    fn derive_write_key_many(
        &mut self,
        start_key_id: Self::KeyId,
        end_key_id: Self::KeyId,
        _spec_bounds: Option<(Self::KeyId, Self::KeyId)>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        let mut keys = vec![];

        for key_id in start_key_id..end_key_id {
            let key = <Self as AffineKeyManagementScheme<G, C, N>>::derive_write_key(self, key_id)?;
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
        Ok(())
    }

    fn update(&mut self, wal: &[Self::LogEntry]) -> Result<(), Self::Error> {
        for entry in wal {
            if let StableLogEntry::Update { id: _, block } = entry {
                let key = self.kdf.derive(*block);
                self.keys.insert(*block, key);
            }
        }

        self.kdf = KDF::with_key(self.rng.gen_key());

        Ok(())
    }
}

pub struct LocalizedAffineKeyMap<KDF, R, const N: usize> {
    keys: HashMap<(KhfKeyId, KhfKeyId), Key<N>>,
    kdf: KDF,
    rng: R,
}

impl<KDF, R, const N: usize> LocalizedAffineKeyMap<KDF, R, N>
where
    KDF: KeyDerivationFunction<N>,
    R: KeyGenerator<N>,
{
    pub fn new(mut rng: R) -> Self {
        Self {
            keys: HashMap::new(),
            kdf: KDF::with_key(rng.gen_key()),
            rng,
        }
    }
}

impl<KDF, R, const N: usize> KeyManagementScheme for LocalizedAffineKeyMap<KDF, R, N> {
    type KeyId = (KhfKeyId, KhfKeyId);
    type LogEntry = StableLogEntry;
    type Error = Infallible;
}

impl<KDF, R, G, C, const N: usize> AffineKeyManagementScheme<G, C, N>
    for LocalizedAffineKeyMap<KDF, R, N>
where
    KDF: KeyDerivationFunction<N, KeyId = (KhfKeyId, KhfKeyId)>,
    R: KeyGenerator<N>,
{
    fn derive_read_key(&mut self, key_id: Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
        Ok(self.keys.get(&key_id).map(|key| *key))
    }

    fn derive_read_key_many(
        &mut self,
        (obj_id, start_key_id): Self::KeyId,
        (_, end_key_id): Self::KeyId,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        let mut keys = vec![];

        for key_id in start_key_id..end_key_id {
            if let Some(key) = <Self as AffineKeyManagementScheme<G, C, N>>::derive_read_key(
                self,
                (obj_id, key_id),
            )? {
                keys.push(((obj_id, key_id), key));
            } else {
                break;
            }
        }

        Ok(keys)
    }

    fn derive_write_key(&mut self, key_id: Self::KeyId) -> Result<Key<N>, Self::Error> {
        Ok(self.kdf.derive(key_id))
    }

    fn derive_write_key_many(
        &mut self,
        (obj_id, start_key_id): Self::KeyId,
        (_, end_key_id): Self::KeyId,
        _spec_bounds: Option<(Self::KeyId, Self::KeyId)>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        let mut keys = vec![];

        for key_id in start_key_id..end_key_id {
            let key = <Self as AffineKeyManagementScheme<G, C, N>>::derive_write_key(
                self,
                (obj_id, key_id),
            )?;
            keys.push(((obj_id, key_id), key));
        }

        Ok(keys)
    }

    fn delete(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
        key_id: Self::KeyId,
    ) -> Result<(), Self::Error> {
        self.keys.remove(&key_id);
        Ok(())
    }

    fn update(&mut self, wal: &[Self::LogEntry]) -> Result<(), Self::Error> {
        for entry in wal {
            if let StableLogEntry::Update { id, block } = entry {
                let key = self.kdf.derive((*id, *block));
                self.keys.insert((*id, *block), key);
            }
        }

        self.kdf = KDF::with_key(self.rng.gen_key());

        Ok(())
    }
}

impl<KDF, R, G, C, const N: usize> LocalizedKeyManagementScheme<G, C, N>
    for LocalizedAffineKeyMap<KDF, R, N>
where
    KDF: KeyDerivationFunction<N, KeyId = (u64, u64)>,
    R: KeyGenerator<N>,
{
    type ObjectId = KhfKeyId;

    fn delete_object(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
        obj_id: Self::ObjectId,
    ) -> Result<(), Self::Error> {
        for block in 0.. {
            if self.keys.remove(&(obj_id, block)).is_none() {
                break;
            }
        }
        Ok(())
    }

    fn truncate_object(
        &mut self,
        _wal: &SecureWAL<Self::LogEntry, G, C, N>,
        obj_id: Self::ObjectId,
        num_keys: u64,
    ) -> Result<(), Self::Error> {
        for block in num_keys.. {
            if self.keys.remove(&(obj_id, block as KhfKeyId)).is_none() {
                break;
            }
        }
        Ok(())
    }
}

impl<KDF, R, const N: usize> PersistableKeyManagementScheme<N> for LocalizedAffineKeyMap<KDF, R, N>
where
    KDF: KeyDerivationFunction<N, KeyId = (u64, u64)>,
    R: KeyGenerator<N> + Default,
{
    fn load(_root_key: Key<N>, _path: impl AsRef<std::path::Path>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self::new(R::default()))
    }

    fn persist(
        &mut self,
        _root_key: Key<N>,
        _path: impl AsRef<std::path::Path>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}
