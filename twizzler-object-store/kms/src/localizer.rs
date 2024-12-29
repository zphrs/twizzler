use std::marker::PhantomData;

use crate::{key::Key, wal::SecureWAL};

use super::{
    AffineKeyManagementScheme, KeyManagementScheme, SpeculativeKeyManagementScheme,
    StableKeyManagementScheme, UnstableKeyManagementScheme,
};

pub struct Localizer<'a, KMS, G, C, const N: usize> {
    inner: &'a mut KMS,
    obj_id: u64,
    _pd: PhantomData<(G, C)>,
}

impl<'a, KMS, G, C, const N: usize> Localizer<'a, KMS, G, C, N> {
    pub fn new(inner: &'a mut KMS, obj_id: u64) -> Self {
        Self {
            inner,
            obj_id,
            _pd: PhantomData,
        }
    }
}

impl<'a, KMS, G, C, const N: usize> KeyManagementScheme for Localizer<'a, KMS, G, C, N>
where
    KMS: KeyManagementScheme<KeyId = (u64, u64)>,
{
    type KeyId = u64;
    type LogEntry = KMS::LogEntry;
    type Error = KMS::Error;
}

impl<'a, KMS, G, C, const N: usize> StableKeyManagementScheme<G, C, N>
    for Localizer<'a, KMS, G, C, N>
where
    KMS: StableKeyManagementScheme<G, C, N, KeyId = (u64, u64)>,
{
    fn derive(&mut self, key_id: Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
        self.inner.derive((self.obj_id, key_id))
    }

    fn ranged_derive(
        &mut self,
        start_key_id: Self::KeyId,
        end_key_id: Self::KeyId,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        Ok(self
            .inner
            .ranged_derive((self.obj_id, start_key_id), (self.obj_id, end_key_id))?
            .into_iter()
            .map(|((_, block), key)| (block, key))
            .collect())
    }

    fn derive_mut(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        key_id: Self::KeyId,
    ) -> Result<Key<N>, Self::Error> {
        self.inner.derive_mut(wal, (self.obj_id, key_id))
    }

    fn ranged_derive_mut(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        start_key_id: Self::KeyId,
        end_key_id: Self::KeyId,
        spec_bounds: Option<(Self::KeyId, Self::KeyId)>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        Ok(self
            .inner
            .ranged_derive_mut(
                wal,
                (self.obj_id, start_key_id),
                (self.obj_id, end_key_id),
                spec_bounds.map(|(start, end)| ((self.obj_id, start), (self.obj_id, end))),
            )?
            .into_iter()
            .map(|((_, block), key)| (block, key))
            .collect())
    }

    fn delete(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        key_id: Self::KeyId,
    ) -> Result<(), Self::Error> {
        self.inner.delete(wal, (self.obj_id, key_id))
    }

    fn update(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        Ok(self
            .inner
            .update(wal)?
            .into_iter()
            .map(|((_, key_id), key)| (key_id, key))
            .collect())
    }
}

impl<'a, KMS, G, C, const N: usize> AffineKeyManagementScheme<G, C, N>
    for Localizer<'a, KMS, G, C, N>
where
    KMS: AffineKeyManagementScheme<G, C, N, KeyId = (u64, u64)>,
{
    fn derive_read_key(&mut self, key_id: Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
        self.inner.derive_read_key((self.obj_id, key_id))
    }

    fn derive_read_key_many(
        &mut self,
        start_key_id: Self::KeyId,
        end_key_id: Self::KeyId,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        Ok(self
            .inner
            .derive_read_key_many((self.obj_id, start_key_id), (self.obj_id, end_key_id))?
            .into_iter()
            .map(|((_, block), key)| (block, key))
            .collect())
    }

    fn derive_write_key(&mut self, key_id: Self::KeyId) -> Result<Key<N>, Self::Error> {
        self.inner.derive_write_key((self.obj_id, key_id))
    }

    fn derive_write_key_many(
        &mut self,
        start_key_id: Self::KeyId,
        end_key_id: Self::KeyId,
        spec_bounds: Option<(Self::KeyId, Self::KeyId)>,
    ) -> Result<Vec<(Self::KeyId, Key<N>)>, Self::Error> {
        Ok(self
            .inner
            .derive_write_key_many(
                (self.obj_id, start_key_id),
                (self.obj_id, end_key_id),
                spec_bounds.map(|(start, end)| ((self.obj_id, start), (self.obj_id, end))),
            )?
            .into_iter()
            .map(|((_, block), key)| (block, key))
            .collect())
    }

    fn delete(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        key_id: Self::KeyId,
    ) -> Result<(), Self::Error> {
        self.inner.delete(wal, (self.obj_id, key_id))
    }

    fn update(&mut self, wal: &[Self::LogEntry]) -> Result<(), Self::Error> {
        Ok(self.inner.update(wal)?)
    }
}

impl<'a, KMS, G, C, const N: usize> SpeculativeKeyManagementScheme<G, C, N>
    for Localizer<'a, KMS, G, C, N>
where
    KMS: SpeculativeKeyManagementScheme<G, C, N, KeyId = (u64, u64)>,
{
    fn speculate_range(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        start_key_id: Self::KeyId,
        end_key_id: Self::KeyId,
    ) -> Result<(), Self::Error> {
        self.inner
            .speculate_range(wal, (self.obj_id, start_key_id), (self.obj_id, end_key_id))
    }
}

impl<'a, KMS, G, C, const N: usize> UnstableKeyManagementScheme<G, C, N>
    for Localizer<'a, KMS, G, C, N>
where
    KMS: UnstableKeyManagementScheme<G, C, N, KeyId = (u64, u64)>,
{
    fn derive(&mut self, key_id: Self::KeyId) -> Result<Option<Key<N>>, Self::Error> {
        self.inner.derive((self.obj_id, key_id))
    }

    fn derive_mut(&mut self, key_id: Self::KeyId) -> Result<Key<N>, Self::Error> {
        self.inner.derive_mut((self.obj_id, key_id))
    }

    fn sync(&mut self, _entry: &Self::LogEntry) -> Result<(), Self::Error> {
        panic!("shouldn't call sync on Localizer")
    }

    fn delete(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
        key_id: Self::KeyId,
    ) -> Result<(), Self::Error> {
        self.inner.delete(wal, (self.obj_id, key_id))
    }

    fn update(
        &mut self,
        wal: &SecureWAL<Self::LogEntry, G, C, N>,
    ) -> Result<Vec<(Self::KeyId, (Key<N>, Vec<u8>))>, Self::Error> {
        Ok(self
            .inner
            .update(wal)?
            .into_iter()
            .map(|((_, key_id), (key, data))| (key_id, (key, data)))
            .collect())
    }
}
