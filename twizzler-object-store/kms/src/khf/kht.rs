use std::fmt;

use lru_mem::LruCache;
use serde::{Deserialize, Serialize};

use super::{node::Node, topology::Topology, KhfKeyId, Pos};
use crate::{consts::KEY_CACHE_LIMIT, hasher::Hasher, kdf::KeyDerivationFunction, key::Key};

#[derive(Deserialize, Serialize, Clone)]
pub struct Kht<H, const N: usize> {
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    root: Node<H, N>,
    topology: Topology,
    #[serde(skip)]
    #[serde(default = "key_cache_default")]
    cache: LruCache<Pos, Key<N>>,
}

fn key_cache_default<const N: usize>() -> LruCache<Pos, Key<N>> {
    LruCache::new(KEY_CACHE_LIMIT)
}

impl<H, const N: usize> Kht<H, N> {
    pub fn new(key: Key<N>) -> Self {
        Self {
            root: Node::new(key),
            topology: Topology::default(),
            cache: key_cache_default(),
        }
    }

    pub fn derive(&self, leaf: KhfKeyId) -> Key<N>
    where
        H: Hasher<N>,
    {
        self.root
            .derive(&self.topology, self.topology.leaf_position(leaf))
    }

    pub fn derive_and_cache(&mut self, leaf: KhfKeyId) -> Key<N>
    where
        H: Hasher<N>,
    {
        self.root.derive_and_cache(
            &self.topology,
            self.topology.leaf_position(leaf),
            &mut self.cache,
        )
    }
}

impl<H, const N: usize> KeyDerivationFunction<N> for Kht<H, N>
where
    H: Hasher<N>,
{
    type KeyId = KhfKeyId;

    fn with_key(key: Key<N>) -> Self {
        Self::new(key)
    }

    fn derive(&mut self, leaf: Self::KeyId) -> Key<N> {
        self.derive_and_cache(leaf)
    }
}

impl<H, const N: usize> fmt::Display for Kht<H, N>
where
    H: Hasher<N>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.root.fmt(f, &self.topology)
    }
}
