use std::fmt;

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

use crate::key::Key;

#[serde_as]
#[derive(Deserialize, Serialize, Clone)]
pub enum LogEntry<const N: usize> {
    UpdateRange {
        khf_id: u64,
        start_key_id: u64,
        end_key_id: u64,
    },
    Update {
        khf_id: u64,
        key_id: u64,
    },
    Delete {
        khf_id: u64,
        key_id: u64,
    },
    Alloc {
        inode: u64,
        khf_id: u64,
        #[serde_as(as = "Bytes")]
        root_key: Key<N>,
        #[serde_as(as = "Bytes")]
        spanning_root_key: Key<N>,
    },
    Dealloc {
        inode: u64,
        khf_id: u64,
    },
}

impl<const N: usize> fmt::Debug for LogEntry<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpdateRange {
                khf_id,
                start_key_id,
                end_key_id,
            } => f
                .debug_struct("UpdateRange")
                .field("khf_id", khf_id)
                .field("start_key_id", start_key_id)
                .field("end_key_id", end_key_id)
                .finish(),
            Self::Update { khf_id, key_id } => f
                .debug_struct("Update")
                .field("khf_id", khf_id)
                .field("key_id", key_id)
                .finish(),
            Self::Delete { khf_id, key_id } => f
                .debug_struct("Delete")
                .field("khf_id", khf_id)
                .field("key_id", key_id)
                .finish(),
            Self::Alloc {
                inode,
                khf_id,
                root_key,
                spanning_root_key,
            } => f
                .debug_struct("Alloc")
                .field("inode", inode)
                .field("khf_id", khf_id)
                .field("root_key", &hex::encode(root_key))
                .field("spanning_root_key", &hex::encode(spanning_root_key))
                .finish(),
            Self::Dealloc { inode, khf_id } => f
                .debug_struct("Alloc")
                .field("inode", inode)
                .field("khf_id", khf_id)
                .finish(),
        }
    }
}
