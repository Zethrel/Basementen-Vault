//! In-memory [`LocalVault`] for tests and prototyping. Real clients back
//! this trait with SQLite; the semantics here are the reference behaviour.

use std::collections::{HashMap, VecDeque};

use crate::types::{LocalVault, PendingOp, RemoteItem, StoredItem};

#[derive(Default)]
pub struct MemoryVault {
    items: HashMap<String, StoredItem>,
    queue: VecDeque<PendingOp>,
    last_seq: i64,
}

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }
}

impl LocalVault for MemoryVault {
    fn last_seq(&self) -> i64 {
        self.last_seq
    }

    fn set_last_seq(&mut self, seq: i64) {
        self.last_seq = seq;
    }

    fn get(&self, item_id: &str) -> Option<StoredItem> {
        self.items.get(item_id).cloned()
    }

    fn list(&self) -> Vec<StoredItem> {
        let mut all: Vec<StoredItem> = self.items.values().cloned().collect();
        all.sort_by(|a, b| a.item_id.cmp(&b.item_id));
        all
    }

    fn apply_remote(&mut self, item: &RemoteItem) {
        self.items.insert(
            item.item_id.clone(),
            StoredItem {
                item_id: item.item_id.clone(),
                revision: item.revision,
                deleted: item.deleted,
                content: item.content.clone(),
            },
        );
    }

    fn clear_items(&mut self) {
        self.items.clear();
    }

    fn stage(&mut self, op: PendingOp) {
        match &op {
            PendingOp::Upsert(envelope) => {
                self.items.insert(
                    envelope.item_id.clone(),
                    StoredItem {
                        item_id: envelope.item_id.clone(),
                        revision: envelope.revision as i64,
                        deleted: false,
                        content: Some(envelope.clone()),
                    },
                );
            }
            PendingOp::Delete {
                item_id,
                base_revision,
            } => {
                self.items.insert(
                    item_id.clone(),
                    StoredItem {
                        item_id: item_id.clone(),
                        revision: base_revision + 1,
                        deleted: true,
                        content: None,
                    },
                );
            }
        }
        self.queue.push_back(op);
    }

    fn pending_ops(&self) -> Vec<PendingOp> {
        self.queue.iter().cloned().collect()
    }

    fn pop_front_op(&mut self) {
        self.queue.pop_front();
    }
}
