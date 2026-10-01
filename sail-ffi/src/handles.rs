//! Handles: what the host holds of sail's objects. A handle is a slot and
//! the generation the slot was at, so a handle freed, and its slot taken
//! again, names nothing rather than the new object.

use std::sync::Arc;

/// Objects by handle. A table's handles carry its tag in their top bit, so
/// two tables never give the same handle.
pub(crate) struct Table<T> {
    slots: Vec<Slot<T>>,
    free: Vec<usize>,
    tag: u64,
}

/// The tag of the handles of command service clients.
#[cfg_attr(not(feature = "command-server"), allow(dead_code))]
pub(crate) const CLIENT_TAG: u64 = 1 << 63;

struct Slot<T> {
    generation: u32,
    value: Option<Arc<T>>,
}

impl<T> Table<T> {
    pub const fn new() -> Self {
        Self::tagged(0)
    }

    pub const fn tagged(tag: u64) -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            tag,
        }
    }

    pub fn insert(&mut self, value: Arc<T>) -> u64 {
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                self.slots.push(Slot {
                    generation: 1,
                    value: None,
                });
                self.slots.len() - 1
            }
        };
        let slot = &mut self.slots[index];
        slot.value = Some(value);
        handle(index, slot.generation) | self.tag
    }

    pub fn get(&self, handle: u64) -> Option<Arc<T>> {
        let (index, generation) = self.split(handle)?;
        let slot = self.slots.get(index)?;
        (slot.generation == generation)
            .then(|| slot.value.clone())
            .flatten()
    }

    pub fn remove(&mut self, handle: u64) -> Option<Arc<T>> {
        let (index, generation) = self.split(handle)?;
        let slot = self.slots.get_mut(index)?;
        if slot.generation != generation {
            return None;
        }
        let value = slot.value.take()?;
        // Never 0, and 31 bits: the top bit is the table's tag.
        slot.generation = (slot.generation.wrapping_add(1) & GENERATIONS).max(1);
        self.free.push(index);
        Some(value)
    }

    #[cfg(test)]
    pub fn values(&self) -> impl Iterator<Item = &Arc<T>> {
        self.slots.iter().filter_map(|s| s.value.as_ref())
    }
}

const GENERATIONS: u32 = 0x7fff_ffff;

fn handle(index: usize, generation: u32) -> u64 {
    (u64::from(generation) << 32) | (index as u64 + 1)
}

impl<T> Table<T> {
    fn split(&self, handle: u64) -> Option<(usize, u32)> {
        if handle & (1 << 63) != self.tag {
            return None;
        }
        let index = (handle & 0xffff_ffff) as usize;
        let generation = ((handle >> 32) as u32) & GENERATIONS;
        (index != 0 && generation != 0).then(|| (index - 1, generation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_freed_handle_names_nothing_though_its_slot_is_taken_again() {
        let mut table = Table::new();
        let a = table.insert(Arc::new("a"));
        assert_ne!(a, 0);
        assert_eq!(table.get(a).as_deref(), Some(&"a"));
        assert_eq!(table.remove(a).as_deref(), Some(&"a"));
        assert!(table.get(a).is_none());
        assert!(table.remove(a).is_none());
        let b = table.insert(Arc::new("b"));
        assert_ne!(a, b, "the slot is taken again, at a new generation");
        assert!(table.get(a).is_none());
        assert_eq!(table.get(b).as_deref(), Some(&"b"));
        for bad in [0, 1, u64::MAX, b + 1] {
            assert!(table.get(bad).is_none(), "{:#x}", bad);
        }
        assert_eq!(table.values().count(), 1);
        // Another table's handles are none of this one's.
        let mut clients = Table::tagged(CLIENT_TAG);
        let c = clients.insert(Arc::new("c"));
        assert_ne!(c, b);
        assert!(table.get(c).is_none());
        assert!(clients.get(b).is_none());
        assert_eq!(clients.get(c).as_deref(), Some(&"c"));
    }
}
