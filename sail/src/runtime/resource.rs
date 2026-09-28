//! Immutable runtime resources. Readers retain their generation across
//! awaits; writers validate a replacement before publishing it.

use arc_swap::ArcSwap;
use std::sync::Arc;

pub(crate) struct HotResource<T> {
    current: Arc<ArcSwap<T>>,
}

impl<T> Clone for HotResource<T> {
    fn clone(&self) -> Self {
        Self {
            current: self.current.clone(),
        }
    }
}

impl<T> HotResource<T> {
    pub(crate) fn new(value: T) -> Self {
        Self::from_arc(Arc::new(value))
    }

    pub(crate) fn from_arc(value: Arc<T>) -> Self {
        Self {
            current: Arc::new(ArcSwap::from(value)),
        }
    }

    pub(crate) fn load(&self) -> Arc<T> {
        self.current.load_full()
    }

    pub(crate) fn publish(&self, value: Arc<T>) {
        self.current.store(value);
    }
}

/// An already validated publication. Dropping it rolls back preparation.
pub(crate) type ResourceUpdate = Box<dyn FnOnce() + Send>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_generation_survives_publication() {
        let resource = HotResource::new(vec![1]);
        let old = resource.load();
        resource.clone().publish(Arc::new(vec![2]));
        assert_eq!(*old, vec![1]);
        assert_eq!(*resource.load(), vec![2]);
    }
}
