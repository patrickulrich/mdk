//! Platform-agnostic synchronization primitives

// Native: parking_lot for performance
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use parking_lot::RwLock;

// WASM: std::sync with parking_lot-like API
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod wasm {
    use std::fmt;
    use std::sync::{
        RwLock as StdRwLock, RwLockReadGuard as StdReadGuard,
        RwLockWriteGuard as StdWriteGuard,
    };

    pub struct RwLock<T>(StdRwLock<T>);

    impl<T: fmt::Debug> fmt::Debug for RwLock<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0.try_read() {
                Ok(guard) => f.debug_tuple("RwLock").field(&*guard).finish(),
                Err(_) => f.debug_tuple("RwLock").field(&"<locked>").finish(),
            }
        }
    }

    impl<T> RwLock<T> {
        pub fn new(value: T) -> Self {
            RwLock(StdRwLock::new(value))
        }

        pub fn read(&self) -> RwLockReadGuard<'_, T> {
            RwLockReadGuard(self.0.read().expect("RwLock poisoned"))
        }

        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            RwLockWriteGuard(self.0.write().expect("RwLock poisoned"))
        }
    }

    pub struct RwLockReadGuard<'a, T>(StdReadGuard<'a, T>);

    impl<'a, T> std::ops::Deref for RwLockReadGuard<'a, T> {
        type Target = T;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    pub struct RwLockWriteGuard<'a, T>(StdWriteGuard<'a, T>);

    impl<'a, T> std::ops::Deref for RwLockWriteGuard<'a, T> {
        type Target = T;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<'a, T> std::ops::DerefMut for RwLockWriteGuard<'a, T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use wasm::RwLock;
