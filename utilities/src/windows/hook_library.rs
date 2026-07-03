use std::fmt;

use super::{
    detour_binder::{DetourBinder, RuntimeDetourBinder},
    patcher::Patcher,
};

use crate::error::{Error, UserCallbackResult};

/// Error type for HookLibrary operations
#[derive(Debug)]
pub enum HookLibraryError {
    /// Standard library error
    Standard(Error),
    /// User callback error
    UserCallback(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for HookLibraryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookLibraryError::Standard(e) => write!(f, "{}", e),
            HookLibraryError::UserCallback(e) => write!(f, "user callback error: {}", e),
        }
    }
}

impl std::error::Error for HookLibraryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HookLibraryError::Standard(e) => e.source(),
            HookLibraryError::UserCallback(e) => e.source(),
        }
    }
}

#[allow(clippy::type_complexity)]
pub struct HookLibrary {
    static_binders: Vec<&'static dyn DetourBinder>,
    runtime_binders: Vec<Box<dyn DetourBinder>>,
    patches: Vec<(usize, Vec<u8>)>,
    /// Child libraries that are enabled after (and disabled before) this library's own
    /// binders and patches, enabling arbitrary composition of hook libraries.
    children: Vec<HookLibrary>,
}
impl HookLibrary {
    // builder functions
    pub fn new() -> HookLibrary {
        HookLibrary {
            static_binders: vec![],
            runtime_binders: vec![],
            patches: vec![],
            children: vec![],
        }
    }
    /// Adds a child `HookLibrary` whose binders and patches are enabled after this
    /// library's own, and disabled before them (the exact reverse of enable order).
    pub fn with_hook_library(mut self, child: HookLibrary) -> Self {
        self.children.push(child);
        self
    }
    pub fn with_static_binder(mut self, binder: &'static dyn DetourBinder) -> Self {
        self.static_binders.push(binder);
        self
    }
    pub fn with_runtime_binder(mut self, binder: Box<dyn DetourBinder>) -> Self {
        self.runtime_binders.push(binder);
        self
    }
    pub fn with_detour<F: retour::Function>(
        self,
        detour: &'static retour::GenericDetour<F>,
    ) -> Self {
        self.with_runtime_binder(Box::new(RuntimeDetourBinder {
            enable: Box::new(|| unsafe { detour.enable().map_err(|e| Box::new(e) as _) }),
            disable: Box::new(|| unsafe { detour.disable().map_err(|e| Box::new(e) as _) }),
        }))
    }
    pub fn with_callbacks(
        self,
        enable: impl Fn() -> UserCallbackResult<()> + Send + Sync + 'static,
        disable: impl Fn() -> UserCallbackResult<()> + Send + Sync + 'static,
    ) -> Self {
        self.with_runtime_binder(Box::new(RuntimeDetourBinder {
            enable: Box::new(enable),
            disable: Box::new(disable),
        }))
    }
    pub fn with_patch(mut self, address: usize, bytes: &[u8]) -> Self {
        self.patches.push((address, bytes.to_owned()));
        self
    }

    pub fn set_enabled(
        &self,
        patcher: &mut Patcher,
        enabled: bool,
    ) -> Result<(), HookLibraryError> {
        // Enable sequence:  [self.binders → self.patches → children]
        // Disable sequence: [children → self.patches → self.binders]  (exact reverse)
        if enabled {
            // Enable self's binders first.
            for binder in self.binders() {
                binder.enable().map_err(HookLibraryError::UserCallback)?;
            }
            // Then apply self's patches.
            for (address, patch) in &self.patches {
                unsafe {
                    patcher.patch(*address, patch);
                }
            }
            // Finally, enable each child (recursively applies the same sequence).
            for child in &self.children {
                child.set_enabled(patcher, true)?;
            }
        } else {
            // Disable children first (reverse of enable order).
            for child in &self.children {
                child.set_enabled(patcher, false)?;
            }
            // Then unpatch self's patches.
            for (address, _) in &self.patches {
                unsafe {
                    patcher.unpatch(*address).ok_or_else(|| {
                        HookLibraryError::Standard(Error::UnpatchFailed { address: *address })
                    })?;
                }
            }
            // Finally, disable self's binders.
            for binder in self.binders() {
                binder.disable().map_err(HookLibraryError::UserCallback)?;
            }
        }
        Ok(())
    }

    /// Convenience method that enables the library and returns it for chaining.
    pub fn enable(self, patcher: &mut Patcher) -> Result<Self, HookLibraryError> {
        self.set_enabled(patcher, true)?;
        Ok(self)
    }
}
impl HookLibrary {
    fn binders(&self) -> impl Iterator<Item = &dyn DetourBinder> {
        self.static_binders
            .iter()
            .map(|b| *b as &dyn DetourBinder)
            .chain(self.runtime_binders.iter().map(|b| b.as_ref()))
    }
}
impl Default for HookLibrary {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for HookLibrary {
    fn drop(&mut self) {
        // Disable self's binders. Children are dropped automatically after this
        // body runs (the `children` Vec drops field-by-field), so each child's
        // `Drop` fires and disables their own binders. This is best-effort
        // cleanup — parent binders are disabled before child binders on drop,
        // which does not mirror the explicit disable order (children-first).
        for binder in self.binders() {
            let _ = binder.disable();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};

    /// A mock `DetourBinder` that increments a counter on `enable` and decrements on `disable`.
    /// Using `i32` (not `u8`) avoids underflow wrapping to 255 when `Drop` calls `disable()`
    /// after test assertions have already returned the counter to 0.
    struct MockBinder {
        counter: Arc<AtomicI32>,
    }

    impl DetourBinder for MockBinder {
        fn enable(&self) -> UserCallbackResult<()> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn disable(&self) -> UserCallbackResult<()> {
            self.counter.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A mock `DetourBinder` that appends a label to a shared log on each call,
    /// used to verify enable/disable call ordering.
    struct LoggingBinder {
        log: Arc<Mutex<Vec<&'static str>>>,
        label: &'static str,
    }

    impl DetourBinder for LoggingBinder {
        fn enable(&self) -> UserCallbackResult<()> {
            self.log.lock().unwrap().push(self.label);
            Ok(())
        }
        fn disable(&self) -> UserCallbackResult<()> {
            self.log.lock().unwrap().push(self.label);
            Ok(())
        }
    }

    /// Creates a `MockBinder` and returns the shared counter alongside it.
    fn make_binder() -> (Arc<AtomicI32>, MockBinder) {
        let counter = Arc::new(AtomicI32::new(0));
        let binder = MockBinder {
            counter: counter.clone(),
        };
        (counter, binder)
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_child_binder_enabled() {
        let mut patcher = Patcher::new();
        let (parent_counter, parent_binder) = make_binder();
        let (child_counter, child_binder) = make_binder();

        let child = HookLibrary::new().with_runtime_binder(Box::new(child_binder));
        let parent = HookLibrary::new()
            .with_runtime_binder(Box::new(parent_binder))
            .with_hook_library(child);

        parent.set_enabled(&mut patcher, true).unwrap();
        assert_eq!(parent_counter.load(Ordering::SeqCst), 1);
        assert_eq!(child_counter.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_child_binder_disabled() {
        let mut patcher = Patcher::new();
        let (parent_counter, parent_binder) = make_binder();
        let (child_counter, child_binder) = make_binder();

        let child = HookLibrary::new().with_runtime_binder(Box::new(child_binder));
        let parent = HookLibrary::new()
            .with_runtime_binder(Box::new(parent_binder))
            .with_hook_library(child);

        parent.set_enabled(&mut patcher, true).unwrap();
        parent.set_enabled(&mut patcher, false).unwrap();
        assert_eq!(parent_counter.load(Ordering::SeqCst), 0);
        assert_eq!(child_counter.load(Ordering::SeqCst), 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_nested_children() {
        let mut patcher = Patcher::new();
        let (parent_counter, parent_binder) = make_binder();
        let (child_counter, child_binder) = make_binder();
        let (grandchild_counter, grandchild_binder) = make_binder();

        let grandchild =
            HookLibrary::new().with_runtime_binder(Box::new(grandchild_binder));
        let child = HookLibrary::new()
            .with_runtime_binder(Box::new(child_binder))
            .with_hook_library(grandchild);
        let parent = HookLibrary::new()
            .with_runtime_binder(Box::new(parent_binder))
            .with_hook_library(child);

        parent.set_enabled(&mut patcher, true).unwrap();
        assert_eq!(parent_counter.load(Ordering::SeqCst), 1);
        assert_eq!(child_counter.load(Ordering::SeqCst), 1);
        assert_eq!(grandchild_counter.load(Ordering::SeqCst), 1);

        parent.set_enabled(&mut patcher, false).unwrap();
        assert_eq!(parent_counter.load(Ordering::SeqCst), 0);
        assert_eq!(child_counter.load(Ordering::SeqCst), 0);
        assert_eq!(grandchild_counter.load(Ordering::SeqCst), 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_enable_returns_self() {
        let mut patcher = Patcher::new();
        let (_counter, binder) = make_binder();

        let child = HookLibrary::new().with_runtime_binder(Box::new(binder));
        let result = HookLibrary::new()
            .with_hook_library(child)
            .enable(&mut patcher);
        assert!(result.is_ok());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_disable_order() {
        let mut patcher = Patcher::new();
        let log = Arc::new(Mutex::new(Vec::new()));

        let parent_binder = LoggingBinder {
            log: log.clone(),
            label: "parent",
        };
        let child_binder = LoggingBinder {
            log: log.clone(),
            label: "child",
        };

        let child = HookLibrary::new().with_runtime_binder(Box::new(child_binder));
        let parent = HookLibrary::new()
            .with_runtime_binder(Box::new(parent_binder))
            .with_hook_library(child);

        parent.set_enabled(&mut patcher, true).unwrap();
        assert_eq!(*log.lock().unwrap(), vec!["parent", "child"]);

        parent.set_enabled(&mut patcher, false).unwrap();
        // Full log: ["parent", "child", "child", "parent"]
        // Last two entries (disable order): ["child", "parent"]
        let log_guard = log.lock().unwrap();
        let len = log_guard.len();
        assert_eq!(&log_guard[len - 2..], &["child", "parent"]);
    }
}
