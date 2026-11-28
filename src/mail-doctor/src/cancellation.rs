//! Cooperative cancellation shared by the stages within each worker thread
//! (port of `services/cancellation.py`). The context is thread-local, exactly
//! like Python's `threading.local`, so it must be installed on the thread that
//! runs the pipeline.

use std::cell::RefCell;
use std::sync::Arc;

pub const DEFAULT_MAX_MESSAGES: usize = 50_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Audit was cancelled")]
pub struct AuditCancelled;

pub type ShouldCancel = Arc<dyn Fn() -> bool + Send + Sync>;

struct Context {
    should_cancel: Option<ShouldCancel>,
    max_messages: usize,
}

thread_local! {
    static CONTEXT: RefCell<Context> = RefCell::new(Context { should_cancel: None, max_messages: DEFAULT_MAX_MESSAGES });
}

/// `Err(AuditCancelled)` when the current thread's job was cancelled.
pub fn check_cancel() -> Result<(), AuditCancelled> {
    let cancelled = CONTEXT.with(|c| c.borrow().should_cancel.as_ref().is_some_and(|f| f()));
    if cancelled {
        Err(AuditCancelled)
    } else {
        Ok(())
    }
}

/// Maximum number of messages a stage may process on this thread.
pub fn message_limit() -> usize {
    CONTEXT.with(|c| c.borrow().max_messages)
}

/// Run `body` with a cancellation context installed; checks for cancellation
/// before and after, and restores the previous context afterwards (even on panic).
pub fn cancellation_context<T, E: From<AuditCancelled>>(
    should_cancel: ShouldCancel,
    max_messages: usize,
    body: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    struct Restore(Option<ShouldCancel>, usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            let (cancel, limit) = (self.0.take(), self.1);
            CONTEXT.with(|c| {
                let mut c = c.borrow_mut();
                c.should_cancel = cancel;
                c.max_messages = limit;
            });
        }
    }
    let previous = CONTEXT.with(|c| {
        let mut c = c.borrow_mut();
        let previous = Restore(c.should_cancel.replace(should_cancel), c.max_messages);
        c.max_messages = max_messages;
        previous
    });
    let _restore = previous;
    check_cancel()?;
    let value = body()?;
    check_cancel()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn context_is_scoped_and_restored() {
        assert_eq!(message_limit(), DEFAULT_MAX_MESSAGES);
        assert!(check_cancel().is_ok());
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        let result: Result<usize, AuditCancelled> =
            cancellation_context(Arc::new(move || f.load(Ordering::SeqCst)), 7, || {
                assert_eq!(message_limit(), 7);
                flag.store(true, Ordering::SeqCst);
                assert_eq!(check_cancel(), Err(AuditCancelled));
                Ok(1)
            });
        assert_eq!(result, Err(AuditCancelled));
        assert_eq!(message_limit(), DEFAULT_MAX_MESSAGES);
        assert!(check_cancel().is_ok());
    }
}
