//! unit tests for attackstr.
//! See TESTING.md for the Santh testing standard.
pub use attackstr::*;
pub use std::collections::HashMap;

// Shared tracing-capture helper (ONE owner) used by encoding.rs and loader.rs to
// assert that Law-10 loud-degrade warnings are actually emitted.
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
pub(crate) struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

pub(crate) struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for SharedBuffer {
    type Writer = BufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BufferWriter(Arc::clone(&self.0))
    }
}

impl Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Run `f` with a temporary tracing subscriber and return everything it logged.
pub(crate) fn capture_logs<F>(f: F) -> String
where
    F: FnOnce(),
{
    let buffer = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(buffer.clone())
        .finish();

    tracing::subscriber::with_default(subscriber, f);

    let captured = buffer.0.lock().unwrap().clone();
    String::from_utf8(captured).unwrap()
}

#[path = "config.rs"]
mod config_tests;
mod encoding;
#[path = "grammar.rs"]
mod grammar_tests;
mod lib_tests;
mod loader;
mod mutate;
mod test_depth_unit;
#[path = "validate.rs"]
mod validate_tests;
