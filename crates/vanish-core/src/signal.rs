//! Один флаг SIGINT/SIGTERM: конвейер доводит текущий файл до конца
//! (все экстенты и проходы → fsync → verify → truncate → sync → unlink)
//! и не начинает следующие файлы, каталоги или recovery-цели.

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: i32) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

pub fn install() {
    unsafe {
        // На linux sighandler_t = usize; приводим fn-указатель напрямую.
        let handler = on_signal as extern "C" fn(i32) as usize;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

pub fn reset_for_tests() {
    SHUTDOWN.store(false, Ordering::SeqCst);
}
