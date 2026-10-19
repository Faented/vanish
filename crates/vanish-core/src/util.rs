//! Мелкие утилиты: SHA-256 имён (без plaintext в хранимых артефактах),
//! chunk-итераторы, seed.

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Хэш канон-имени для отчёта (исходное имя НЕ сохраняется).
pub fn name_sha256(path: &Path) -> String {
    let mut h = Sha256::new();
    // to_string_lossy: детерминированно по строке на всех ОС (имя всё равно
    // стирается; хэш нужен только для сопоставления строк отчёта).
    h.update(path.to_string_lossy().as_bytes());
    hex::encode(h.finalize())
}

/// Новый случайный seed для ChaCha (32 байта).
pub fn random_seed32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Случайный hex-хвост для имён `.vanish-v1-<hex16>`.
pub fn random_tail() -> String {
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    format!("vanish-v1-{}", hex::encode(b))
}

/// Куски [start, start+len): (offset, chunk_len).
pub struct Chunks {
    pub offset: u64,
    pub len: u64,
}

pub fn iterate_chunks(offset: u64, len: u64, chunk: u64) -> impl Iterator<Item = Chunks> {
    let mut cur = offset;
    std::iter::from_fn(move || {
        if cur >= offset + len {
            return None;
        }
        let n = chunk.min(offset + len - cur);
        let c = Chunks { offset: cur, len: n };
        cur += n;
        Some(c)
    })
}
