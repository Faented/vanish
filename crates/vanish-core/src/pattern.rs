//! Генератор паттернов записи. Ключевое свойство: **детерминированный replay**
//! — содержимое чанка №i зависит только (seed_base, kind, pass, i), поэтому
//! verify может перевостановить чанки в том же порядке и сверить побайтно.

use rand::RngCore;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::config::PatternChoice;
use crate::error::Result;

/// Строки Гутманна: len-1 одинарные байты, len-3 — тройки. rand(строки 0,3,34)
/// заполняются из ChaCha20 того же pass-seed.
pub const GUTMANN_ROWS: &[&[u8]] = &[
    b"",                 // 0  random
    &[0x55],             // 1
    &[0xAA],             // 2
    b"",                 // 3  random
    &[0x92, 0x49, 0x24], // 4
    &[0x49, 0x24, 0x92], // 5
    &[0x24, 0x92, 0x49], // 6
    &[0x00],             // 7
    &[0x11],             // 8
    &[0x22],             // 9
    &[0x33],             // 10
    &[0x44],             // 11
    &[0x55],             // 12
    &[0x66],             // 13
    &[0x77],             // 14
    &[0x88],             // 15
    &[0x99],             // 16
    &[0xAA],             // 17
    &[0xBB],             // 18
    &[0xCC],             // 19
    &[0xDD],             // 20
    &[0xEE],             // 21
    &[0xFF],             // 22
    &[0x92, 0x49, 0x24], // 23
    &[0x49, 0x24, 0x92], // 24
    &[0x24, 0x92, 0x49], // 25
    &[0x6D, 0xB6, 0xDB], // 26
    &[0xB6, 0xDB, 0x6D], // 27
    &[0xDB, 0x6D, 0xB6], // 28
    &[0x00],             // 29
    &[0x11],             // 30
    &[0x22],             // 31
    &[0x33],             // 32
    &[0xFF],             // 33
    b"",                 // 34 random
];

pub const GUTMANN_RANDOM_ROWS: [usize; 3] = [0, 3, 34];

/// Таблица "гутманн: строка p" как заполнение.
fn gutmann_row_fill(row: usize, chunk_idx: u64, seed_base: &[u8; 32], pass: u8, buf: &mut [u8]) {
    if GUTMANN_RANDOM_ROWS.contains(&row) {
        random_fill(seed_base, pass, chunk_idx, buf);
        return;
    }
    let row = &GUTMANN_ROWS[row % GUTMANN_ROWS.len()];
    if row.is_empty() {
        buf.fill(0);
        return;
    }
    for (i, b) in buf.iter_mut().enumerate() {
        *b = row[i % row.len()];
    }
}

/// Детерминированный ChaCha20-keystream: (seed_base, pass, chunk_idx) → поток.
fn random_fill(seed_base: &[u8; 32], pass: u8, chunk_idx: u64, buf: &mut [u8]) {
    let mut h = Sha256::new();
    h.update(b"vanish.v1.random");
    h.update(seed_base);
    h.update([pass, 0, 0, 0]);
    h.update(chunk_idx.to_le_bytes());
    let seed = h.finalize();
    let seed: [u8; 32] = seed.into();
    let mut rng = ChaCha20Rng::from_seed(seed);
    rng.fill_bytes(buf);
}

/// Детерминированное наполнение чанкового буфера.
pub fn fill_chunk(
    kind: &PatternChoice,
    seed_base: &[u8; 32],
    pass: u8,
    chunk_idx: u64,
    buf: &mut [u8],
) {
    match kind {
        PatternChoice::Zero => buf.fill(0),
        PatternChoice::Hex(b) => buf.fill(*b),
        PatternChoice::Random => random_fill(seed_base, pass, chunk_idx, buf),
        PatternChoice::Gutmann => {
            let row = pass as usize % GUTMANN_ROWS.len();
            gutmann_row_fill(row, chunk_idx, seed_base, pass, buf);
        }
    }
}

/// Стрим чанков (со счётчиком). Наполняет только буферы выравненного движка.
pub struct PatternStream {
    kind: PatternChoice,
    seed_base: [u8; 32],
    pass: u8,
    idx: u64,
}

impl PatternStream {
    pub fn new(kind: PatternChoice, pass: u8, seed_base: [u8; 32]) -> Self {
        PatternStream {
            kind,
            seed_base,
            pass,
            idx: 0,
        }
    }

    /// Свежий replay: тот же последователь, сч/ёкид от 0 (для verify).
    pub fn replay(&self) -> Self {
        PatternStream::new(self.kind, self.pass, self.seed_base)
    }

    #[inline]
    pub fn fill(&mut self, buf: &mut [u8]) {
        let idx = self.idx;
        self.idx += 1;
        fill_chunk(&self.kind, &self.seed_base, self.pass, idx, buf);
    }

    /// Вернуть произвольный чанк по индексу без прыжка счётчика (для verify).
    pub fn fill_at(&self, chunk_idx: u64, buf: &mut [u8]) {
        fill_chunk(&self.kind, &self.seed_base, self.pass, chunk_idx, buf);
    }
}

/// Проверка чанка: сверить payload с ожидаемым от паттерна.
pub fn expect_chunk(
    kind: &PatternChoice,
    seed_base: &[u8; 32],
    pass: u8,
    chunk_idx: u64,
    data: &[u8],
) -> Result<()> {
    use crate::error::VanishError;
    let mut expected = vec![0u8; data.len()];
    fill_chunk(kind, seed_base, pass, chunk_idx, &mut expected);
    for (i, (got, want)) in data.iter().zip(expected.iter()).enumerate() {
        if got != want {
            let offset = chunk_idx * crate::aligned::CHUNK as u64 + i as u64;
            return Err(VanishError::VerifyMismatch { offset });
        }
    }
    expected.zeroize();
    Ok(())
}
