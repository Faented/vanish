//! Отчёт v1: события + гарантии; НИКОГДА не содержит исходных имён plaintext.

use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA: &str = "vanish.report.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Info,
    Warn,
    Error,
}

/// Diagnostic observations, not proof of physical sanitization or key erasure.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Guarantees {
    pub ssd_chipoff_protected: bool,
    pub journal_contains_old_names: bool,
    pub swap_pages_possible: bool,
    pub encrypted_at_rest: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetEvent {
    pub kind: String, // file | dir | tail | stream
    pub name_hash: String,
    pub tail: Option<String>,
    pub strategy: Option<String>,
    pub status: String, // ok | rejected | failed | skipped
    pub reason: Option<String>,
    pub bytes: u64,
    pub warnings: Vec<String>,
    pub guarantees: Option<Guarantees>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub schema: &'static str,
    pub started_ms: u64,
    pub finished_ms: u64,
    pub code: u8,
    pub ok: usize,
    pub skipped: usize,
    pub rejected: usize,
    pub failed: usize,
    pub bytes: u64,
    pub targets: Vec<TargetEvent>,
    pub notes: Vec<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl RunReport {
    pub fn new() -> Self {
        RunReport {
            schema: SCHEMA,
            started_ms: now_ms(),
            finished_ms: 0,
            code: 0,
            ok: 0,
            skipped: 0,
            rejected: 0,
            failed: 0,
            bytes: 0,
            targets: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn push(&mut self, ev: TargetEvent) -> &TargetEvent {
        match ev.status.as_str() {
            "ok" => self.ok += 1,
            "skipped" => self.skipped += 1,
            "rejected" => self.rejected += 1,
            _ => self.failed += 1,
        }
        if ev.status == "ok" {
            self.bytes += ev.bytes;
        }
        self.targets.push(ev);
        self.targets.last().unwrap()
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    pub fn finish(mut self, code: u8) -> Self {
        self.finished_ms = now_ms();
        self.code = code;
        self
    }

    /// Человеческая сводка (stderr).
    pub fn summary_text(&self) -> String {
        format!(
            "targets: ok={}, skipped={}, rejected={}, failed={}; bytes wiped: {} MB; exit={}",
            self.ok,
            self.skipped,
            self.rejected,
            self.failed,
            self.bytes / (1024 * 1024),
            self.code
        )
    }
}

impl Default for RunReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Генератор событий с хронометражем.
pub struct Timer {
    start: std::time::Instant,
}

impl Timer {
    pub fn start() -> Self {
        Timer {
            start: std::time::Instant::now(),
        }
    }
    pub fn ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}
