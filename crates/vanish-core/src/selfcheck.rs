//! Самоверификация бинаря: SHA-256(живой exe) против манифеста SHA256SUMS.
//! Формат манифеста — стандартный sha256sum: `<hex64>  <имя>` (пример вывода
//! `sha256sum`). Манифест ставится рядом с бинарем скриптом сборки
//! scripts/build-release.sh. Рассчитан на упакованный билд: хэш считается
//! по ФАЙЛУ на диске (все байты, включая упаковщик-заголовок).

use std::fs::File;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};

/// SHA-256 файла на диске (последовательно, STREAMING, без подгрузки целиком).
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex_encode(&h.finalize()))
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Где искать манифест: (1) явно указанный путь; (2) переменная окружения
/// VANISH_SHA256SUMS; (3) рядом с exe (one dir up: exe.parent()/SHA256SUMS).
pub fn resolve_manifest(exe: &Path, explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    if let Ok(env) = std::env::var("VANISH_SHA256SUMS") {
        if !env.is_empty() && Path::new(&env).exists() {
            return Some(PathBuf::from(env));
        }
    }
    let dir = exe.parent()?;
    let p = dir.join("SHA256SUMS");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

/// Сверка: Ok(true) — совпало, Ok(false) — TAMPERED (хэш в манифесте другой),
/// Err — нет записи о бине в манифесте / ошибки чтения.
/// Сравнение имени — по basename exe, регистр имени косвенно не важен.
pub fn check(exe: &Path, manifest: &Path) -> Result<bool, String> {
    let exe_name = exe
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| "не удалось извлечь имя бинаря".to_string())?;
    let actual = sha256_file(exe).map_err(|e| format!("чтение exe: {}", e))?;

    let f = File::open(manifest).map_err(|e| format!("чтение манифеста: {}", e))?;
    let reader = std::io::BufReader::new(f);
    let mut found = false;
    for line in reader.lines() {
        let line = line.map_err(|e| format!("чтение манифеста: {}", e))?;
        let s = line.trim_end_matches(['\r', '\n', ' ', '\t']);
        if s.len() < 65 {
            continue;
        }
        // стандарт sha256sum: ровно 64 hex-символа, затем пробел(ы) и оператор имени
        let (hash, name) = s.split_at(64);
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let name = name.trim_start();
        let name = name.strip_prefix('*').unwrap_or(name);
        if name != exe_name {
            continue;
        }
        found = true;
        if hash.eq_ignore_ascii_case(&actual) {
            return Ok(true);
        }
        break; // нашлась запись с тем же именем, но другим хэшем — tamper
    }
    if found {
        Ok(false)
    } else {
        Err(format!("в манифесте {} нет записи для бинаря '{}'", manifest.display(), exe_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vanish-selfcheck-{}-{}",
            std::process::id(),
            crate::util::random_tail().trim_start_matches('.')
        ));
        let _ = std::fs::create_dir_all(&d);
        d
    }

    #[test]
    fn selfcheck_ok_mismatch_absent() {
        let d = tmp_dir();
        // живой бинарь: случайный файл
        let exe = d.join("vanish");
        let data = b"fake-binary-content-123";
        std::fs::write(&exe, data).unwrap();
        let actual = sha256_file(&exe).unwrap();
        assert_eq!(actual.len(), 64);

        // здоровый манифест
        let man = d.join("SHA256SUMS");
        std::fs::write(&man, format!("{}  vanish\n", actual)).unwrap();
        assert_eq!(check(&exe, &man).unwrap(), true);

        // tamper (хэш не тот)
        let other = "0".repeat(64);
        std::fs::write(&man, format!("{}  vanish\n", other)).unwrap();
        assert_eq!(check(&exe, &man).unwrap(), false);

        // отсутствующее имя
        let man2 = d.join("SHA256SUMS_other");
        std::fs::write(&man2, format!("{}  other\n", actual)).unwrap();
        assert!(check(&exe, &man2).is_err());

        // resolve_manifest: рядом с exe находят
        let found = resolve_manifest(&exe, None).unwrap();
        assert_eq!(found, man);

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sha256_file_matches_known_vector() {
        // SHA256("abc") известный вектор
        let d = tmp_dir();
        let p = d.join("vec");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"abc").unwrap();
        drop(f);
        assert_eq!(
            sha256_file(&p).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
