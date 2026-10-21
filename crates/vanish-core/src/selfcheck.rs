//! Самоверификация бинаря: SHA-256(живой exe) против манифеста SHA256SUMS.
//! Формат манифеста — стандартный sha256sum: `<hex64>  <имя>` (пример вывода
//! `sha256sum`). Манифест ставится рядом с бинарем скриптом сборки
//! scripts/build-release.sh. Рассчитан на упакованный билд: хэш считается
//! по ФАЙЛУ на диске (все байты, включая упаковщик-заголовок).

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

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
        return p.is_file().then(|| p.to_path_buf());
    }
    if let Ok(env) = std::env::var("VANISH_SHA256SUMS") {
        if !env.is_empty() {
            return Path::new(&env).is_file().then(|| PathBuf::from(env));
        }
    }
    let dir = exe.parent()?;
    let p = dir.join("SHA256SUMS");
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

/// Сверка: Ok(true) — совпало, Ok(false) — TAMPERED (хэш в манифесте другой),
/// Err — нет записи о бине в манифесте / ошибки чтения.
/// Сравнение имени — по basename exe, с учётом регистра.
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
        let s = line.trim_end_matches('\r');
        // Check bytes before slicing UTF-8: malformed input must never panic.
        let hash_bytes = match s.as_bytes().get(..64) {
            Some(bytes) if bytes.iter().all(u8::is_ascii_hexdigit) => bytes,
            _ => continue,
        };
        let hash = std::str::from_utf8(hash_bytes).expect("ASCII hex is UTF-8");
        let rest = &s[64..];
        // sha256sum text and binary markers respectively; filenames are not trimmed.
        let name = match rest.strip_prefix("  ").or_else(|| rest.strip_prefix(" *")) {
            Some(name) => name,
            None => continue,
        };
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
        Err(format!(
            "в манифесте {} нет записи для бинаря '{}'",
            manifest.display(),
            exe_name
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_dir() -> PathBuf {
        let base = Path::new("/tmp/opencode");
        let base = if base.is_dir() {
            base.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        let d = base.join(format!(
            "vanish-selfcheck-{}-{}",
            std::process::id(),
            crate::util::random_tail().trim_start_matches('.')
        ));
        std::fs::create_dir(&d).unwrap();
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
        assert!(check(&exe, &man).unwrap());

        // tamper (хэш не тот)
        let other = "0".repeat(64);
        std::fs::write(&man, format!("{}  vanish\n", other)).unwrap();
        assert!(!check(&exe, &man).unwrap());

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

    #[test]
    fn malformed_manifest_is_an_error_not_a_panic() {
        let d = tmp_dir();
        let exe = d.join("vanish");
        let man = d.join("SHA256SUMS");
        std::fs::write(&exe, b"fixture").unwrap();
        for content in [format!("{}я  vanish\n", "a".repeat(63)), "short\n".into()] {
            std::fs::write(&man, content).unwrap();
            assert!(check(&exe, &man).is_err());
        }
        let actual = sha256_file(&exe).unwrap();
        std::fs::write(&man, format!("{actual}vanish\n")).unwrap();
        assert!(check(&exe, &man).is_err());
        std::fs::write(&man, format!("{actual} *vanish\n")).unwrap();
        assert!(check(&exe, &man).unwrap());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn explicit_manifest_does_not_fall_back_to_adjacent_manifest() {
        let d = tmp_dir();
        let exe = d.join("vanish");
        std::fs::write(d.join("SHA256SUMS"), "fixture").unwrap();
        assert!(resolve_manifest(&exe, Some(&d.join("missing"))).is_none());
        assert!(resolve_manifest(&exe, Some(&d)).is_none());
        std::fs::remove_dir_all(d).unwrap();
    }
}
