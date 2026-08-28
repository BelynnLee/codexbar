use crate::{config::BrowserPreference, provider::ProviderError};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
};

/// Windows `ERROR_SHARING_VIOLATION`: another process holds the file open without granting the
/// share access we request. A running browser locks its live cookie database this way.
const SHARING_VIOLATION: i32 = 32;

#[derive(Debug, Clone)]
pub struct CookieHeader {
    pub value: String,
    pub source: String,
}

pub fn find_cookie_header(
    preference: BrowserPreference,
    domains: &[&str],
    preferred_names: &[&str],
) -> Result<CookieHeader, ProviderError> {
    let roots = browser_roots(preference)?;
    let mut failures = Vec::new();
    for (browser_name, root) in roots {
        if !root.exists() {
            continue;
        }
        let master_key = match load_master_key(&root) {
            Ok(key) => key,
            Err(error) => {
                failures.push(format!("{browser_name}: {error}"));
                continue;
            }
        };
        for profile in profiles(&root) {
            match read_profile_cookies(&profile, &master_key, domains, preferred_names) {
                Ok(Some(value)) => {
                    let profile_name = profile
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("Default");
                    return Ok(CookieHeader {
                        value,
                        source: format!("{browser_name} · {profile_name}"),
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    failures.push(format!("{browser_name}/{}: {error}", profile.display()));
                }
            }
        }
    }

    let detail = if failures.is_empty() {
        "Chrome or Edge is not installed, or no matching profile exists".to_owned()
    } else {
        failures.join("; ")
    };
    Err(ProviderError::MissingCredentials(format!(
        "Could not import a browser session cookie automatically. Paste a Cookie header in Settings, or resolve: {detail}"
    )))
}

fn browser_roots(
    preference: BrowserPreference,
) -> Result<Vec<(&'static str, PathBuf)>, ProviderError> {
    let local_app_data = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| ProviderError::Platform("LOCALAPPDATA is not set".into()))?;
    let chrome = (
        "Chrome",
        local_app_data
            .join("Google")
            .join("Chrome")
            .join("User Data"),
    );
    let edge = (
        "Edge",
        local_app_data
            .join("Microsoft")
            .join("Edge")
            .join("User Data"),
    );
    Ok(match preference {
        BrowserPreference::Auto => vec![chrome, edge],
        BrowserPreference::Chrome => vec![chrome],
        BrowserPreference::Edge => vec![edge],
    })
}

fn profiles(root: &Path) -> Vec<PathBuf> {
    let mut profiles = Vec::new();
    for name in ["Default", "Guest Profile"] {
        let path = root.join(name);
        if path.exists() {
            profiles.push(path);
        }
    }
    if let Ok(entries) = fs::read_dir(root) {
        let mut named_profiles = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name();
                name.to_string_lossy()
                    .starts_with("Profile ")
                    .then(|| entry.path())
            })
            .collect::<Vec<_>>();
        named_profiles.sort();
        profiles.extend(named_profiles);
    }
    profiles
}

fn load_master_key(root: &Path) -> Result<Vec<u8>, ProviderError> {
    let bytes = fs::read(root.join("Local State")).map_err(|error| {
        ProviderError::Credential(format!("Could not read Chromium Local State: {error}"))
    })?;
    let state: Value = serde_json::from_slice(&bytes).map_err(|error| {
        ProviderError::Credential(format!("Invalid Chromium Local State: {error}"))
    })?;
    let encoded = state
        .pointer("/os_crypt/encrypted_key")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Credential("Chromium Local State has no encrypted_key".into())
        })?;
    let mut encrypted = STANDARD.decode(encoded).map_err(|error| {
        ProviderError::Credential(format!("Invalid Chromium encrypted_key: {error}"))
    })?;
    if encrypted.starts_with(b"DPAPI") {
        encrypted.drain(..5);
    }
    dpapi_unprotect(&encrypted)
}

fn read_profile_cookies(
    profile: &Path,
    master_key: &[u8],
    domains: &[&str],
    preferred_names: &[&str],
) -> Result<Option<String>, ProviderError> {
    let database = [
        profile.join("Network").join("Cookies"),
        profile.join("Cookies"),
    ]
    .into_iter()
    .find(|path| path.exists());
    let Some(database) = database else {
        return Ok(None);
    };
    let temporary = tempfile::tempdir().map_err(|error| {
        ProviderError::Credential(format!("Could not stage browser cookies: {error}"))
    })?;
    let staged = temporary.path().join("Cookies");
    copy_unlocked(&database, &staged).map_err(|error| {
        // ERROR_SHARING_VIOLATION (32): the browser holds the database open without sharing reads,
        // so no user-mode copy can snapshot it. Edge is the usual culprit — its Startup boost keeps
        // background processes alive that keep the lock even after every window is closed.
        if error.raw_os_error() == Some(SHARING_VIOLATION) {
            ProviderError::Credential(
                "cookie database is locked by the running browser; fully quit it (Edge's Startup boost \
                 keeps it locked via background processes — end them in Task Manager) or paste a Cookie \
                 header in Settings"
                    .to_owned(),
            )
        } else {
            ProviderError::Credential(format!("could not copy browser cookie database: {error}"))
        }
    })?;
    // Copy the write-ahead log so cookies written since the last checkpoint are visible. We
    // deliberately skip the -shm index: SQLite rebuilds it from the WAL when we open the copy
    // read-write below, which avoids trusting a shared-memory file captured mid-write.
    let wal = PathBuf::from(format!("{}-wal", database.display()));
    if wal.exists() {
        let _ = copy_unlocked(&wal, &temporary.path().join("Cookies-wal"));
    }

    // The staged files are a private throwaway copy, so open read-write: it lets SQLite recover the
    // WAL and rebuild the shared-memory index, which a read-only connection cannot do.
    let connection = Connection::open_with_flags(
        staged,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| {
        ProviderError::Credential(format!("Could not open browser cookies: {error}"))
    })?;
    let mut statement = connection
        .prepare(
            "SELECT host_key, name, value, encrypted_value FROM cookies \
             WHERE host_key LIKE '%' || ?1 ORDER BY last_access_utc DESC",
        )
        .map_err(|error| {
            ProviderError::Credential(format!("Could not query browser cookies: {error}"))
        })?;
    let preferred = preferred_names.iter().copied().collect::<HashSet<_>>();
    let mut values = HashMap::<String, String>::new();
    let mut saw_app_bound_cookie = false;
    for domain in domains {
        let rows = statement
            .query_map([domain], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                ))
            })
            .map_err(|error| {
                ProviderError::Credential(format!("Could not read browser cookies: {error}"))
            })?;
        for row in rows.flatten() {
            let (host, name, plaintext, encrypted) = row;
            if !preferred.is_empty() && !preferred.contains(name.as_str()) {
                continue;
            }
            if values.contains_key(&name) {
                continue;
            }
            let value = if !plaintext.is_empty() {
                Some(plaintext)
            } else if encrypted.starts_with(b"v20") {
                saw_app_bound_cookie = true;
                None
            } else {
                decrypt_cookie_value(master_key, &host, &encrypted).ok()
            };
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                values.insert(name, value);
            }
        }
    }
    if values.is_empty() && saw_app_bound_cookie {
        return Err(ProviderError::Platform(concat!(
            "this login uses Chromium App-Bound (v20) encryption, which third-party apps cannot ",
            "decrypt. Paste a Cookie header in Settings (copy the request Cookie header from the ",
            "browser's DevTools \u{2192} Network tab)."
        )
        .into()));
    }
    if values.is_empty() {
        return Ok(None);
    }
    let mut ordered = values.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Some(
        ordered
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; "),
    ))
}

/// Copies a file that another process may currently hold open.
///
/// Chrome and Edge keep the live `Cookies` database (and its `-wal` sibling) open while running,
/// with `GENERIC_READ | GENERIC_WRITE` and read+write sharing. We open the source sharing the same
/// access so a snapshot succeeds without asking the browser to release the file. `std::fs::copy`
/// usually works here too, but the exact share mode `CopyFileW` requests is an unspecified std
/// implementation detail that has varied across releases; pinning the full share mode keeps this
/// robust regardless of toolchain.
///
/// This still cannot read a browser that denies read sharing entirely — Edge's Startup boost holds
/// the database with no `FILE_SHARE_READ`, which is a hard OS-level lock. The caller maps that
/// `ERROR_SHARING_VIOLATION` to a message steering the user to quit the browser or paste a cookie.
#[cfg(windows)]
fn copy_unlocked(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    const SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
    let mut reader = fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_ALL)
        .open(source)?;
    let mut writer = fs::File::create(destination)?;
    std::io::copy(&mut reader, &mut writer)?;
    Ok(())
}

#[cfg(not(windows))]
fn copy_unlocked(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::copy(source, destination).map(drop)
}

fn decrypt_cookie_value(
    master_key: &[u8],
    host: &str,
    encrypted: &[u8],
) -> Result<String, ProviderError> {
    let mut plaintext = if encrypted.starts_with(b"v10") || encrypted.starts_with(b"v11") {
        if master_key.len() != 32 || encrypted.len() < 3 + 12 + 16 {
            return Err(ProviderError::Credential(
                "Invalid Chromium AES cookie payload".into(),
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|_| ProviderError::Credential("Invalid Chromium AES master key".into()))?;
        cipher
            .decrypt(Nonce::from_slice(&encrypted[3..15]), &encrypted[15..])
            .map_err(|_| {
                ProviderError::Credential("Could not authenticate Chromium cookie".into())
            })?
    } else {
        dpapi_unprotect(encrypted)?
    };

    let host_digest = Sha256::digest(host.as_bytes());
    if plaintext.starts_with(host_digest.as_slice()) {
        plaintext.drain(..host_digest.len());
    }
    while plaintext.last() == Some(&0) {
        plaintext.pop();
    }
    String::from_utf8(plaintext)
        .map_err(|error| ProviderError::Credential(format!("Browser cookie is not UTF-8: {error}")))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn dpapi_unprotect(encrypted: &[u8]) -> Result<Vec<u8>, ProviderError> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData},
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(encrypted.len())
            .map_err(|_| ProviderError::Credential("DPAPI input is too large".into()))?,
        pbData: encrypted.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input references `encrypted` for the duration of the call; optional pointers are null as required by
    // CryptUnprotectData; `output` is initialized by Windows and released with LocalFree after copying.
    let succeeded = unsafe {
        CryptUnprotectData(
            &raw const input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            0,
            &raw mut output,
        )
    };
    if succeeded == 0 {
        return Err(ProviderError::Credential(format!(
            "Windows DPAPI rejected browser key (OS error {})",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: a successful CryptUnprotectData call returns `cbData` readable bytes at `pbData`.
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    // SAFETY: `pbData` is allocated by LocalAlloc inside CryptUnprotectData and must be released exactly once.
    let _ = unsafe { LocalFree(output.pbData.cast::<c_void>()) };
    Ok(result)
}

#[cfg(not(windows))]
fn dpapi_unprotect(_encrypted: &[u8]) -> Result<Vec<u8>, ProviderError> {
    Err(ProviderError::Platform(
        "DPAPI cookie import is only available on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;

    #[test]
    fn decrypts_aes_gcm_cookie_and_strips_host_digest() {
        let key = [7_u8; 32];
        let nonce = [3_u8; 12];
        let host = ".cursor.com";
        let mut plaintext = Sha256::digest(host.as_bytes()).to_vec();
        plaintext.extend_from_slice(b"session-value");
        let cipher = Aes256Gcm::new_from_slice(&key).expect("AES key");
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .expect("encrypt");
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        assert_eq!(
            decrypt_cookie_value(&key, host, &blob).expect("decrypt cookie"),
            "session-value"
        );
    }

    // Reproduces the `os error 32` sharing violation the menu bar hit against a running browser and
    // proves `copy_unlocked` reads through it. Chromium's SQLite keeps the live database open with
    // `GENERIC_READ | GENERIC_WRITE` while sharing only read+write; `CopyFileW` (behind
    // `std::fs::copy`) opens the source sharing only read, so the browser's held write access is
    // rejected. `copy_unlocked` shares write access too and succeeds.
    // A running browser keeps its live cookie database open with `GENERIC_READ | GENERIC_WRITE`
    // while sharing read+write (SQLite's default). `copy_unlocked` shares the same access back, so it
    // snapshots the database in place. (Edge additionally denies read sharing outright via its
    // Startup boost processes; no user-mode copy — this one included — can read through that, which
    // is why the error path steers the user to a manual Cookie header instead.)
    #[cfg(windows)]
    #[test]
    fn copy_unlocked_snapshots_a_database_held_open_like_sqlite() {
        use std::os::windows::fs::OpenOptionsExt;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;

        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("Cookies");
        fs::write(&source, b"cookie-database-bytes").expect("seed database");

        let _held = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ_WRITE)
            .open(&source)
            .expect("hold the database open the way SQLite does");

        let destination = directory.path().join("staged");
        copy_unlocked(&source, &destination).expect("copy_unlocked reads the held-open database");
        assert_eq!(
            fs::read(&destination).expect("read staged copy"),
            b"cookie-database-bytes"
        );
    }
}
