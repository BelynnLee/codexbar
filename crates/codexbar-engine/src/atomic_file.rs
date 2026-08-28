use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_STAGING_ATTEMPTS: usize = 128;
static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);

pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    atomic_write_with_stage_hook(path, bytes, |_| {})
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn file_has_multiple_links(file: &File) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a valid handle for the duration of this call and `information` points to
    // writable initialized storage.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information) };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(information.nNumberOfLinks != 1)
    }
}

#[cfg(not(windows))]
pub fn file_has_multiple_links(file: &File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(file.metadata()?.nlink() != 1)
}

pub fn stage_file(path: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let (staged, mut file) = create_staged_file(path)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    Ok(staged)
}

fn atomic_write_with_stage_hook(
    path: &Path,
    bytes: &[u8],
    after_stage: impl FnOnce(&Path),
) -> std::io::Result<()> {
    let (staged, mut file) = create_staged_file(path)?;
    after_stage(&staged);
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let result = result.and_then(|()| replace_file(&staged, path));
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

fn create_staged_file(path: &Path) -> std::io::Result<(PathBuf, File)> {
    create_staged_file_with_counter(path, &NEXT_STAGING_ID)
}

fn create_staged_file_with_counter(
    path: &Path,
    counter: &AtomicU64,
) -> std::io::Result<(PathBuf, File)> {
    for _ in 0..MAX_STAGING_ATTEMPTS {
        let staging_id = counter.fetch_add(1, Ordering::Relaxed);
        let staged = staged_path(path, staging_id)?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
        {
            Ok(file) => return Ok((staged, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not reserve a unique atomic-write staging file",
    ))
}

fn staged_path(path: &Path, staging_id: u64) -> std::io::Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "atomic write path has no file name",
        )
    })?;
    let mut staged_name = file_name.to_os_string();
    staged_name.push(format!(".tmp-{}-{staging_id}", std::process::id()));
    Ok(path.with_file_name(staged_name))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are encoded as stable, null-terminated UTF-16 buffers for the duration of
    // the call. MoveFileExW takes no ownership of them.
    let succeeded = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn atomic_replace_with_backup(
    destination: &Path,
    replacement: &Path,
    backup: &Path,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{REPLACEFILE_WRITE_THROUGH, ReplaceFileW};

    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let replacement = replacement
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let backup = backup
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: all three paths are stable, null-terminated UTF-16 buffers for the duration of the
    // call. ReplaceFileW takes no ownership of them. A backup is always requested so the caller
    // can validate the exact file displaced by the atomic replacement.
    let succeeded = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            replacement.as_ptr(),
            backup.as_ptr(),
            REPLACEFILE_WRITE_THROUGH,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn atomic_replace_with_backup(
    destination: &Path,
    replacement: &Path,
    backup: &Path,
) -> std::io::Result<()> {
    fs::rename(destination, backup)?;
    if let Err(error) = fs::rename(replacement, destination) {
        let _ = fs::rename(backup, destination);
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn atomic_move_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are stable, null-terminated UTF-16 buffers for the call. Omitting
    // MOVEFILE_REPLACE_EXISTING is the no-overwrite fence.
    let succeeded = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn atomic_move_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::hard_link(source, destination)?;
    fs::remove_file(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex};

    fn staged_files(directory: &Path, file_name: &str) -> Vec<PathBuf> {
        let prefix = format!("{file_name}.tmp-");
        std::fs::read_dir(directory)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect()
    }

    #[test]
    fn replaces_existing_file_without_leaving_a_staged_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");

        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(staged_files(directory.path(), "config.json").is_empty());
    }

    #[test]
    fn backup_replacement_preserves_the_exact_displaced_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let backup = directory.path().join("config.json.backup");
        fs::write(&path, b"before").unwrap();
        let staged = stage_file(&path, b"after").unwrap();

        atomic_replace_with_backup(&path, &staged, &backup).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"after");
        assert_eq!(fs::read(&backup).unwrap(), b"before");
        assert!(!staged.exists());
    }

    #[test]
    fn no_replace_move_preserves_an_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let destination = directory.path().join("destination");
        fs::write(&source, b"source").unwrap();
        fs::write(&destination, b"destination").unwrap();

        assert!(atomic_move_no_replace(&source, &destination).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"source");
        assert_eq!(fs::read(&destination).unwrap(), b"destination");
    }

    #[test]
    fn concurrent_writes_install_one_complete_payload_without_staging_residue() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let first = vec![0x11; 256 * 1024];
        let second = vec![0xee; 256 * 1024];
        let barrier = Arc::new(Barrier::new(2));
        let staged_paths = Arc::new(Mutex::new(Vec::new()));
        let handles = [first.clone(), second.clone()].map(|payload| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let staged_paths = Arc::clone(&staged_paths);
            std::thread::spawn(move || {
                atomic_write_with_stage_hook(&path, &payload, move |staged| {
                    staged_paths.lock().unwrap().push(staged.to_path_buf());
                    barrier.wait();
                })
            })
        });

        let results = handles.map(|handle| handle.join().unwrap());

        let staged_paths = staged_paths.lock().unwrap();
        assert_eq!(staged_paths.len(), 2);
        assert_ne!(staged_paths[0], staged_paths[1]);
        assert!(
            results.iter().any(Result::is_ok),
            "concurrent results: {results:?}"
        );
        let installed = std::fs::read(&path).unwrap();
        assert!(
            (results[0].is_ok() && installed == first)
                || (results[1].is_ok() && installed == second),
            "installed file did not match a successful writer: {results:?}"
        );
        assert!(staged_files(directory.path(), "config.json").is_empty());
    }

    #[test]
    fn replace_failure_removes_only_the_staged_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        std::fs::create_dir(&path).unwrap();

        let result = atomic_write(&path, b"fictional-config");

        assert!(result.is_err());
        assert!(path.is_dir());
        assert!(staged_files(directory.path(), "config.json").is_empty());
    }

    #[test]
    fn staging_collision_retries_without_touching_the_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let counter = AtomicU64::new(7);
        let collision = staged_path(&path, 7).unwrap();
        std::fs::write(&collision, b"foreign-staging-file").unwrap();

        let (reserved, file) = create_staged_file_with_counter(&path, &counter).unwrap();
        drop(file);

        assert_ne!(reserved, collision);
        assert_eq!(std::fs::read(&collision).unwrap(), b"foreign-staging-file");
        std::fs::remove_file(reserved).unwrap();
    }
}
