//! Platform-specific local IPC endpoints and streams.

use crate::config::{prepare_state_dir, StateLock};
use anyhow::{Context, Result};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(windows)]
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(unix)]
const SOCKET_NAME: &str = "daemon.sock";

#[cfg(unix)]
pub(crate) struct LocalEndpointGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
impl Drop for LocalEndpointGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.ctime() == self.changed_seconds
                && metadata.ctime_nsec() == self.changed_nanoseconds
                && metadata.file_type().is_socket()
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(windows)]
pub(crate) struct LocalEndpointGuard;

#[cfg(test)]
impl LocalEndpointGuard {
    /// Consume the guard before a test removes its state directory. On Unix the
    /// socket cleanup runs through `Drop`; on Windows the zero-sized ownership
    /// marker is simply consumed without pretending it owns a closeable handle.
    pub(crate) fn release_for_test(self) {}
}

#[cfg(unix)]
pub(crate) type LocalServerStream = UnixStream;
#[cfg(unix)]
pub(crate) type LocalClientStream = UnixStream;
#[cfg(windows)]
pub(crate) type LocalServerStream = NamedPipeServer;
#[cfg(windows)]
pub(crate) type LocalClientStream = NamedPipeClient;

// Read EOF alone does not end a Unix subscription: clients may shut down only
// their write half and keep receiving events. Check full closure without writing
// protocol bytes, and only poll after EOF so ordinary subscribers incur no cost.
pub(crate) trait SubscriptionStream: AsyncRead + AsyncWrite + Unpin {
    fn subscription_closed_after_eof(&self) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(unix)]
impl SubscriptionStream for UnixStream {
    fn subscription_closed_after_eof(&self) -> Result<bool> {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        let mut fds = [PollFd::new(self, PollFlags::empty())];
        match poll(&mut fds, Some(&Timespec::default())) {
            Ok(_) => {
                let flags = fds[0].revents();
                anyhow::ensure!(
                    !flags.contains(PollFlags::NVAL),
                    "invalid subscription socket"
                );
                Ok(flags.intersects(PollFlags::HUP | PollFlags::ERR))
            }
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(error) => Err(error).context("poll subscription socket closure"),
        }
    }
}

#[cfg(windows)]
impl SubscriptionStream for NamedPipeServer {}

#[cfg(test)]
impl SubscriptionStream for tokio::io::DuplexStream {}

#[cfg(unix)]
pub(crate) struct LocalListener(UnixListener);

#[cfg(unix)]
impl LocalListener {
    pub(crate) async fn accept(&mut self) -> Result<LocalServerStream> {
        Ok(self
            .0
            .accept()
            .await
            .context("accept local daemon client")?
            .0)
    }
}

#[cfg(windows)]
pub(crate) struct LocalListener {
    pipe_name: String,
    pending: Option<NamedPipeServer>,
}

#[cfg(windows)]
impl LocalListener {
    pub(crate) async fn accept(&mut self) -> Result<LocalServerStream> {
        // This future is polled inside `tokio::select!`, so it must remain
        // cancellation-safe. Keep the pending server in `self` while waiting;
        // taking it before `.await` would leave the listener empty whenever a
        // different select branch wins.
        self.pending
            .as_ref()
            .context("named pipe listener missing")?
            .connect()
            .await
            .context("accept local daemon client")?;
        let next = create_pipe_server(&self.pipe_name, false)?;
        self.pending
            .replace(next)
            .context("named pipe listener missing")
    }
}

#[cfg(unix)]
fn local_endpoint(dir: &Path) -> String {
    dir.join(SOCKET_NAME).display().to_string()
}

#[cfg(windows)]
fn local_endpoint(dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::os::windows::ffi::OsStrExt;

    let path = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(b"meshmsg-windows-pipe-v1\0");
    for unit in path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    let digest = hasher.finalize();
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(r"\\.\pipe\meshmsg-{suffix}")
}

#[cfg(windows)]
struct WindowsHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn token_user_buffer(token: windows_sys::Win32::Foundation::HANDLE) -> Result<Vec<usize>> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser};

    let mut required = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
    }
    anyhow::ensure!(required > 0, "determine Windows token owner size");
    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    let loaded = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    };
    anyhow::ensure!(
        loaded != 0,
        "read Windows token owner: {}",
        std::io::Error::last_os_error()
    );
    Ok(buffer)
}

#[cfg(windows)]
fn sid_belongs_to_current_user(candidate: windows_sys::Win32::Security::PSID) -> Result<bool> {
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Security::{EqualSid, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut current_token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut current_token) };
    anyhow::ensure!(
        opened != 0,
        "open current process token: {}",
        std::io::Error::last_os_error()
    );
    let current_token = WindowsHandle(current_token);
    let current_user = token_user_buffer(current_token.0)?;
    let current_sid = unsafe { (*(current_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    Ok(unsafe { EqualSid(candidate, current_sid) } != 0)
}

#[cfg(windows)]
fn current_user_sid_string() -> Result<String> {
    use std::ffi::c_void;
    use windows_sys::{
        core::PWSTR,
        Win32::{
            Foundation::{LocalFree, HANDLE},
            Security::{Authorization::ConvertSidToStringSidW, TOKEN_QUERY, TOKEN_USER},
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    let mut token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    anyhow::ensure!(
        opened != 0,
        "open current process token: {}",
        std::io::Error::last_os_error()
    );
    let token = WindowsHandle(token);
    let user = token_user_buffer(token.0)?;
    let sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let mut text: PWSTR = std::ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    anyhow::ensure!(
        converted != 0,
        "format current user SID: {}",
        std::io::Error::last_os_error()
    );
    let length = unsafe {
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        length
    };
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .context("current user SID is not valid UTF-16")?;
    unsafe { LocalFree(text.cast::<c_void>()) };
    Ok(value)
}

#[cfg(windows)]
fn process_belongs_to_current_user(process_id: u32) -> Result<bool> {
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Security::{TOKEN_QUERY, TOKEN_USER},
        System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    };

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    anyhow::ensure!(
        !process.is_null(),
        "open named pipe server process: {}",
        std::io::Error::last_os_error()
    );
    let process = WindowsHandle(process);

    let mut server_token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut server_token) };
    anyhow::ensure!(
        opened != 0,
        "open named pipe server token: {}",
        std::io::Error::last_os_error()
    );
    let server_token = WindowsHandle(server_token);

    let server_user = token_user_buffer(server_token.0)?;
    let server_sid = unsafe { (*(server_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    sid_belongs_to_current_user(server_sid)
}

#[cfg(windows)]
fn verify_named_pipe_server_owner(stream: &NamedPipeClient) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{Foundation::HANDLE, System::Pipes::GetNamedPipeServerProcessId};

    let mut process_id = 0;
    let found =
        unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle() as HANDLE, &mut process_id) };
    anyhow::ensure!(
        found != 0,
        "identify named pipe server: {}",
        std::io::Error::last_os_error()
    );
    anyhow::ensure!(
        process_belongs_to_current_user(process_id)?,
        "refusing named pipe server owned by another Windows user"
    );
    Ok(())
}

#[cfg(unix)]
pub(crate) async fn bind_local_endpoint(
    dir: &Path,
    _state_lock: &StateLock,
) -> Result<(LocalListener, LocalEndpointGuard)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    prepare_state_dir(dir)?;
    let path = dir.join(SOCKET_NAME);
    if path.exists() {
        if UnixStream::connect(&path).await.is_ok() {
            anyhow::bail!("a meshmsg daemon is already running for {}", dir.display());
        }
        std::fs::remove_file(&path).context("remove stale daemon socket")?;
    }
    let listener = UnixListener::bind(&path).context("bind daemon socket")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .context("restrict daemon socket permissions")?;
    let metadata = std::fs::symlink_metadata(&path).context("inspect daemon socket")?;
    Ok((
        LocalListener(listener),
        LocalEndpointGuard {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        },
    ))
}

#[cfg(windows)]
fn create_pipe_server(name: &str, first: bool) -> Result<NamedPipeServer> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
    };

    // Make the current user the owner and grant access only to that user,
    // LocalSystem, and administrators. PIPE_REJECT_REMOTE_CLIENTS additionally
    // excludes network clients.
    let user_sid = current_user_sid_string()?;
    let mut sddl: Vec<u16> =
        format!("O:{user_sid}D:P(A;;GA;;;{user_sid})(A;;GA;;;SY)(A;;GA;;;BA)\0")
            .encode_utf16()
            .collect();
    let mut descriptor = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_mut_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    anyhow::ensure!(
        converted != 0,
        "create owner-only named pipe security descriptor: {}",
        std::io::Error::last_os_error()
    );
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
    };
    unsafe { LocalFree(descriptor) };
    result.context("create owner-only daemon named pipe")
}

#[cfg(windows)]
pub(crate) async fn bind_local_endpoint(
    dir: &Path,
    _state_lock: &StateLock,
) -> Result<(LocalListener, LocalEndpointGuard)> {
    prepare_state_dir(dir)?;
    let pipe_name = local_endpoint(dir);
    let pending = create_pipe_server(&pipe_name, true)?;
    Ok((
        LocalListener {
            pipe_name,
            pending: Some(pending),
        },
        LocalEndpointGuard,
    ))
}

#[cfg(unix)]
pub(crate) async fn connect_daemon(dir: &Path) -> Result<LocalClientStream> {
    UnixStream::connect(dir.join(SOCKET_NAME))
        .await
        .with_context(|| {
            format!(
                "connect to local daemon at {}; start it with `meshmsg daemon`",
                local_endpoint(dir)
            )
        })
}

#[cfg(windows)]
pub(crate) async fn connect_daemon(dir: &Path) -> Result<LocalClientStream> {
    let endpoint = local_endpoint(dir);
    for attempt in 0..20 {
        match ClientOptions::new().open(&endpoint) {
            Ok(stream) => {
                verify_named_pipe_server_owner(&stream)
                    .context("authenticate local daemon named pipe")?;
                return Ok(stream);
            }
            Err(error) if attempt < 19 && matches!(error.raw_os_error(), Some(2 | 231)) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("connect to local daemon at {endpoint}; start it with `meshmsg daemon`")
                });
            }
        }
    }
    unreachable!("named pipe connection retry loop always returns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StateLock;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(windows)]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(unix)]
    #[tokio::test]
    async fn daemon_socket_is_owner_only_and_replaces_stale_file() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SOCKET_NAME);
        std::fs::write(&path, b"stale").unwrap();
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (_listener, guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(guard);
        assert!(!path.exists());
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_guard_does_not_remove_a_replacement_path() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (listener, guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        drop(listener);
        let path = dir.join(SOCKET_NAME);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();

        drop(guard);
        assert_eq!(std::fs::read(path).unwrap(), b"replacement");
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_name_stably_hashes_wide_paths() {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        let first = std::path::PathBuf::from(OsString::from_wide(&[0x0061, 0xd800]));
        let second = std::path::PathBuf::from(OsString::from_wide(&[0x0061, 0xd801]));
        assert_eq!(local_endpoint(&first), local_endpoint(&first));
        assert_ne!(local_endpoint(&first), local_endpoint(&second));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_named_pipe_has_protected_owner_dacl() {
        use std::{ffi::c_void, os::windows::io::AsRawHandle};
        use windows_sys::Win32::{
            Foundation::{LocalFree, HANDLE},
            Security::{
                Authorization::{
                    BuildTrusteeWithSidW, GetEffectiveRightsFromAclW, GetSecurityInfo,
                    SE_KERNEL_OBJECT, TRUSTEE_W,
                },
                CreateWellKnownSid, GetSecurityDescriptorControl, WinWorldSid,
                DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
                SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED,
            },
        };

        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (listener, _guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        let server = listener.pending.as_ref().unwrap();
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                server.as_raw_handle() as HANDLE,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0);
        assert!(!owner.is_null());
        assert!(!dacl.is_null());
        assert!(sid_belongs_to_current_user(owner).unwrap());

        let mut control = 0;
        let mut revision = 0;
        let read_control =
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
        assert_ne!(read_control, 0);
        assert_ne!(control & SE_DACL_PROTECTED, 0);

        let mut world_sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut world_sid_size = world_sid.len() as u32;
        let made_world = unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                std::ptr::null_mut(),
                world_sid.as_mut_ptr().cast(),
                &mut world_sid_size,
            )
        };
        assert_ne!(made_world, 0);
        let mut trustee = TRUSTEE_W::default();
        unsafe { BuildTrusteeWithSidW(&mut trustee, world_sid.as_mut_ptr().cast()) };
        let mut rights = 0;
        let status = unsafe { GetEffectiveRightsFromAclW(dacl, &trustee, &mut rights) };
        assert_eq!(status, 0);
        assert_eq!(rights, 0, "Everyone must not receive named-pipe access");

        unsafe { LocalFree(descriptor.cast::<c_void>()) };
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_foreign_pipe_owner_sid_is_rejected() {
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, WinLocalSystemSid, SECURITY_MAX_SID_SIZE,
        };

        let mut system_sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = system_sid.len() as u32;
        let created = unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                std::ptr::null_mut(),
                system_sid.as_mut_ptr().cast(),
                &mut size,
            )
        };
        assert_ne!(created, 0, "{}", std::io::Error::last_os_error());
        assert!(!sid_belongs_to_current_user(system_sid.as_mut_ptr().cast()).unwrap());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_named_pipe_accepts_authenticated_local_ipc() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let endpoint = local_endpoint(&dir);
        let (mut listener, _guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut client = connect_daemon(&dir).await.unwrap();
        let mut server = accept.await.unwrap();
        assert_eq!(endpoint, local_endpoint(&dir));
        client.write_all(b"ping").await.unwrap();
        let mut received = [0; 4];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"ping");
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_named_pipe_accept_survives_cancellation() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (mut listener, _guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();

        let cancelled = tokio::time::timeout(Duration::from_millis(10), listener.accept()).await;
        assert!(cancelled.is_err());
        assert!(listener.pending.is_some());

        let (server, client) = tokio::join!(listener.accept(), connect_daemon(&dir));
        let mut server = server.unwrap();
        let mut client = client.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut received = [0; 4];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"ping");

        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
