#![allow(unused)]
use std::{
    ffi::OsStr,
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd, RawFd},
        unix::ffi::OsStrExt,
    },
    task::{ready, Poll},
};

use tokio::{
    io::{unix::AsyncFd, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    runtime::Runtime,
};

use crate::{
    cutils::cerr,
    log::{dev_info, SudoLogger},
    system::{fork, term::PtyLeader, ForkResult, _exit},
};

#[macro_use]
mod macros;
#[macro_use]
pub(crate) mod gettext;

pub(crate) mod common;
pub(crate) mod cutils;
pub(crate) mod exec;
pub(crate) mod log;
pub(crate) mod system;

pub struct AsyncPtyLeader {
    fd: AsyncFd<PtyLeader>,
}

impl AsyncRead for AsyncPtyLeader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready_mut(cx))?;

            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|fd| fd.get_mut().read(unfilled)) {
                Ok(Ok(len)) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncPtyLeader {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready_mut(cx))?;

            match guard.try_io(|fd| fd.get_mut().write(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        cerr(unsafe { libc::close(self.fd.get_ref().as_raw_fd()) })?;
        Poll::Ready(Ok(()))
    }
}

pub fn run<T, Fut: std::future::Future<Output = T>>(
    async_process: impl FnOnce(AsyncPtyLeader, tokio::net::UnixStream) -> Fut,
) -> T {
    use crate::{exec, system::User};
    use std::path::Path;

    let me = User::real().ok().flatten().unwrap();

    let (left_sock, right_sock) = std::os::unix::net::UnixStream::pair().unwrap();
    left_sock.set_nonblocking(true).unwrap();

    let pty = crate::exec::get_pty(&me).unwrap();

    match unsafe { fork() }.unwrap() {
        ForkResult::Parent(child_pid) => {
            let runtime = Runtime::new().unwrap();

            runtime.block_on(async move {
                let leader = AsyncPtyLeader {
                    fd: AsyncFd::new(pty.leader).unwrap(),
                };

                // Turn the std socket into a tokio socket
                let sock = UnixStream::from_std(left_sock).unwrap();

                async_process(leader, sock).await
            })
        }
        ForkResult::Child => {
            let mut sock = right_sock;
            let follower = pty.follower;

            // Read the length of the command
            let mut buf = [0; std::mem::size_of::<usize>()];
            let read_len = sock.read(&mut buf).unwrap();
            assert_eq!(buf.len(), read_len);

            // Read the actual command
            let command_len = usize::from_ne_bytes(buf);
            let mut buf = vec![0; command_len];
            let read_len = sock.read(&mut buf).unwrap();
            assert_eq!(command_len, read_len);

            let command = Path::new(OsStr::from_bytes(&buf));

            SudoLogger::new("sshd").into_global_logger();
            dev_info!("development logs are enabled");

            let _exit_reason = exec::run_command(
                exec::RunOptions {
                    command,
                    arguments: &[],
                    arg0: None,
                    chdir: None,
                    is_login: true,
                    umask: exec::Umask::Override(0o022),
                    use_pty: true,
                    noexec: false,
                    user: &me,
                    group: &me.primary_group().unwrap(),
                },
                vec![("OXI_SH", "1")],
                sock,
                follower,
            )
            .unwrap();

            _exit(0);
        }
    }
}
