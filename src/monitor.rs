use std::{
    ffi::OsStr,
    io::{self, Read},
    marker::PhantomData,
    os::{
        fd::{AsFd, AsRawFd},
        unix::{
            ffi::OsStrExt,
            net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream},
            process::CommandExt,
        },
    },
    path::Path,
    process::Command,
};

use crate::pty::get_pty;
use tokio::{io::AsyncWriteExt, net::UnixStream};
use tracing::warn;

use crate::fd::{recv_fd, send_fd, FdStream};

const MONITOR_SOCK_ADDR: &str = "/tmp/oxish-monitor.sck";

trait State {}
impl State for CommandSetup {}
impl State for CommandRunning {}

pub(crate) struct CommandSetup {}
pub(crate) struct CommandRunning {}

#[allow(private_bounds)]
pub(crate) struct MonitorStream<S: State> {
    inner: UnixStream,
    _marker: PhantomData<S>,
}

impl MonitorStream<CommandSetup> {
    pub(crate) async fn connect() -> io::Result<Self> {
        Ok(Self {
            inner: UnixStream::connect(MONITOR_SOCK_ADDR).await?,
            _marker: PhantomData,
        })
    }

    pub(crate) async fn run_command<P: AsRef<Path> + ?Sized>(
        mut self,
        command: &P,
    ) -> io::Result<MonitorStream<CommandRunning>> {
        let command = command.as_ref().as_os_str().as_bytes();

        self.inner.write_all(&command.len().to_ne_bytes()).await?;
        self.inner.write_all(command).await?;

        // FIXME(@pvdrz): Maybe receive a message from the monitor acknolwedging that the command
        // is being executed.

        Ok(MonitorStream::<CommandRunning> {
            inner: self.inner,
            _marker: PhantomData,
        })
    }
}

impl MonitorStream<CommandRunning> {
    pub(crate) async fn recv_pty(mut self) -> io::Result<FdStream> {
        let fd = recv_fd(&mut self.inner).await?;

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(unsafe { FdStream::from_raw(fd) }?)
    }
}

pub(crate) fn monitor_main() -> anyhow::Result<()> {
    if let Err(e) = std::fs::remove_file(MONITOR_SOCK_ADDR) {
        if e.kind() != io::ErrorKind::NotFound {
            anyhow::bail!("Cannot delete monitor socket file: {e}");
        }
    }

    // Create a UNIX listener so each network process can communicate with the monitor
    let listener = StdUnixListener::bind(MONITOR_SOCK_ADDR)?;

    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                if let Err(e) = accept_request(socket) {
                    warn!("Cannot handle connection to monitor: {e}");
                }
            }
            Err(e) => {
                warn!("Cannot accept incoming connection to monitor: {e}");
            }
        }
    }
}

pub(crate) fn accept_request(mut socket: StdUnixStream) -> anyhow::Result<()> {
    // Read the length of the command
    let mut buf = [0; size_of::<usize>()];
    let read_len = socket.read(&mut buf)?;
    assert_eq!(buf.len(), read_len);

    // Read the actual command
    let command_len = usize::from_ne_bytes(buf);
    let mut buf = vec![0; command_len];
    let read_len = socket.read(&mut buf)?;
    assert_eq!(command_len, read_len);

    let command = OsStr::from_bytes(&buf);

    tracing::debug!("opening PTY");
    let pty = get_pty()?;

    tracing::debug!("sending PTY to network");
    send_fd(&mut socket, pty.leader.as_raw_fd())?;

    let mut command = Command::new(command);
    let fd_follower = pty.follower.as_fd().as_raw_fd();

    unsafe {
        command.pre_exec(move || {
            // make a new session for the process
            libc::setsid();
            // set the follower as the controlling terminal
            libc::ioctl(fd_follower, libc::TIOCSCTTY, 0);
            Ok(())
        })
    };

    command
        .stdin(pty.follower.try_clone()?)
        .stdout(pty.follower.try_clone()?)
        .stderr(pty.follower);

    tracing::debug!("running command: {:?}", command.get_program());
    let _child = command.spawn()?;

    Ok(())
}
