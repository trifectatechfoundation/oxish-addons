use std::{
    io,
    marker::PhantomData,
    os::unix::{ffi::OsStrExt, net::UnixListener as StdUnixListener},
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::UnixStream,
};
use tracing::warn;

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

impl AsyncRead for MonitorStream<CommandRunning> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.inner) }.poll_read(cx, buf)
    }
}

impl AsyncWrite for MonitorStream<CommandRunning> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.inner) }.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.inner) }.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.inner) }.poll_shutdown(cx)
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
                if let Err(e) = process_engine::run_command(socket) {
                    warn!("Cannot handle connection to monitor: {e}");
                }
            }
            Err(e) => {
                warn!("Cannot accept incoming connection to monitor: {e}");
            }
        }
    }
}
