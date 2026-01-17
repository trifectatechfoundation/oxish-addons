mod fd;
mod monitor;

use std::{
    fs::{self, File},
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    sync::Arc,
};

use aws_lc_rs::signature::Ed25519KeyPair;
use clap::Parser;
use listenfd::ListenFd;
use oxish::{
    auth::AuthService, connection::ConnectionService, service::ServiceRunner,
    SshTransportConnection,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use tracing::{debug, info, warn};

use crate::monitor::{monitor_main, MonitorStream};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let host_key = Arc::new(if args.generate_host_key {
        match File::create_new(&args.host_key_file) {
            Ok(mut host_key_file) => {
                let Ok(host_key) = Ed25519KeyPair::generate() else {
                    anyhow::bail!("failed to generate host key");
                };
                // FIXME ensure the host key is only readable by the ssh server user
                host_key_file.write_all(host_key.to_pkcs8v1()?.as_ref())?;
                eprintln!("generated host key at {}", args.host_key_file);
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                anyhow::bail!("host key file `{}` already exists", &args.host_key_file);
            }
            Err(err) => return Err(err.into()),
        }
    } else {
        Ed25519KeyPair::from_pkcs8(&fs::read(args.host_key_file)?)?
    });

    let listener = match (ListenFd::from_env().take_tcp_listener(0)?, args.port) {
        (Some(listener), None) => listener,
        (None, Some(port)) => {
            let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
            StdTcpListener::bind(addr)?
        }
        (Some(_), Some(_)) => anyhow::bail!("LISTEN_FDS and --port conflict with each other"),
        (None, None) => anyhow::bail!("unless LISTEN_FDS is set, --port is required"),
    };
    info!(addr = %listener.local_addr()?, "listening for connections");

    let monitor_pid = unsafe { libc::fork() };

    if monitor_pid == -1 {
        anyhow::bail!("Cannot fork monitor process");
    }

    if monitor_pid == 0 {
        return monitor_main();
    }

    debug!("Forked monitor as {monitor_pid}");

    listener_main(listener, host_key)
}

fn listener_main(listener: StdTcpListener, host_key: Arc<Ed25519KeyPair>) -> anyhow::Result<()> {
    // Ignore SIGCHLD
    if libc::SIG_ERR == unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) } {
        return Err(io::Error::last_os_error().into());
    }

    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                let network_pid = unsafe { libc::fork() };

                if network_pid == -1 {
                    anyhow::bail!("Cannot fork network process");
                }

                if network_pid == 0 {
                    tokio::runtime::Runtime::new()?.block_on(network_main(
                        stream,
                        addr,
                        host_key.clone(),
                    ))?;
                    return Ok(());
                }

                debug!("Forked network as {network_pid}");
            }

            Err(error) => {
                warn!(%error, "failed to accept connection");
                continue;
            }
        }
    }
}

async fn network_main(
    stream: StdTcpStream,
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
) -> anyhow::Result<()> {
    debug!(%addr, "accepted connection");
    stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(stream)?;

    // FIXME(aws/aws-lc-rs#975) use tokio::spawn() once StreamingDecryptingKey is Send
    let Ok(conn) = SshTransportConnection::connect(stream, addr, host_key).await else {
        return Ok(()); // Some kind of error happened. Has been logged already.
    };

    ServiceRunner::new(conn, move |service_name, packet_sender| {
        if service_name == b"ssh-userauth" {
            Some(Box::new(AuthService::new(
                move |service_name, username, packet_sender| {
                    debug!(
                        "Authenticated {} for service {}",
                        String::from_utf8_lossy(username),
                        String::from_utf8_lossy(service_name)
                    );
                    Some(Box::new(ConnectionService::new(
                        move |channel_type, _type_data, mut channels| {
                            debug!(
                                "New channel of type {}",
                                String::from_utf8_lossy(channel_type)
                            );
                            tokio::spawn(async move {
                                debug!("connecting to monitor listener");
                                let monitor_stream = MonitorStream::connect().await.unwrap();

                                debug!("sending command to monitor");
                                let term_stream = monitor_stream
                                    .run_command("/usr/bin/sh")
                                    .await
                                    .unwrap()
                                    .recv_pty()
                                    .await
                                    .unwrap();

                                let (mut term_read, mut term_write) = tokio::io::split(term_stream);

                                debug!("copying data to and from the terminal");
                                let left = tokio::io::copy(&mut term_read, &mut channels.stdout);

                                let right = async move {
                                    let mut buf = [0; 1024];
                                    loop {
                                        if let Ok(size) = channels.stdin.read(&mut buf).await {
                                            let _ = term_write.write_all(&buf[..size]).await;
                                            for c in &buf[..size] {
                                                println!("SSH: {}", *c as char);
                                                if *c == 3 {
                                                    // ctrl-c
                                                    // THERE IS SOMETHING STRANGE GOING ON HERE
                                                    channels.exit_status.send(2).unwrap();
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                };

                                let _ = tokio::join!(left, right);
                            });
                            true
                        },
                        packet_sender,
                    )))
                },
                packet_sender,
            )))
        } else {
            None
        }
    })
    .run()
    .await;

    Ok(())
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long)]
    port: Option<u16>,
    #[clap(long, default_value = "ssh_host_ed25519_key")]
    host_key_file: String,
    #[clap(long)]
    generate_host_key: bool,
}
