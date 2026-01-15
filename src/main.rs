use core::net::{Ipv4Addr, SocketAddr};
use std::{
    fs::{self, File},
    io::{self, Write},
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
    net::{TcpListener, UnixStream},
};
use tracing::{debug, info, warn};

fn main() -> anyhow::Result<()> {
    process_engine::runtime(async_main)
}

async fn async_main(
    terminal: process_engine::AsyncPtyLeader,
    cmdsock: UnixStream,
) -> anyhow::Result<()> {
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
        (Some(listener), None) => {
            listener.set_nonblocking(true)?;
            TcpListener::from_std(listener)?
        }
        (None, Some(port)) => {
            let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
            TcpListener::bind(addr).await?
        }
        (Some(_), Some(_)) => anyhow::bail!("LISTEN_FDS and --port conflict with each other"),
        (None, None) => anyhow::bail!("unless LISTEN_FDS is set, --port is required"),
    };
    info!(addr = %listener.local_addr()?, "listening for connections");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!(%addr, "accepted connection");
                // FIXME(aws/aws-lc-rs#975) use tokio::spawn() once StreamingDecryptingKey is Send
                let Ok(conn) =
                    SshTransportConnection::connect(stream, addr, host_key.clone()).await
                else {
                    continue; // Some kind of error happened. Has been logged already.
                };
                ServiceRunner::new(conn, |service_name, packet_sender| {
                    if service_name == b"ssh-userauth" {
                        Some(Box::new(AuthService::new(
                            |service_name, username, packet_sender| {
                                debug!(
                                    "Authenticated {} for service {}",
                                    String::from_utf8_lossy(username),
                                    String::from_utf8_lossy(service_name)
                                );
                                Some(Box::new(ConnectionService::new(
                                    |channel_type, _type_data, mut channels| {
                                        debug!(
                                            "New channel of type {}",
                                            String::from_utf8_lossy(channel_type)
                                        );
                                        tokio::spawn(async move {
                                            let _ =
                                                channels.stdout.write_all(b"hello world\r\n").await;
                                            loop {
                                                let mut buf = [0; 128];
                                                let Ok(size) = channels.stdin.read(&mut buf).await
                                                else {
                                                    break;
                                                };
                                                if size == 0 {
                                                    break;
                                                }
                                                for c in &buf[..size] {
                                                    match *c {
                                                        3 => {
                                                            // ctrl-c
                                                            channels.exit_status.send(2).unwrap();
                                                            return;
                                                        }
                                                        b'\r' => {
                                                            let _ = channels
                                                                .stdout
                                                                .write_all(b"\r\n")
                                                                .await;
                                                        }
                                                        v => {
                                                            let _ = channels
                                                                .stdout
                                                                .write_all(&[v])
                                                                .await;
                                                        }
                                                    }
                                                }
                                            }
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
            }
            Err(error) => {
                warn!(%error, "failed to accept connection");
                continue;
            }
        }
    }
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
