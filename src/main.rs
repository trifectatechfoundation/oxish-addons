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
    sync::Mutex,
};
use tracing::{debug, info, warn};

fn main() -> anyhow::Result<()> {
    process_engine::run(async_main)
}

async fn async_main(
    terminal: process_engine::AsyncPtyLeader,
    sock: UnixStream,
) -> anyhow::Result<()> {
    let cmdsock = Arc::new(Mutex::new((terminal, sock)));
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
                let cmdsock = cmdsock.clone();
                ServiceRunner::new(conn, move |service_name, packet_sender| {
                    let cmdsock = cmdsock.clone();
                    if service_name == b"ssh-userauth" {
                        Some(Box::new(AuthService::new(
                            move |service_name, username, packet_sender| {
                                debug!(
                                    "Authenticated {} for service {}",
                                    String::from_utf8_lossy(username),
                                    String::from_utf8_lossy(service_name)
                                );
                                let cmdsock = cmdsock.clone();
                                Some(Box::new(ConnectionService::new(
                                    move |channel_type, _type_data, mut channels| {
                                        debug!(
                                            "New channel of type {}",
                                            String::from_utf8_lossy(channel_type)
                                        );
                                        let cmdsock = cmdsock.clone();
                                        tokio::spawn(async move {
                                            let (ref mut term, ref mut sock) =
                                                *cmdsock.lock().await;

                                            let _ = {
                                                let command = b"/usr/bin/sh";
                                                let _ = sock
                                                    .write(&command.len().to_ne_bytes())
                                                    .await
                                                    .unwrap();

                                                let _ = sock.write(command).await.unwrap();
                                            };

                                            loop {
                                                let mut buf = [0; 1024];
                                                if let Ok(size) = term.read(&mut buf).await {
                                                    for c in &buf[..size] {
                                                        println!("TERM: {}", *c as char);
                                                    }

                                                    let _ = channels
                                                        .stdout
                                                        .write_all(&buf[..size])
                                                        .await;
                                                    let _ = channels.stdout.flush().await;
                                                };

                                                if let Ok(size) =
                                                    channels.stdin.read(&mut buf).await
                                                {
                                                    let _ = term.write_all(&buf[..size]).await;
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
