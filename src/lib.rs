use core::net::SocketAddr;
use std::{io, str, sync::Arc};

use aws_lc_rs::signature::Ed25519KeyPair;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, error, warn};

mod key_exchange;
use key_exchange::KeyExchange;
mod proto;
use proto::{Encode, ReadState};

use crate::{
    key_exchange::{EcdhKeyExchangeInit, KeyExchangeInit},
    proto::HandshakeHash,
};

/// A single SSH connection
pub struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
    read: ReadState,
    write_buf: Vec<u8>,
}

impl Connection {
    /// Create a new [`Connection`]
    pub fn new(
        stream: TcpStream,
        addr: SocketAddr,
        host_key: Arc<Ed25519KeyPair>,
    ) -> anyhow::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            addr,
            host_key,
            read: ReadState::default(),
            write_buf: Vec::with_capacity(16_384),
        })
    }

    /// Drive the connection forward
    pub async fn run(mut self) {
        let mut exchange = HandshakeHash::default();
        let state = VersionExchange::default();
        let Ok(state) = state.advance(&mut exchange, &mut self).await else {
            return;
        };

        let future = self
            .read
            .packet::<KeyExchangeInit<'_>>(&mut self.stream, self.addr);
        let (peer_key_exchange_init, rest) = match future.await {
            Ok(packeted) => packeted.hash(&mut exchange),
            Err(error) => {
                error!(addr = %self.addr, %error, "failed to read key exchange init");
                return;
            }
        };

        self.write_buf.clear();
        let mut cx = ConnectionContext {
            addr: self.addr,
            host_key: &self.host_key,
            write_buf: &mut self.write_buf,
        };

        let Ok((packet, state)) = state.advance(peer_key_exchange_init, &mut exchange, &mut cx)
        else {
            return;
        };

        if let Err(error) = self.stream.write_all(&packet).await {
            error!(addr = %self.addr, %error, "failed to send ECDH key exchange reply");
            return;
        }

        self.read.truncate(rest);

        let future = self
            .read
            .packet::<EcdhKeyExchangeInit<'_>>(&mut self.stream, self.addr);
        let ecdh_key_exchange_init = match future.await {
            Ok(packet) => packet.into_inner(),
            Err(_) => return,
        };

        self.write_buf.clear();
        let mut cx = ConnectionContext {
            addr: self.addr,
            host_key: &self.host_key,
            write_buf: &mut self.write_buf,
        };

        let Ok((packet, _keys)) = state.advance(ecdh_key_exchange_init, exchange, &mut cx) else {
            return;
        };

        if let Err(error) = self.stream.write_all(&packet).await {
            error!(addr = %self.addr, %error, "failed to send ECDH key exchange reply");
            return;
        }

        todo!();
    }
}

struct ConnectionContext<'a> {
    addr: SocketAddr,
    host_key: &'a Ed25519KeyPair,
    write_buf: &'a mut Vec<u8>,
}

#[derive(Default)]
struct VersionExchange(());

impl VersionExchange {
    async fn advance(
        &self,
        exchange: &mut HandshakeHash,
        conn: &mut Connection,
    ) -> Result<KeyExchange, ()> {
        let ident_bytes =
            match Identification::read_from_stream(&mut conn.read, &mut conn.stream).await {
                Ok(ident_bytes) => ident_bytes,
                Err(error) => {
                    warn!(addr = %conn.addr, %error, "failed to read version exchange");
                    return Err(());
                }
            };
        let ident = match Identification::decode(&ident_bytes) {
            Ok(ident) => {
                debug!(addr = %conn.addr, ?ident, "received identification");
                ident
            }
            Err(error) => {
                warn!(addr = %conn.addr, %error, "failed to read version exchange");
                return Err(());
            }
        };

        if ident.protocol != PROTOCOL {
            warn!(addr = %conn.addr, ?ident, "unsupported protocol version");
            return Err(());
        }

        exchange.prefixed(&ident_bytes);

        let ident = Identification::outgoing();
        ident.encode(&mut conn.write_buf);
        if let Err(error) = conn.stream.write_all(&conn.write_buf).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(());
        }

        let v_s_len = conn.write_buf.len() - 2;
        if let Some(v_s) = conn.write_buf.get(..v_s_len) {
            exchange.prefixed(v_s);
        }

        Ok(KeyExchange::default())
    }
}

#[derive(Debug)]
struct Identification<'a> {
    protocol: &'a str,
    software: &'a str,
    comments: &'a str,
}

impl Identification<'_> {
    fn outgoing() -> Self {
        Self {
            protocol: PROTOCOL,
            software: SOFTWARE,
            comments: "",
        }
    }
}

impl<'a> Identification<'a> {
    /// Read the identification string as raw bytes with the CRLF stripped off.
    async fn read_from_stream(
        read: &mut ReadState,
        stream: &mut (impl AsyncReadExt + Unpin),
    ) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(256);
        let mut ident = vec![];
        loop {
            if buf.is_empty() && stream.read_buf(&mut buf).await? == 0 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF",
                )));
            }
            ident.push(buf.remove(0));
            if ident.len() > 255 {
                return Err(IdentificationError::TooLong.into());
            }
            if let Some((_, b"\r\n")) = ident.split_last_chunk::<2>() {
                ident.pop().unwrap();
                ident.pop().unwrap();
                break;
            }
        }
        debug!(bytes = ident.len(), "read from stream");

        // Give all data we read but isn't part of the identification string to the ReadState.
        read.buf.extend(buf);

        Ok(ident)
    }

    fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let Ok(message) = str::from_utf8(bytes) else {
            return Err(IdentificationError::InvalidUtf8.into());
        };

        let Some(rest) = message.strip_prefix("SSH-") else {
            return Err(IdentificationError::NoSsh.into());
        };

        let Some((protocol, rest)) = rest.split_once('-') else {
            return Err(IdentificationError::NoVersion.into());
        };

        let (software, comments) = match rest.split_once(' ') {
            Some((software, comments)) => (software, comments),
            None => (rest, ""),
        };

        Ok(Self {
            protocol,
            software,
            comments,
        })
    }
}

impl Encode for Identification<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"SSH-");
        buf.extend_from_slice(self.protocol.as_bytes());
        buf.push(b'-');
        buf.extend_from_slice(self.software.as_bytes());
        if !self.comments.is_empty() {
            buf.push(b' ');
            buf.extend_from_slice(self.comments.as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("failed to get random bytes")]
    FailedRandomBytes,
    #[error("failed to parse identification: {0}")]
    Identification(#[from] IdentificationError),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("incomplete message: {0:?}")]
    Incomplete(Option<usize>),
    #[error("invalid packet: {0}")]
    InvalidPacket(&'static str),
    #[error("no common {0} algorithms")]
    NoCommonAlgorithm(&'static str),
    #[error("unreachable code: {0}")]
    Unreachable(&'static str),
}

#[derive(Debug, Error)]
enum IdentificationError {
    #[error("Invalid UTF-8")]
    InvalidUtf8,
    #[error("No SSH prefix")]
    NoSsh,
    #[error("No version found")]
    NoVersion,
    #[error("Identification too long")]
    TooLong,
}

const PROTOCOL: &str = "2.0";
const SOFTWARE: &str = concat!("OxiSH/", env!("CARGO_PKG_VERSION"));
