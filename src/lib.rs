use core::net::SocketAddr;
use std::{io, str, sync::Arc};

use aws_lc_rs::{
    cipher::{self, StreamingDecryptingKey, StreamingEncryptingKey, UnboundCipherKey},
    hmac,
    signature::Ed25519KeyPair,
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, warn};

mod key_exchange;
use key_exchange::KeyExchange;
mod proto;
use proto::{Decode, Decoded, MessageType, ReadState, WriteState};

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
    write: WriteState,
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
            write: WriteState::new(),
        })
    }

    /// Drive the connection forward
    pub async fn run(mut self) {
        let mut exchange = HandshakeHash::default();
        let state = VersionExchange::default();
        let Ok(state) = state.advance(&mut exchange, &mut self).await else {
            return;
        };

        let packet = match self.read.read_packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read packet");
                return;
            }
        };
        exchange.prefixed(packet.payload);
        let peer_key_exchange_init = match KeyExchangeInit::try_from(packet) {
            Ok(key_exchange_init) => key_exchange_init,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read key exchange init");
                return;
            }
        };

        let mut cx = ConnectionContext {
            addr: self.addr,
            host_key: &self.host_key,
        };

        let Ok((key_exchange_init, state)) = state.advance(peer_key_exchange_init, &mut cx) else {
            return;
        };

        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &key_exchange_init, |kex_init_payload| {
                exchange.update(&(kex_init_payload.len() as u32).to_be_bytes());
                exchange.update(kex_init_payload);
            })
            .await
        {
            warn!(addr = %self.addr, %error, "failed to send key exchange init packet");
            return;
        }

        let packet = match self.read.read_packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read packet");
                return;
            }
        };
        let Ok(ecdh_key_exchange_init) = EcdhKeyExchangeInit::try_from(packet) else {
            return;
        };

        let mut cx = ConnectionContext {
            addr: self.addr,
            host_key: &self.host_key,
        };

        let Ok((key_exchange_reply, keys)) =
            state.advance(ecdh_key_exchange_init, exchange, &mut cx)
        else {
            return;
        };

        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &key_exchange_reply, |_| {})
            .await
        {
            warn!(addr = %self.addr, %error, "failed to send key exchange init packet");
            return;
        }

        let packet = match self.read.read_packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read packet");
                return;
            }
        };
        let r#type = match MessageType::decode(packet.payload) {
            Ok(Decoded {
                value: r#type,
                next: _,
            }) => r#type,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read packet type");
                return;
            }
        };
        if r#type != MessageType::NewKeys {
            warn!(addr = %self.addr,  "unexpected message type {:?}", r#type);
            return;
        }

        if let Err(error) = self
            .write
            .write_packet(&mut self.stream, &MessageType::NewKeys, |_| {})
            .await
        {
            warn!(addr = %self.addr, %error, "failed to send newkeys packet");
            return;
        }

        self.read.decryption_key = Some((
            StreamingDecryptingKey::ctr(
                UnboundCipherKey::new(
                    &cipher::AES_128,
                    &keys.client_to_server.encryption_key.derive::<16>(),
                )
                .unwrap(),
                cipher::DecryptionContext::Iv128(
                    keys.client_to_server.initial_iv.derive::<16>().into(),
                ),
            )
            .unwrap(),
            hmac::Key::new(
                hmac::HMAC_SHA256,
                &keys.client_to_server.integrity_key.derive::<32>(),
            ),
        ));

        self.write.set_encryption_key(
            StreamingEncryptingKey::less_safe_ctr(
                UnboundCipherKey::new(
                    &cipher::AES_128,
                    &keys.server_to_client.encryption_key.derive::<16>(),
                )
                .unwrap(),
                cipher::EncryptionContext::Iv128(
                    keys.server_to_client.initial_iv.derive::<16>().into(),
                ),
            )
            .unwrap(),
            hmac::Key::new(
                hmac::HMAC_SHA256,
                &keys.server_to_client.integrity_key.derive::<32>(),
            ),
        );

        let packet = match self.read.read_packet(&mut self.stream).await {
            Ok(packet) => packet,
            Err(error) => {
                warn!(addr = %self.addr, %error, "failed to read packet");
                return;
            }
        };
        debug!("packet data: {:x?}", packet.payload);

        self.write
            .write_packet(&mut self.stream, &MessageType::Ignore, |_| {})
            .await
            .unwrap();
    }
}

struct ConnectionContext<'a> {
    addr: SocketAddr,
    host_key: &'a Ed25519KeyPair,
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
        let server_ident_bytes = ident.encode();
        if let Err(error) = conn.stream.write_all(&server_ident_bytes).await {
            warn!(addr = %conn.addr, %error, "failed to send version exchange");
            return Err(());
        }

        let v_s_len = server_ident_bytes.len() - 2;
        if let Some(v_s) = server_ident_bytes.get(..v_s_len) {
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
        read.incoming_buf().extend(buf);

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

    fn encode(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(b"SSH-");
        buf.extend_from_slice(self.protocol.as_bytes());
        buf.push(b'-');
        buf.extend_from_slice(self.software.as_bytes());
        if !self.comments.is_empty() {
            buf.push(b' ');
            buf.extend_from_slice(self.comments.as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        buf
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
    #[error("invalid mac for packet")]
    InvalidMac,
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
