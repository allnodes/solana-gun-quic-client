//! Unencrypted QUIC: a `quinn_proto::crypto::Session` with no-op keys and a
//! checksum-only packet tag, on a private QUIC version.
//!
//! No secrecy and no server authentication: anyone on the path can read, forge or
//! reset these connections, and the client's source address is not verified.
//!
//! The client sends its first stream in 0-RTT packets, assuming the compiled-in
//! `EARLY_*` limits until the server's real ones arrive. A server endpoint must:
//! - use [`endpoint_config`] (lists only [`VERSION`], so TLS clients get version
//!   negotiation instead of being dropped) on a port separate from any TLS endpoint;
//! - pass [`check_server_limits`] with its transport limits;
//! - accept with `incoming.accept()?.into_0rtt()` and read streams before
//!   establishment; never call `Incoming::retry()`.

use {
    bytes::BytesMut,
    quinn_proto::{
        ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
        crypto::{
            self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey,
            UnsupportedVersion,
        },
        transport_parameters::TransportParameters,
    },
    std::{any::Any, sync::Arc},
};

/// Private QUIC version of the unencrypted mode ("SG" + 0x0001). Not IETF
/// (0x0000xxxx), not a greasing value (0x?a?a?a?a).
pub const VERSION: u32 = 0x5347_0001;

/// Limits compiled into the client's early parameters; a server must offer at least
/// these (see [`check_server_limits`]). Until the connection is established the
/// client can use only these (and its initial congestion window).
pub const EARLY_MAX_UNI_STREAMS: u32 = 4;
pub const EARLY_MAX_BIDI_STREAMS: u32 = 4;
/// Per-stream send credit before establishment: one full-size (4096-byte) transaction.
pub const EARLY_STREAM_WINDOW: u32 = 4096;
/// Connection send credit before establishment: every early stream full.
pub const EARLY_CONN_WINDOW: u32 =
    (EARLY_MAX_UNI_STREAMS + EARLY_MAX_BIDI_STREAMS) * EARLY_STREAM_WINDOW;

/// Checks a server's transport limits against the compiled-in early ones. quinn
/// closes every connection whose real limits are lower ("0-RTT accepted with
/// incompatible transport parameters"), so a server checks this at startup.
pub fn check_server_limits(
    max_uni: u32,
    max_bidi: u32,
    stream_window: u64,
    conn_window: u64,
) -> Result<(), String> {
    let checks = [
        (
            "max_concurrent_uni_streams",
            u64::from(max_uni),
            EARLY_MAX_UNI_STREAMS,
        ),
        (
            "max_concurrent_bidi_streams",
            u64::from(max_bidi),
            EARLY_MAX_BIDI_STREAMS,
        ),
        ("stream_receive_window", stream_window, EARLY_STREAM_WINDOW),
        ("receive_window", conn_window, EARLY_CONN_WINDOW),
    ];
    for (name, value, early) in checks {
        if value < u64::from(early) {
            return Err(format!(
                "unencrypted QUIC: server {name} = {value} is below the client's compiled-in \
                 early limit {early}"
            ));
        }
    }
    Ok(())
}

/// Server parameters the client assumes for its first flight (RFC 9000 ids).
const EARLY_PARAMS: [(u64, u64); 6] = [
    (0x04, EARLY_CONN_WINDOW as u64),      // initial_max_data
    (0x05, 0),                             // initial_max_stream_data_bidi_local
    (0x06, EARLY_STREAM_WINDOW as u64),    // initial_max_stream_data_bidi_remote
    (0x07, EARLY_STREAM_WINDOW as u64),    // initial_max_stream_data_uni
    (0x08, EARLY_MAX_BIDI_STREAMS as u64), // initial_max_streams_bidi
    (0x09, EARLY_MAX_UNI_STREAMS as u64),  // initial_max_streams_uni
];

fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn read_varint(buf: &mut &[u8]) -> Option<u64> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for b in &buf[1..len] {
        v = (v << 8) | u64::from(*b);
    }
    *buf = &buf[len..];
    Some(v)
}

fn early_params_wire() -> Vec<u8> {
    let mut out = Vec::new();
    for (id, value) in EARLY_PARAMS {
        let mut v = Vec::new();
        write_varint(&mut v, value);
        write_varint(&mut out, id);
        write_varint(&mut out, v.len() as u64);
        out.extend_from_slice(&v);
    }
    out
}

// `TransportParameters` fields are crate-private: build it from the wire form.
fn early_transport_parameters() -> TransportParameters {
    TransportParameters::read(Side::Client, &mut &early_params_wire()[..])
        .expect("compiled-in early parameters are valid")
}

/// Checks encoded server transport parameters against `EARLY_PARAMS`; absent ids
/// take the RFC default 0.
fn check_server_params_wire(mut wire: &[u8]) -> Result<(), String> {
    let mut found = [0u64; 16];
    while !wire.is_empty() {
        let id = read_varint(&mut wire).ok_or("malformed id")?;
        let len = read_varint(&mut wire).ok_or("malformed len")? as usize;
        if wire.len() < len {
            return Err("truncated".into());
        }
        let (mut value, rest) = wire.split_at(len);
        if (0x04..=0x09).contains(&id) {
            found[id as usize] = read_varint(&mut value).ok_or("malformed value")?;
        }
        wire = rest;
    }
    for (id, early) in EARLY_PARAMS {
        if found[id as usize] < early {
            return Err(format!(
                "server transport parameter {id:#x} = {} is below the early value {early}",
                found[id as usize]
            ));
        }
    }
    Ok(())
}

fn protocol_violation(reason: &str) -> TransportError {
    TransportError {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame: None,
        reason: reason.into(),
    }
}

// --- control messages ---------------------------------------------------------
// CRYPTO-data framing: "SGPT" | type u8 | body length u16 BE | body.

const MAGIC: [u8; 4] = *b"SGPT";
const MSG_HEADER_LEN: usize = 4 + 1 + 2;
const MSG_CLIENT_HELLO: u8 = 1;
const MSG_SERVER_HELLO: u8 = 2;
const MSG_SERVER_DONE: u8 = 3;
const MSG_CLIENT_DONE: u8 = 4;

fn encode_msg(buf: &mut Vec<u8>, ty: u8, body: &[u8]) {
    let len = u16::try_from(body.len()).expect("control message body fits u16");
    buf.extend_from_slice(&MAGIC);
    buf.push(ty);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(body);
}

/// The first complete message in `buf` as `(type, total length)`; `None` while incomplete.
fn decode_msg(buf: &[u8]) -> Result<Option<(u8, usize)>, TransportError> {
    if buf.len() < MSG_HEADER_LEN {
        return Ok(None);
    }
    if buf[..4] != MAGIC {
        return Err(protocol_violation("bad plaintext handshake magic"));
    }
    let len = MSG_HEADER_LEN + usize::from(u16::from_be_bytes([buf[5], buf[6]]));
    Ok((buf.len() >= len).then_some((buf[4], len)))
}

// --- keys -------------------------------------------------------------------

const TAG_LEN: usize = 16;
// Header protection is off; quinn's minimum-packet-length logic still uses the sample size.
const SAMPLE_LEN: usize = 16;

const K1: u64 = 0x9E37_79B9_7F4A_7C15;
const K2: u64 = 0xC2B2_AE3D_27D4_EB4F;

const fn fmix(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^ (h >> 33)
}

/// 16-byte integrity checksum over packet number, header and payload.
/// Detects corruption only; it is not a MAC.
fn checksum(pn: u64, header: &[u8], payload: &[u8]) -> [u8; TAG_LEN] {
    let mut a = K1 ^ pn;
    let mut b = K2 ^ pn.rotate_left(32);
    for part in [header, payload] {
        let mut chunks = part.chunks_exact(8);
        for c in &mut chunks {
            let w = u64::from_le_bytes(c.try_into().unwrap());
            a = (a ^ w).wrapping_mul(K1).rotate_left(29);
            b = b.wrapping_add(w).wrapping_mul(K2).rotate_left(31);
        }
        let rem = chunks.remainder();
        let mut t = [0u8; 8];
        t[..rem.len()].copy_from_slice(rem);
        let w = u64::from_le_bytes(t) ^ ((part.len() as u64) << 40);
        a = (a ^ w).wrapping_mul(K1).rotate_left(29);
        b = b.wrapping_add(w).wrapping_mul(K2).rotate_left(31);
    }
    let mut out = [0u8; TAG_LEN];
    out[..8].copy_from_slice(&fmix(a ^ b.rotate_left(17)).to_le_bytes());
    out[8..].copy_from_slice(&fmix(b ^ a.rotate_left(43)).to_le_bytes());
    out
}

/// No encryption; the tag is a checksum.
struct PlainPacketKey;

impl PacketKey for PlainPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let tag_start = buf.len() - TAG_LEN;
        let (data, tag) = buf.split_at_mut(tag_start);
        let (header, payload) = data.split_at(header_len);
        tag.copy_from_slice(&checksum(packet, header, payload));
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let body_len = payload.len().checked_sub(TAG_LEN).ok_or(CryptoError)?;
        if checksum(packet, header, &payload[..body_len]) != payload[body_len..] {
            return Err(CryptoError);
        }
        payload.truncate(body_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        1 << 52
    }
}

struct PlainHeaderKey;

impl HeaderKey for PlainHeaderKey {
    fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}
    fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}
    fn sample_size(&self) -> usize {
        SAMPLE_LEN
    }
}

fn plain_keys() -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(PlainHeaderKey),
            remote: Box::new(PlainHeaderKey),
        },
        packet: KeyPair {
            local: Box::new(PlainPacketKey),
            remote: Box::new(PlainPacketKey),
        },
    }
}

// --- session ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Client: hello not yet written.
    ClientStart,
    /// Client: hello written, waiting for the server's Initial message.
    ClientWaitHello,
    /// Client: server hello read; next write hands out Handshake keys.
    ClientHaveHello,
    /// Client: waiting for the server's Handshake "done".
    ClientWaitDone,
    /// Client: "done" read; next write sends ours and hands out 1-RTT keys.
    ClientGotDone,
    ServerWaitHello,
    /// Server: client hello read; next write sends hello + Handshake keys.
    ServerHaveHello,
    /// Server: hello sent; next write sends "done" + 1-RTT keys.
    ServerHelloSent,
    /// Server: waiting for the client's Handshake "done".
    ServerWaitDone,
    Complete,
}

/// `handshake_data()` of an unencrypted connection (nothing is negotiated).
#[derive(Debug, Clone, Copy)]
pub struct PlaintextHandshakeData;

struct PlaintextSession {
    side: Side,
    state: State,
    local_params: Vec<u8>,
    peer_params: Option<TransportParameters>,
    /// Client only: compiled-in server parameters for the first flight.
    early_params: Option<TransportParameters>,
    rx: Vec<u8>,
    got_handshake_data: bool,
}

impl PlaintextSession {
    fn new(side: Side, params: &TransportParameters) -> Self {
        let mut local_params = Vec::new();
        params.write(&mut local_params);
        Self {
            side,
            state: if side.is_client() {
                State::ClientStart
            } else {
                State::ServerWaitHello
            },
            local_params,
            peer_params: None,
            early_params: side.is_client().then(early_transport_parameters),
            rx: Vec::new(),
            got_handshake_data: false,
        }
    }

    fn on_msg(&mut self, ty: u8, body: &[u8]) -> Result<bool, TransportError> {
        match (self.state, ty) {
            (State::ClientWaitHello, MSG_SERVER_HELLO)
            | (State::ServerWaitHello, MSG_CLIENT_HELLO) => {
                self.peer_params = Some(TransportParameters::read(self.side, &mut &body[..])?);
                self.state = if self.side.is_client() {
                    State::ClientHaveHello
                } else {
                    State::ServerHaveHello
                };
                let first = !self.got_handshake_data;
                self.got_handshake_data = true;
                Ok(first)
            }
            (State::ClientWaitDone, MSG_SERVER_DONE) if body.is_empty() => {
                self.state = State::ClientGotDone;
                Ok(false)
            }
            (State::ServerWaitDone, MSG_CLIENT_DONE) if body.is_empty() => {
                self.state = State::Complete;
                Ok(false)
            }
            _ => Err(protocol_violation("unexpected plaintext handshake message")),
        }
    }
}

impl crypto::Session for PlaintextSession {
    fn initial_keys(&self, _dst_cid: &ConnectionId, _side: Side) -> Keys {
        plain_keys()
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.got_handshake_data
            .then(|| Box::new(PlaintextHandshakeData) as Box<dyn Any>)
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        Some((Box::new(PlainHeaderKey), Box::new(PlainPacketKey)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.side.is_client().then_some(true)
    }

    fn is_handshaking(&self) -> bool {
        self.state != State::Complete
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.rx.extend_from_slice(buf);
        let mut ready = false;
        while let Some((ty, len)) = decode_msg(&self.rx)? {
            let body = self.rx[MSG_HEADER_LEN..len].to_vec();
            self.rx.drain(..len);
            ready |= self.on_msg(ty, &body)?;
        }
        Ok(ready)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        // Client: compiled-in values until the server's real ones arrive.
        Ok(self.peer_params.or(self.early_params))
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        match self.state {
            State::ClientStart => {
                encode_msg(buf, MSG_CLIENT_HELLO, &self.local_params);
                self.state = State::ClientWaitHello;
                None
            }
            State::ClientHaveHello => {
                self.state = State::ClientWaitDone;
                Some(plain_keys())
            }
            State::ClientGotDone => {
                encode_msg(buf, MSG_CLIENT_DONE, &[]);
                self.state = State::Complete;
                Some(plain_keys())
            }
            State::ServerHaveHello => {
                encode_msg(buf, MSG_SERVER_HELLO, &self.local_params);
                self.state = State::ServerHelloSent;
                Some(plain_keys())
            }
            State::ServerHelloSent => {
                encode_msg(buf, MSG_SERVER_DONE, &[]);
                self.state = State::ServerWaitDone;
                Some(plain_keys())
            }
            _ => None,
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        // quinn starts key updates itself; there must always be a next key.
        Some(KeyPair {
            local: Box::new(PlainPacketKey),
            remote: Box::new(PlainPacketKey),
        })
    }

    fn is_valid_retry(
        &self,
        _orig_dst_cid: &ConnectionId,
        _header: &[u8],
        _payload: &[u8],
    ) -> bool {
        false
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        Err(ExportKeyingMaterialError)
    }
}

// --- configs ----------------------------------------------------------------

struct PlaintextClientConfig;

impl crypto::ClientConfig for PlaintextClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if version != VERSION {
            return Err(ConnectError::UnsupportedVersion);
        }
        Ok(Box::new(PlaintextSession::new(Side::Client, params)))
    }
}

struct PlaintextServerConfig;

impl crypto::ServerConfig for PlaintextServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        _dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        if version != VERSION {
            return Err(UnsupportedVersion);
        }
        Ok(plain_keys())
    }

    fn retry_tag(&self, _version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Never used: this port does not send Retry.
        checksum(0, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let session = PlaintextSession::new(Side::Server, params);
        debug_assert!(check_server_params_wire(&session.local_params).is_ok());
        Box::new(session)
    }
}

/// Client config: version [`VERSION`], no-op crypto, early data on. The caller sets
/// the transport config.
pub fn client_config() -> quinn::ClientConfig {
    let mut cfg = quinn::ClientConfig::new(Arc::new(PlaintextClientConfig));
    cfg.version(VERSION);
    cfg
}

/// Server crypto for `quinn::ServerConfig::with_crypto`.
pub fn server_crypto() -> Arc<dyn quinn::crypto::ServerConfig> {
    Arc::new(PlaintextServerConfig)
}

/// Endpoint config listing only [`VERSION`]. Listing QUIC v1 as well would make
/// quinn silently drop TLS clients instead of sending version negotiation.
pub fn endpoint_config() -> quinn::EndpointConfig {
    let mut cfg = quinn::EndpointConfig::default();
    cfg.supported_versions(vec![VERSION]);
    cfg
}

#[cfg(test)]
mod tests {
    use {super::*, quinn_proto::crypto::Session};

    #[test]
    fn early_params_decode_and_match_the_constants() {
        let _ = early_transport_parameters();
        assert!(check_server_params_wire(&early_params_wire()).is_ok());
        let mut low = Vec::new();
        write_varint(&mut low, 0x09);
        write_varint(&mut low, 1);
        write_varint(&mut low, u64::from(EARLY_MAX_UNI_STREAMS) - 1);
        assert!(check_server_params_wire(&low).is_err());
    }

    #[test]
    fn server_limits_check_names_the_failing_limit() {
        assert!(check_server_limits(4, 4, 4096, 32_768).is_ok());
        // Gun's smallest passing config: 4 streams, window MAX_TX_BYTES + 1.
        assert!(check_server_limits(4, 4, 4097, 4097 * 2 * 4).is_ok());
        let cases = [
            ((3, 4, 4096, 32_768), "max_concurrent_uni_streams"),
            ((4, 3, 4096, 32_768), "max_concurrent_bidi_streams"),
            ((4, 4, 4095, 32_768), "stream_receive_window"),
            ((4, 4, 4096, 32_767), "receive_window"),
        ];
        for ((u, b, s, c), name) in cases {
            let err = check_server_limits(u, b, s, c).unwrap_err();
            assert!(err.contains(&format!("server {name} =")), "{err}");
        }
    }

    #[test]
    fn varint_round_trips() {
        for v in [
            0,
            63,
            64,
            16_383,
            16_384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            let mut r = &out[..];
            assert_eq!(read_varint(&mut r), Some(v));
            assert!(r.is_empty());
        }
        assert_eq!(read_varint(&mut &[0x40][..]), None);
    }

    #[test]
    fn message_encode_decode() {
        let mut buf = Vec::new();
        encode_msg(&mut buf, MSG_SERVER_HELLO, b"params");
        assert_eq!(&buf[..7], b"SGPT\x02\x00\x06");
        assert_eq!(decode_msg(&buf).unwrap(), Some((MSG_SERVER_HELLO, 13)));
        for cut in 0..buf.len() {
            assert_eq!(decode_msg(&buf[..cut]).unwrap(), None, "cut {cut}");
        }
        encode_msg(&mut buf, MSG_SERVER_DONE, &[]);
        assert_eq!(decode_msg(&buf[13..]).unwrap(), Some((MSG_SERVER_DONE, 7)));
        let mut bad = buf.clone();
        bad[0] = b'X';
        assert!(decode_msg(&bad).is_err());
    }

    #[test]
    fn checksum_detects_corruption() {
        let key = PlainPacketKey;
        let mut buf = vec![7u8; 100 + TAG_LEN];
        key.encrypt(5, &mut buf, 20);
        let header = buf[..20].to_vec();
        let mut payload = BytesMut::from(&buf[20..]);
        let mut ok = payload.clone();
        assert!(key.decrypt(5, &header, &mut ok).is_ok());
        assert_eq!(&ok[..], &[7u8; 80][..], "tag stripped, payload untouched");
        // Wrong packet number, flipped payload, header or tag bit.
        assert!(key.decrypt(6, &header, &mut payload.clone()).is_err());
        let mut h = header.clone();
        h[0] ^= 1;
        assert!(key.decrypt(5, &h, &mut payload.clone()).is_err());
        payload[3] ^= 1;
        assert!(key.decrypt(5, &header, &mut payload).is_err());
        let mut t = BytesMut::from(&buf[20..]);
        let last = t.len() - 1;
        t[last] ^= 0x80;
        assert!(key.decrypt(5, &header, &mut t).is_err());
        assert!(
            key.decrypt(5, &header, &mut BytesMut::from(&[0u8; 3][..]))
                .is_err()
        );
        assert_ne!(checksum(1, b"", b""), checksum(2, b"", b""));
    }

    #[test]
    fn control_exchange_completes() {
        let params = early_transport_parameters();
        let mut client = PlaintextSession::new(Side::Client, &params);
        let mut server = PlaintextSession::new(Side::Server, &params);
        assert!(client.early_crypto().is_some());
        assert!(
            client.transport_parameters().unwrap().is_some(),
            "early params"
        );

        // 1. client hello (Initial), no keys.
        let mut hello = Vec::new();
        assert!(client.write_handshake(&mut hello).is_none());
        assert!(
            server.read_handshake(&hello).unwrap(),
            "handshake data ready"
        );
        // 2. server hello + Handshake keys, then done + 1-RTT keys.
        let mut s_hello = Vec::new();
        assert!(server.write_handshake(&mut s_hello).is_some());
        let mut s_done = Vec::new();
        assert!(server.write_handshake(&mut s_done).is_some());
        assert!(server.write_handshake(&mut Vec::new()).is_none());
        // 3. client: hello split across two reads, then done.
        let (a, b) = s_hello.split_at(5);
        assert!(!client.read_handshake(a).unwrap());
        assert!(client.read_handshake(b).unwrap());
        assert!(client.write_handshake(&mut Vec::new()).is_some());
        client.read_handshake(&s_done).unwrap();
        let mut c_done = Vec::new();
        assert!(client.write_handshake(&mut c_done).is_some());
        assert!(!client.is_handshaking());
        assert_eq!(client.early_data_accepted(), Some(true));
        // 4. server done.
        assert!(server.is_handshaking());
        server.read_handshake(&c_done).unwrap();
        assert!(!server.is_handshaking());
        assert!(
            client
                .handshake_data()
                .unwrap()
                .is::<PlaintextHandshakeData>()
        );
        assert!(client.next_1rtt_keys().is_some());
        // Anything further is a protocol violation.
        assert!(server.read_handshake(&c_done).is_err());
    }
}
