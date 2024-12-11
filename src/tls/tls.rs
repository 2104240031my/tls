use crate::tls::crypto::Hash;
use crate::tls::error::TlsError;
use crate::tls::error::TlsErrorCode;

const HS_HEADER_LEN: usize            = HandshakeType::BYTES_LEN + 3;
const CH_RANDOM_LEN: usize            = 32;
const CH_LEGACY_SESSION_ID_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TlsEndpointType { Client, Server }

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TlsProtocolVersion {
    TLSv1_2 = 0x0303,
    TLSv1_3 = 0x0304,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TlsCipherSuite {
    TLS_AES_128_GCM_SHA256       = 0x1301,
    TLS_AES_256_GCM_SHA384       = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256       = 0x1304,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TlsNamedGroup {
    x25519 = 0x001d,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TlsSignatureScheme {
    ed25519 = 0x0807,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TlsExtensionType {
    server_name                            = 0,  // RFC 6066
    status_request                         = 5,  // RFC 6066
    supported_groups                       = 10, // RFC 8422, 7919
    signature_algorithms                   = 13, // RFC 8446
    application_layer_protocol_negotiation = 16, // RFC 7301
    signed_certificate_timestamp           = 18, // RFC 6962
    client_certificate_type                = 19, // RFC 7250
    server_certificate_type                = 20, // RFC 7250
    padding                                = 21, // RFC 7685
    pre_shared_key                         = 41, // RFC 8446
    early_data                             = 42, // RFC 8446
    supported_versions                     = 43, // RFC 8446
    cookie                                 = 44, // RFC 8446
    psk_key_exchange_modes                 = 45, // RFC 8446
    certificate_authorities                = 47, // RFC 8446
    oid_filters                            = 48, // RFC 8446
    post_handshake_auth                    = 49, // RFC 8446
    signature_algorithms_cert              = 50, // RFC 8446
    key_share                              = 51, // RFC 8446
}

enum State {
    Client(ClientState),
    Server(ServerState),
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClientState {
    START,
    WAIT_SH,
    WAIT_EE,
    WAIT_CERT_CR,
    WAIT_CERT,
    WAIT_CV,
    WAIT_FINISHED,
    CONNECTED,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ServerState {
    START,
    RECVD_CH,
    NEGOTIATED,
    WAIT_EOED,
    WAIT_FLIGHT2,
    WAIT_CERT,
    WAIT_CV,
    WAIT_FINISHED,
    CONNECTED,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum HandshakeType {
    client_hello            = 1,
    server_hello            = 2,
    new_session_ticket      = 4,
    end_of_early_data       = 5,
    encrypted_extensions    = 8,
    certificate             = 11,
    certificate_request     = 13,
    certificate_verify      = 15,
    finished                = 20,
    key_update              = 24,
    message_hash            = 254,
    end_handshake_type_enum = 255
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum LegacyCompressionMethod { NULL = 0x00 }

pub struct TlsConfig {
    endpoint_type: TlsEndpointType,
    versions: Vec<TlsProtocolVersion>,
    cipher_suites: Vec<TlsCipherSuite>,
    groups: Vec<TlsNamedGroup>,
    sign_schemes: Vec<TlsSignatureScheme>,
}

pub struct TlsSocket {
    endpoint_type: TlsEndpointType,
    state: State,
    // selected
    version: Option<TlsProtocolVersion>,
    cipher_suite: Option<TlsCipherSuite>,
    group: Option<TlsNamedGroup>,
    sign_scheme: Option<TlsSignatureScheme>,
    // client_random: [u8; 32],
    // server_random: [u8; 32],
    // send_aead_iv: [u8; 12],
    // recv_aead_iv: [u8; 12],
    // send_record_ctr: u64,
    // recv_record_ctr: u64,
    // send_aead: Aead,
    // recv_aead: Aead,
    transcript_hash: Option<Hash>,
    config: TlsConfig,
}

impl TlsProtocolVersion {
    pub const BYTES_LEN: usize = 2;
}

impl TlsCipherSuite {
    pub const BYTES_LEN: usize = 2;
}

impl TlsNamedGroup {
    pub const BYTES_LEN: usize = 2;
}

impl TlsSignatureScheme {
    pub const BYTES_LEN: usize = 2;
}

impl HandshakeType {
    const BYTES_LEN: usize = 1;
}

impl LegacyCompressionMethod {
    const BYTES_LEN: usize = 1;
}

impl TlsConfig {

    pub fn new(endpoint_type: TlsEndpointType, versions: &[TlsProtocolVersion],
        cipher_suites: &[TlsCipherSuite], groups: &[TlsNamedGroup],
        sign_schemes: &[TlsSignatureScheme]) -> Self {
        return Self{
            endpoint_type: endpoint_type,
            versions: versions.to_vec(),
            cipher_suites: cipher_suites.to_vec(),
            groups: groups.to_vec(),
            sign_schemes: sign_schemes.to_vec()
        };
    }

    pub fn push_version(&mut self, version: TlsProtocolVersion) {
        self.versions.push(version);
    }

    pub fn set_versions(&mut self, versions: &[TlsProtocolVersion]) {
        self.versions = versions.to_vec();
    }

    pub fn push_cipher_suite(&mut self, cipher_suite: TlsCipherSuite) {
        self.cipher_suites.push(cipher_suite);
    }

    pub fn set_cipher_suites(&mut self, cipher_suites: &[TlsCipherSuite]) {
        self.cipher_suites = cipher_suites.to_vec();
    }

    pub fn push_group(&mut self, group: TlsNamedGroup) {
        self.groups.push(group);
    }

    pub fn set_groups(&mut self, groups: &[TlsNamedGroup]) {
        self.groups = groups.to_vec();
    }

    pub fn push_sign_scheme(&mut self, sign_scheme: TlsSignatureScheme) {
        self.sign_schemes.push(sign_scheme);
    }

    pub fn set_sign_schemes(&mut self, sign_schemes: &[TlsSignatureScheme]) {
        self.sign_schemes = sign_schemes.to_vec();
    }

}

impl Clone for TlsConfig {

    fn clone(&self) -> Self {
        return Self{
            endpoint_type: self.endpoint_type,
            versions: self.versions.clone(),
            cipher_suites: self.cipher_suites.clone(),
            groups: self.groups.clone(),
            sign_schemes: self.sign_schemes.clone()
        };
    }

}

impl TlsSocket {

    pub fn new(config: &TlsConfig) -> Result<Self, TlsError> {
        return Ok(Self{
            endpoint_type: config.endpoint_type,
            state: match config.endpoint_type {
                TlsEndpointType::Client => State::Client(ClientState::START),
                TlsEndpointType::Server => State::Server(ServerState::START),
            },
            version: None,
            cipher_suite: None,
            group: None,
            sign_scheme: None,
            transcript_hash: None,
            config: config.clone()
        });
    }

    pub fn handshake_send(&mut self, buf: &mut [u8]) {}
    pub fn handshake_recv(&mut self, buf: &mut [u8]) {}

    pub fn application_send(&mut self, buf: &mut [u8]) {}
    pub fn application_recv(&mut self, buf: &mut [u8]) {}

    pub fn transport_send(&mut self, buf: &mut [u8]) {}
    pub fn transport_recv(&mut self, buf: &mut [u8]) {}

    fn send_client_hello(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {

        let client_hello_len: usize =
            2 +
            CH_RANDOM_LEN +
            1 + CH_LEGACY_SESSION_ID_LEN +
            2 + (TlsCipherSuite::BYTES_LEN * self.config.cipher_suites.len()) +
            1 + LegacyCompressionMethod::BYTES_LEN;
        // client_hello_len = client_hello_len + 2 + extensions_len;

        let hs_msg_len: usize = HS_HEADER_LEN + client_hello_len;

        if buf.len() < hs_msg_len {
            return Err(TlsError::new(TlsErrorCode::BufferTooShort));
        }

        return Ok(hs_msg_len);

    }

}