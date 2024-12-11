use crate::tls::crypto::Hash;
use crate::tls::error::Error;
use crate::tls::error::ErrorCode;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EndpointType { Client, Server }

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    TLSv1_2 = 0x0303,
    TLSv1_3 = 0x0304,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256       = 0x1301,
    TLS_AES_256_GCM_SHA384       = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256       = 0x1304,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    x25519 = 0x001d,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    ed25519 = 0x0807,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExtensionType {
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

pub struct Config {
    endpoint_type: EndpointType,
    versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuite>,
    groups: Vec<NamedGroup>,
    sign_schemes: Vec<SignatureScheme>,
}

pub struct TlsSocket {
    endpoint_type: EndpointType,
    state: State,
    // selected
    version: Option<ProtocolVersion>,
    cipher_suite: Option<CipherSuite>,
    group: Option<NamedGroup>,
    sign_scheme: Option<SignatureScheme>,
    // client_random: [u8; 32],
    // server_random: [u8; 32],
    // send_aead_iv: [u8; 12],
    // recv_aead_iv: [u8; 12],
    // send_record_ctr: u64,
    // recv_record_ctr: u64,
    // send_aead: Aead,
    // recv_aead: Aead,
    transcript_hash: Option<Hash>,
}

impl Config {

    pub fn new(endpoint_type: EndpointType, versions: &[ProtocolVersion], cipher_suites: &[CipherSuite],
        groups: &[NamedGroup], sign_schemes: &[SignatureScheme]) -> Self {
        return Self{
            endpoint_type: endpoint_type,
            versions: versions.to_vec(),
            cipher_suites: cipher_suites.to_vec(),
            groups: groups.to_vec(),
            sign_schemes: sign_schemes.to_vec()
        };
    }

    pub fn push_version(&mut self, version: ProtocolVersion) {
        self.versions.push(version);
    }

    pub fn set_versions(&mut self, versions: &[ProtocolVersion]) {
        self.versions = versions.to_vec();
    }

    pub fn push_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.cipher_suites.push(cipher_suite);
    }

    pub fn set_cipher_suites(&mut self, cipher_suites: &[CipherSuite]) {
        self.cipher_suites = cipher_suites.to_vec();
    }

    pub fn push_group(&mut self, group: NamedGroup) {
        self.groups.push(group);
    }

    pub fn set_groups(&mut self, groups: &[NamedGroup]) {
        self.groups = groups.to_vec();
    }

    pub fn push_sign_scheme(&mut self, sign_scheme: SignatureScheme) {
        self.sign_schemes.push(sign_scheme);
    }

    pub fn set_sign_schemes(&mut self, sign_schemes: &[SignatureScheme]) {
        self.sign_schemes = sign_schemes.to_vec();
    }

}

impl TlsSocket {

    pub fn new(config: &Config) -> Result<Self, Error> {
        return Ok(Self{
            endpoint_type: config.endpoint_type,
            state: match config.endpoint_type {
                EndpointType::Client => State::Client(ClientState::START),
                EndpointType::Server => State::Server(ServerState::START),
            },
            version: None,
            cipher_suite: None,
            group: None,
            sign_scheme: None,
            transcript_hash: None
        });
    }

    pub fn handshake_send(&mut self, buf: &mut [u8]) {}
    pub fn handshake_recv(&mut self, buf: &mut [u8]) {}

    pub fn application_send(&mut self, buf: &mut [u8]) {}
    pub fn application_recv(&mut self, buf: &mut [u8]) {}

    pub fn transport_send(&mut self, buf: &mut [u8]) {}
    pub fn transport_recv(&mut self, buf: &mut [u8]) {}

}