use pkgcrypto::crypto::random::RandAes256;
use crate::tls::crypto::DiffieHellmanAlgorithm;
use crate::tls::crypto::DigitalSignatureAlgorithm;
use crate::tls::crypto::Hash;
use crate::tls::error::TLSError;
use crate::tls::error::TLSErrorCode;

const HS_HEADER_LEN: usize                     = TLSHandshakeType::BYTES_LEN + 3;
const CH_RANDOM_LEN: usize                     = 32;
const CH_LEGACY_SESSION_ID_LEN: usize          = 32;
const CH_LEGACY_COMPRESSION_METHODS_LEN: usize = 1;
const EXT_HDR_LEN: usize              = TLSExtensionType::BYTES_LEN + 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TLSRole { Client, Server }

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TLSProtocolVersion {
    TLSv1_2 = 0x0303,
    TLSv1_3 = 0x0304,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TLSCipherSuite {
    TLS_AES_128_GCM_SHA256       = 0x1301,
    TLS_AES_256_GCM_SHA384       = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256       = 0x1304,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TLSNamedGroup {
    x25519 = 0x001d,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TLSSignatureScheme {
    ed25519 = 0x0807,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TLSExtensionType {
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

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TLSContentType {
    invalid            = 0,
    change_cipher_spec = 20,
    alert              = 21,
    handshake          = 22,
    application_data   = 23,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TLSHandshakeType {
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
enum TLSLegacyCompressionMethod { null = 0x00 }

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TLSState {
    Initial,
    ClientHelloSent,
    ClientHelloRecvd,
    ServerHelloSent,
    ServerHelloRecvd,
    EncryptedExtensionsSent,
    EncryptedExtensionsRecvd,
    CertificateRequestSent,
    CertificateRequestRecvd,
    CertificateSent,
    CertificateRecvd,
    CertificateVerifySent,
    CertificateVerifyRecvd,
    FinishedSent,
    FinishedRecvd,
}

pub struct TLSConfig {
    role: TLSRole,
    versions: Vec<TLSProtocolVersion>,
    cipher_suites: Vec<TLSCipherSuite>,
    groups: Vec<TLSNamedGroup>,
    sign_schemes: Vec<TLSSignatureScheme>,
}

pub struct TLSSocket<'sock> {
    role: TLSRole,
    state: TLSState,
    // selected
    version: Option<TLSProtocolVersion>,
    cipher_suite: Option<TLSCipherSuite>,
    group: Option<TLSNamedGroup>,
    sign_scheme: Option<TLSSignatureScheme>,
    csprng: RandAes256,
    ke_priv_key: [u8; DiffieHellmanAlgorithm::MAX_PRIVATE_KEY_LEN],
    // client_random: [u8; 32],
    // server_random: [u8; 32],
    // send_aead_iv: [u8; 12],
    // recv_aead_iv: [u8; 12],
    // send_record_ctr: u64,
    // recv_record_ctr: u64,
    // send_aead: Aead,
    // recv_aead: Aead,
    transcript_hash: Option<Hash>,
    config: &'sock TLSConfig,
}

impl TLSProtocolVersion {
    pub const BYTES_LEN: usize = 2;
}

impl TLSCipherSuite {
    pub const BYTES_LEN: usize = 2;
}

impl TLSNamedGroup {
    pub const BYTES_LEN: usize = 2;

    fn to_dh_algorithm(&self) -> DiffieHellmanAlgorithm {
        return match self {
            Self::x25519 => DiffieHellmanAlgorithm::X25519,
        };
    }
}

impl TLSSignatureScheme {
    pub const BYTES_LEN: usize = 2;

    fn to_sign_algorithm(&self) -> DigitalSignatureAlgorithm {
        return match self {
            Self::ed25519 => DigitalSignatureAlgorithm::Ed25519,
        };
    }
}

impl TLSExtensionType {
    pub const BYTES_LEN: usize = 2;
}

impl TLSHandshakeType {
    const BYTES_LEN: usize = 1;
}

impl TLSLegacyCompressionMethod {
    const BYTES_LEN: usize = 1;
}

impl TLSConfig {

    pub fn new(role: TLSRole, versions: &[TLSProtocolVersion],
        cipher_suites: &[TLSCipherSuite], groups: &[TLSNamedGroup],
        sign_schemes: &[TLSSignatureScheme]) -> Self {
        return Self{
            role: role,
            versions: versions.to_vec(),
            cipher_suites: cipher_suites.to_vec(),
            groups: groups.to_vec(),
            sign_schemes: sign_schemes.to_vec()
        };
    }

    pub fn push_version(&mut self, version: TLSProtocolVersion) {
        self.versions.push(version);
    }

    pub fn set_versions(&mut self, versions: &[TLSProtocolVersion]) {
        self.versions = versions.to_vec();
    }

    pub fn push_cipher_suite(&mut self, cipher_suite: TLSCipherSuite) {
        self.cipher_suites.push(cipher_suite);
    }

    pub fn set_cipher_suites(&mut self, cipher_suites: &[TLSCipherSuite]) {
        self.cipher_suites = cipher_suites.to_vec();
    }

    pub fn push_group(&mut self, group: TLSNamedGroup) {
        self.groups.push(group);
    }

    pub fn set_groups(&mut self, groups: &[TLSNamedGroup]) {
        self.groups = groups.to_vec();
    }

    pub fn push_sign_scheme(&mut self, sign_scheme: TLSSignatureScheme) {
        self.sign_schemes.push(sign_scheme);
    }

    pub fn set_sign_schemes(&mut self, sign_schemes: &[TLSSignatureScheme]) {
        self.sign_schemes = sign_schemes.to_vec();
    }

}

impl<'sock> TLSSocket<'sock> {

    pub fn new<'conf: 'sock>(config: &'conf TLSConfig) -> Result<Self, TLSError> {
        return Ok(Self{
            role: config.role,
            state: TLSState::Initial,
            version: None,
            cipher_suite: None,
            group: None,
            sign_scheme: None,
            ke_priv_key: [0; DiffieHellmanAlgorithm::MAX_PRIVATE_KEY_LEN],
            csprng: RandAes256::new()?,
            transcript_hash: None,
            config: config
        });
    }

    pub fn handshake_send(&mut self, buf: &mut [u8]) -> Result<usize, TLSError> {

        let s: usize = match self.role {
            TLSRole::Client => match self.state {
                TLSState::Initial => self.send_client_hello(&mut buf[5..])?,
                _                 => return Err(TLSError::new(TLSErrorCode::UnsuitableState))
            },
            TLSRole::Server => 0
        };

        buf[0] = TLSContentType::handshake as u8;
        buf[1] = 0x03;
        buf[2] = 0x01;
        buf[3] = (s >> 8) as u8;
        buf[4] = s as u8;

        return Ok(5 + s);
    }

    pub fn handshake_recv(&mut self, buf: &mut [u8]) {}

    pub fn application_send(&mut self, buf: &mut [u8]) {}
    pub fn application_recv(&mut self, buf: &mut [u8]) {}

    pub fn transport_send(&mut self, buf: &mut [u8]) {}
    pub fn transport_recv(&mut self, buf: &mut [u8]) {}

    fn send_client_hello(&mut self, buf: &mut [u8]) -> Result<usize, TLSError> {

        let dh_algo: DiffieHellmanAlgorithm = self.config.groups[0].to_dh_algorithm();
        let dh_priv_key_len: usize = dh_algo.priv_key_len();
        let dh_pub_key_len: usize = dh_algo.pub_key_len();

        self.csprng.fill_bytes(&mut self.ke_priv_key[..dh_priv_key_len])?;

        let supported_versions_len: usize = TLSProtocolVersion::BYTES_LEN * self.config.versions.len();
        let supported_groups_len: usize = TLSNamedGroup::BYTES_LEN * self.config.groups.len();
        let signature_algorithms_len: usize = TLSSignatureScheme::BYTES_LEN * self.config.sign_schemes.len();
        let key_share_len: usize = TLSNamedGroup::BYTES_LEN + 2 + dh_pub_key_len;

        let extensions_len: usize =
            EXT_HDR_LEN + 1 + supported_versions_len +
            EXT_HDR_LEN + 2 + supported_groups_len +
            EXT_HDR_LEN + 2 + signature_algorithms_len +
            EXT_HDR_LEN + 2 + key_share_len;

        let cipher_suites_len: usize = TLSCipherSuite::BYTES_LEN * self.config.cipher_suites.len();

        let client_hello_len: usize =
            TLSProtocolVersion::BYTES_LEN +
            CH_RANDOM_LEN +
            1 + CH_LEGACY_SESSION_ID_LEN +
            2 + cipher_suites_len +
            1 + TLSLegacyCompressionMethod::BYTES_LEN +
            2 + extensions_len;

        let hs_msg_len: usize = HS_HEADER_LEN + client_hello_len;

        if buf.len() < hs_msg_len {
            return Err(TLSError::new(TLSErrorCode::BufferTooShort));
        }

        // handshake header
        buf[0] = TLSHandshakeType::client_hello as u8;
        buf[1] = (client_hello_len >> 16) as u8;
        buf[2] = (client_hello_len >> 8) as u8;
        buf[3] = client_hello_len as u8;

        // ClientHello.(legacy_)version = 0x0303 (TLS1.2)
        buf[4] = ((TLSProtocolVersion::TLSv1_2 as u16) >> 8) as u8;
        buf[5] = TLSProtocolVersion::TLSv1_2 as u8;

        let mut off: usize = 6 + CH_RANDOM_LEN;

        // ClientHello.random
        self.csprng.fill_bytes(&mut buf[6..off])?;

        // ClientHello.(legacy_)session_id
        buf[off] = CH_LEGACY_SESSION_ID_LEN as u8;
        off = off + 1;
        self.csprng.fill_bytes(&mut buf[off..(off + CH_LEGACY_SESSION_ID_LEN)])?;
        off = off + CH_LEGACY_SESSION_ID_LEN;

        // ClientHello.cipher_suites
        buf[off + 0] = (cipher_suites_len >> 8) as u8;
        buf[off + 1] = cipher_suites_len as u8;
        off = off + 2;
        for cipher_suite in &self.config.cipher_suites {
            let u: usize = (*cipher_suite) as usize;
            buf[off + 0] = (u >> 8) as u8;
            buf[off + 1] = u as u8;
            off = off + 2;
        }

        // ClientHello.(legacy_)compression_methods
        buf[off + 0] = CH_LEGACY_COMPRESSION_METHODS_LEN as u8;
        buf[off + 1] = TLSLegacyCompressionMethod::null as u8;
        off = off + 2;

        // ClientHello.extensions
        buf[off + 0] = (extensions_len >> 8) as u8;
        buf[off + 1] = extensions_len as u8;
        off = off + 2;

        // ClientHello.extensions.supported_versions
        buf[off + 0] = ((TLSExtensionType::supported_versions as usize) >> 8) as u8;
        buf[off + 1] = (TLSExtensionType::supported_versions as usize) as u8;
        buf[off + 2] = 0x00;
        buf[off + 3] = (supported_versions_len + 1) as u8;
        buf[off + 4] = supported_versions_len as u8;
        off = off + 5;
        for version in &self.config.versions {
            let u: usize = (*version) as usize;
            buf[off + 0] = (u >> 8) as u8;
            buf[off + 1] = u as u8;
            off = off + 2;
        }

        // ClientHello.extensions.supported_groups
        buf[off + 0] = ((TLSExtensionType::supported_groups as usize) >> 8) as u8;
        buf[off + 1] = (TLSExtensionType::supported_groups as usize) as u8;
        buf[off + 2] = ((supported_groups_len + 2) >> 8) as u8;
        buf[off + 3] = (supported_groups_len + 2) as u8;
        buf[off + 4] = (supported_groups_len >> 8) as u8;
        buf[off + 5] = supported_groups_len as u8;
        off = off + 6;
        for group in &self.config.groups {
            let u: usize = (*group) as usize;
            buf[off + 0] = (u >> 8) as u8;
            buf[off + 1] = u as u8;
            off = off + 2;
        }

        // ClientHello.extensions.signature_algorithms
        buf[off + 0] = ((TLSExtensionType::signature_algorithms as usize) >> 8) as u8;
        buf[off + 1] = (TLSExtensionType::signature_algorithms as usize) as u8;
        buf[off + 2] = ((signature_algorithms_len + 2) >> 8) as u8;
        buf[off + 3] = (signature_algorithms_len + 2) as u8;
        buf[off + 4] = (signature_algorithms_len >> 8) as u8;
        buf[off + 5] = signature_algorithms_len as u8;
        off = off + 6;
        for sign_scheme in &self.config.sign_schemes {
            let u: usize = (*sign_scheme) as usize;
            buf[off + 0] = (u >> 8) as u8;
            buf[off + 1] = u as u8;
            off = off + 2;
        }

        // ClientHello.extensions.key_share
        buf[off + 0] = ((TLSExtensionType::key_share as usize) >> 8) as u8;
        buf[off + 1] = (TLSExtensionType::key_share as usize) as u8;
        buf[off + 2] = ((key_share_len + 2) >> 8) as u8;
        buf[off + 3] = (key_share_len + 2) as u8;
        buf[off + 4] = (key_share_len >> 8) as u8;
        buf[off + 5] = key_share_len as u8;
        buf[off + 6] = ((self.config.groups[0] as usize) >> 8) as u8;
        buf[off + 7] = (self.config.groups[0] as usize) as u8;
        buf[off + 8] = (dh_pub_key_len >> 8) as u8;
        buf[off + 9] = dh_pub_key_len as u8;
        off = off + 10;
        dh_algo.compute_public_key_oneshot(
            &self.ke_priv_key[..dh_priv_key_len],
            &mut buf[off..(off + dh_pub_key_len)]
        )?;

        return Ok(hs_msg_len);

    }

}

// section-9.2.に実装必須の拡張がリストされてる