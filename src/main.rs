mod tls;

use crate::tls::tls::{
    TlsSocket,
    TlsConfig,
    TlsEndpointType,
    TlsProtocolVersion,
    TlsCipherSuite,
    TlsNamedGroup,
    TlsSignatureScheme
};

fn main() {

    let conf = TlsConfig::new(
        TlsEndpointType::Client,
        &[TlsProtocolVersion::TLSv1_3],
        &[
            TlsCipherSuite::TLS_AES_128_GCM_SHA256,
            TlsCipherSuite::TLS_AES_128_CCM_SHA256,
            TlsCipherSuite::TLS_AES_256_GCM_SHA384,
            TlsCipherSuite::TLS_CHACHA20_POLY1305_SHA256
        ],
        &[TlsNamedGroup::x25519],
        &[TlsSignatureScheme::ed25519],
    );

    let sock = TlsSocket::new(&conf).unwrap();

}