mod tls;

use crate::tls::tls::{
    TlsSocket,
    Config,
    EndpointType,
    ProtocolVersion,
    CipherSuite,
    NamedGroup,
    SignatureScheme
};

fn main() {

    let conf = Config::new(
        EndpointType::Client,
        &[ProtocolVersion::TLSv1_3],
        &[
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_128_CCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        ],
        &[NamedGroup::x25519],
        &[SignatureScheme::ed25519],
    );

    let sock = TlsSocket::new(&conf).unwrap();

}