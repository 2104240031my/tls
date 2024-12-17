mod tls;

use crate::tls::tls::{
    TLSSocket,
    TLSConfig,
    TLSRole,
    TLSProtocolVersion,
    TLSCipherSuite,
    TLSNamedGroup,
    TLSSignatureScheme
};

use std::net::TcpStream;
use std::io::Write;

fn main() {

    let conf = TLSConfig::new(
        TLSRole::Client,
        &[TLSProtocolVersion::TLSv1_3],
        &[
            TLSCipherSuite::TLS_AES_128_GCM_SHA256,
            TLSCipherSuite::TLS_AES_128_CCM_SHA256,
            TLSCipherSuite::TLS_AES_256_GCM_SHA384,
            TLSCipherSuite::TLS_CHACHA20_POLY1305_SHA256
        ],
        &[TLSNamedGroup::x25519],
        &[TLSSignatureScheme::ed25519],
    );

    let mut sock = TLSSocket::new(&conf).unwrap();

    let mut buf = [0x00u8; 512];
    let s = sock.handshake_send(&mut buf[..]).unwrap();

    printbytesln(&buf[..s]);

    let mut strm = TcpStream::connect("127.0.0.1:443").unwrap();
    strm.write(&buf[..s]).unwrap();

}

fn printbytes(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
}

fn printbytesln(bytes: &[u8]) {
    printbytes(bytes);
    println!();
}