//! The SOCKS5 wire (RFC 1928), only as much of it as a CONNECT proxy speaks.
//!
//! Reading is one small step at a time — greeting, request head, address — because
//! each step's length is decided by the bytes before it. Everything here is about
//! the protocol and nothing about what the proxy does with it: which names are
//! reachable is [`crate::proxy`]'s question, and this module only carries the
//! answer back in the reply code the client expects.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use orc_app::error::{CliError, Result};

/// The only version there is; a `4` here is a SOCKS4 client, and it is told so.
const VERSION: u8 = 5;
/// The only method this proxy offers. The session's credential is the API key the
/// CLI already holds, and a loopback listener asking for a second one would be
/// theatre: what `--bind` opens to the network is the thing to think about.
const NO_AUTHENTICATION: u8 = 0x00;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// What a reply says happened (RFC 1928 §6). The codes are meant to be told apart
/// by a client, so a refusal by policy never arrives as a general failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    /// "Connection not allowed by ruleset": this proxy will not carry that name.
    NotAllowed = 0x02,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    CommandNotSupported = 0x07,
}

/// What a client asked the proxy to do. Only [`Command::Connect`] is carried; the
/// other two are refused with the code that names them rather than a hang.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Connect,
    Bind,
    UdpAssociate,
    Unknown(u8),
}

impl Command {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::Connect,
            0x02 => Self::Bind,
            0x03 => Self::UdpAssociate,
            other => Self::Unknown(other),
        }
    }

    /// What the command is called in a log line and in a refusal.
    pub(crate) fn name(self) -> String {
        match self {
            Self::Connect => "CONNECT".to_owned(),
            Self::Bind => "BIND".to_owned(),
            Self::UdpAssociate => "UDP ASSOCIATE".to_owned(),
            Self::Unknown(byte) => format!("command {byte:#04x}"),
        }
    }
}

/// One SOCKS5 request, with the address in the form the client wrote it: a name
/// stays a name, because resolving it is the server's job and not this process's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocksRequest {
    pub(crate) command: Command,
    pub(crate) host: String,
    pub(crate) port: u16,
}

/// Reads the greeting and answers it, agreeing on no authentication.
///
/// A client offering nothing this proxy speaks is told so in its own protocol
/// (`0xFF`) before the connection is dropped, so it reports a method mismatch
/// instead of a truncated handshake.
pub(crate) async fn greet<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|err| protocol(&format!("read the greeting: {err}")))?;
    if head[0] != VERSION {
        return Err(protocol(&format!(
            "this is a SOCKS5 proxy and the client offered version {}",
            head[0]
        )));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|err| protocol(&format!("read the greeting's methods: {err}")))?;
    if !methods.contains(&NO_AUTHENTICATION) {
        let _ = stream.write_all(&[VERSION, NO_ACCEPTABLE_METHODS]).await;
        return Err(protocol(
            "the client offered no unauthenticated method, which is the only one this proxy takes",
        ));
    }
    stream
        .write_all(&[VERSION, NO_AUTHENTICATION])
        .await
        .map_err(|err| protocol(&format!("answer the greeting: {err}")))?;
    Ok(())
}

/// Reads one request: the command, the address as written, and the port.
pub(crate) async fn read_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|err| protocol(&format!("read the request: {err}")))?;
    if head[0] != VERSION {
        return Err(protocol(&format!(
            "a request carrying version {} is not SOCKS5",
            head[0]
        )));
    }
    let host = match head[3] {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|err| protocol(&format!("read an address: {err}")))?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|err| protocol(&format!("read an address: {err}")))?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|err| protocol(&format!("read a name: {err}")))?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream
                .read_exact(&mut name)
                .await
                .map_err(|err| protocol(&format!("read a name: {err}")))?;
            String::from_utf8(name).map_err(|_| protocol("a name that is not text"))?
        }
        other => {
            return Err(protocol(&format!(
                "address type {other:#04x} is not one of the three"
            )));
        }
    };
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|err| protocol(&format!("read a port: {err}")))?;
    Ok(SocksRequest {
        command: Command::from_byte(head[1]),
        host,
        port: u16::from_be_bytes(port),
    })
}

/// Answers a request.
///
/// The bound address is always `0.0.0.0:0`: what a CONNECT reached is a tunnel on
/// the far side of an ORC access server, and there is no local socket whose address would
/// mean anything to the client.
pub(crate) async fn reply<S>(stream: &mut S, reply: Reply) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let frame = [VERSION, reply as u8, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream
        .write_all(&frame)
        .await
        .map_err(|err| protocol(&format!("answer the request: {err}")))?;
    Ok(())
}

fn protocol(message: &str) -> CliError {
    CliError::Operational(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drives one exchange: what the client writes, and what it reads back.
    async fn exchange(client_bytes: &[u8]) -> (Result<SocksRequest>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(256);
        client.write_all(client_bytes).await.expect("write");
        let greeted = greet(&mut server).await;
        let request = match greeted {
            Ok(()) => read_request(&mut server).await,
            Err(err) => Err(err),
        };
        drop(server);
        let mut answered = Vec::new();
        client.read_to_end(&mut answered).await.expect("read");
        (request, answered)
    }

    #[tokio::test]
    async fn a_greeting_offering_no_auth_is_agreed_and_the_request_read() {
        let name = b"db.shop.internal";
        let mut bytes = vec![5, 2, 0x00, 0x02, 5, 0x01, 0x00, 0x03];
        bytes.push(u8::try_from(name.len()).expect("short name"));
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(&5432u16.to_be_bytes());
        let (request, answered) = exchange(&bytes).await;
        let request = request.expect("a request");
        assert_eq!(request.command, Command::Connect);
        assert_eq!(
            request.host, "db.shop.internal",
            "a name stays a name: resolving it is the server's job"
        );
        assert_eq!(request.port, 5432);
        assert_eq!(&answered[..2], &[5, 0], "no authentication is agreed");
    }

    #[tokio::test]
    async fn a_client_with_no_unauthenticated_method_is_told_so() {
        // Only username/password on offer.
        let (request, answered) = exchange(&[5, 1, 0x02]).await;
        assert!(request.is_err(), "the handshake fails");
        assert_eq!(
            answered,
            vec![5, 0xFF],
            "and it fails in the client's own protocol"
        );
    }

    #[tokio::test]
    async fn a_socks4_client_is_refused_by_version() {
        let (request, answered) = exchange(&[4, 1, 0x00]).await;
        assert!(request.is_err());
        assert!(answered.is_empty(), "nothing is agreed with version 4");
    }

    #[tokio::test]
    async fn every_address_type_reads_back_as_the_client_wrote_it() {
        let mut ipv4 = vec![5, 1, 0x00, 5, 0x01, 0x00, 0x01, 10, 0, 0, 5];
        ipv4.extend_from_slice(&5432u16.to_be_bytes());
        let (request, _) = exchange(&ipv4).await;
        assert_eq!(request.expect("ipv4").host, "10.0.0.5");

        let mut ipv6 = vec![5, 1, 0x00, 5, 0x01, 0x00, 0x04];
        ipv6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        ipv6.extend_from_slice(&443u16.to_be_bytes());
        let (request, _) = exchange(&ipv6).await;
        let request = request.expect("ipv6");
        assert_eq!(request.host, "::1");
        assert_eq!(request.port, 443);
    }

    #[tokio::test]
    async fn the_other_two_commands_are_read_and_named() {
        for (byte, command) in [(0x02, Command::Bind), (0x03, Command::UdpAssociate)] {
            let mut bytes = vec![5, 1, 0x00, 5, byte, 0x00, 0x01, 127, 0, 0, 1];
            bytes.extend_from_slice(&80u16.to_be_bytes());
            let (request, _) = exchange(&bytes).await;
            assert_eq!(request.expect("a request").command, command);
        }
        assert_eq!(Command::Bind.name(), "BIND");
        assert_eq!(Command::UdpAssociate.name(), "UDP ASSOCIATE");
    }

    #[tokio::test]
    async fn a_reply_is_ten_bytes_naming_its_code() {
        let (mut client, mut server) = tokio::io::duplex(64);
        reply(&mut server, Reply::NotAllowed).await.expect("reply");
        drop(server);
        let mut answered = Vec::new();
        client.read_to_end(&mut answered).await.expect("read");
        assert_eq!(answered, vec![5, 0x02, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
}
