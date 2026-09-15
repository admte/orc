//! `orc forward`: local listeners onto services that are not exposed.
//!
//! The command uses the API key `orc login` stored for the access server. One
//! HTTP/2 connection carries the session, with one stream per forwarded
//! connection.
//!
//! The names are the ones a pool card already shows
//! (`{pool}[-{slot}].{project}[.{suffix}]`), so they paste. The zone's internal
//! suffix is **asked for**, not assumed: a deployment that calls it something
//! other than `internal` must still take the name it renders.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use clap::Args;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::config::StoredConfig;
use crate::pb::access_service_client::AccessServiceClient;
use crate::pb::{
    DescribeRequest, DescribeResponse, ForwardFrame, ForwardOpen, ForwardTarget, NodeTarget,
    OpenSessionRequest, ResolvedTarget, ServiceTarget, TunnelKind, forward_frame, forward_target,
    session_event,
};
use orc_app::error::{CliError, Result};

/// The connection window is shared by a session's forwards. The smaller stream
/// window bounds how much one slow local reader can park in this process.
const H2_CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;
const H2_STREAM_WINDOW: u32 = 256 * 1024;

/// Maximum payload bytes sent in one protocol frame.
const FRAME_BYTES: usize = 8 * 1024;

/// Depth of the per-connection outbound queue: one frame on the wire, one behind
/// it. Anything deeper buffers on behalf of a peer that is not reading.
const OUTBOUND_DEPTH: usize = 2;

#[derive(Debug, Args)]
#[command(after_help = "\
A udp forward carries one datagram per frame, so it is reliable and ordered: right for \
request/response protocols, wrong for real-time media.\n\
Ctrl-C closes every listener, every tunnel, and the session.")]
pub struct ForwardArgs {
    /// Server to forward through (default: the host `orc login` stored).
    #[arg(long, value_name = "HOST")]
    pub server: Option<String>,
    /// Organization code (default: the stored one, or the only one in reach).
    #[arg(long, value_name = "CODE")]
    pub org: Option<String>,
    /// Local address to listen on.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1")]
    pub bind: String,
    /// Break-glass: dial the target through this node's own resolver. Requires
    /// `access_node`, and the target is then a plain `host:port`.
    #[arg(long, value_name = "NODE")]
    pub via: Option<String>,
    /// Local port for the matching target, in the order the targets are given.
    /// Defaults to the target's own port.
    #[arg(short = 'l', long = "local-port", value_name = "PORT")]
    pub local: Vec<u16>,
    /// One or more `[scheme://]{pool}[-{slot}].{project}[.{suffix}][:port]`
    /// targets — `tcp` by default, `udp` and `http` explicit. With `--via`, a
    /// plain `host:port`.
    #[arg(value_name = "TARGET", required = true)]
    pub targets: Vec<String>,
}

/// What a target string says before the server has resolved anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedTarget {
    pub(crate) udp: bool,
    /// The name as typed, minus scheme and port.
    pub(crate) name: String,
    pub(crate) port: Option<u16>,
}

/// A service name split into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceName {
    pub(crate) pool: String,
    pub(crate) slot: u16,
    pub(crate) project: String,
}

/// Splits `[scheme://]name[:port]`.
///
/// `http` is a scheme, not a transport: an http endpoint is carried over tcp like
/// any other, and saying `http://` only spares the reader wondering.
pub(crate) fn parse_target(raw: &str) -> Result<ParsedTarget> {
    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("tcp".to_owned(), raw),
    };
    let udp = match scheme.as_str() {
        "tcp" | "http" | "https" => false,
        "udp" => true,
        other => {
            return Err(CliError::Usage(format!(
                "{raw}: unknown scheme {other}; use tcp, udp or http"
            )));
        }
    };
    let (name, port) = split_port(rest)
        .ok_or_else(|| CliError::Usage(format!("{raw}: the port after ':' must be a number")))?;
    if name.is_empty() {
        return Err(CliError::Usage(format!("{raw}: names nothing")));
    }
    Ok(ParsedTarget {
        udp,
        name: name.to_owned(),
        port,
    })
}

/// Splits a trailing `:port`, leaving a bracketed IPv6 literal alone.
fn split_port(value: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (address, tail) = rest.split_once(']')?;
        return match tail.strip_prefix(':') {
            Some(port) => Some((address, Some(port.parse().ok()?))),
            None if tail.is_empty() => Some((address, None)),
            None => None,
        };
    }
    match value.rsplit_once(':') {
        Some((name, port)) => Some((name, Some(port.parse().ok()?))),
        None => Some((value, None)),
    }
}

/// Splits `{pool}[-{slot}].{project}[.{suffix}]`.
///
/// The suffix the server reports is stripped when it is there. What is left has
/// the pool first and the project second, which is what makes a name a client
/// pasted from a deployment with a *different* suffix still resolve: the two
/// labels that matter lead, and whatever trails them is somebody's suffix.
pub(crate) fn parse_service_name(name: &str, suffix: &str) -> Result<ServiceName> {
    let trimmed = suffix
        .strip_prefix('.')
        .unwrap_or(suffix)
        .trim_end_matches('.');
    let stripped = if trimmed.is_empty() {
        name
    } else {
        name.strip_suffix(&format!(".{trimmed}")).unwrap_or(name)
    };
    let mut labels = stripped.split('.');
    let (Some(pool), Some(project)) = (labels.next(), labels.next()) else {
        return Err(CliError::Usage(format!(
            "{name}: a target names {{pool}}.{{project}}[.{suffix}]"
        )));
    };
    if pool.is_empty() || project.is_empty() {
        return Err(CliError::Usage(format!(
            "{name}: a target names {{pool}}.{{project}}[.{suffix}]"
        )));
    }
    let (pool, slot) = split_slot(pool);
    Ok(ServiceName {
        pool,
        slot,
        project: project.to_owned(),
    })
}

/// A trailing `-{digits}` is the slot form; anything else is part of the pool's
/// own name, hyphens included.
pub(crate) fn split_slot(pool: &str) -> (String, u16) {
    if let Some((name, slot)) = pool.rsplit_once('-')
        && !name.is_empty()
        && !slot.is_empty()
        && slot.bytes().all(|byte| byte.is_ascii_digit())
        && let Ok(slot) = slot.parse::<u16>()
        && slot > 0
    {
        return (name.to_owned(), slot);
    }
    (pool.to_owned(), 0)
}

/// The local port one forward listens on: the one asked for, else the target's
/// own.
pub(crate) fn local_port(asked: Option<u16>, remote: u16) -> u16 {
    asked.unwrap_or(remote)
}

/// Runs one forward session until the client is interrupted or the server ends
/// it.
///
/// # Errors
///
/// Returns a [`CliError`] when the arguments do not parse, the server refuses
/// anything, a local port is taken, or the session ends other than by interrupt.
pub async fn forward(args: ForwardArgs, config: &StoredConfig) -> Result<()> {
    let server = server_host(args.server.as_deref(), config)?;
    let token = credential_token(&server, config)?;
    let parsed = args
        .targets
        .iter()
        .map(|raw| parse_target(raw))
        .collect::<Result<Vec<_>>>()?;

    let channel = connect(&server).await?;
    let mut client = AccessServiceClient::new(channel.clone());
    let org = args
        .org
        .clone()
        .or_else(|| config.default_org.clone())
        .unwrap_or_default();

    let described: DescribeResponse = client
        .describe(authorized(DescribeRequest { org: org.clone() }, &token)?)
        .await
        .map_err(|status| status_error(&status))?
        .into_inner();

    let targets = parsed
        .iter()
        .map(|target| build_target(target, args.via.as_deref(), &described.internal_dns_suffix))
        .collect::<Result<Vec<_>>>()?;

    let mut events = client
        .open_session(authorized(
            OpenSessionRequest {
                org: org.clone(),
                targets: targets.clone(),
                // Implied by a target this session names, rather than asked for:
                // `orc forward --via` says which node in the target itself.
                break_glass: false,
            },
            &token,
        )?)
        .await
        .map_err(|status| status_error(&status))?
        .into_inner();
    let first = events
        .message()
        .await
        .map_err(|status| status_error(&status))?;
    let Some(Some(session_event::Kind::Opened(opened))) = first.map(|event| event.kind) else {
        return Err(CliError::Operational(
            "the server opened no session".to_owned(),
        ));
    };

    eprintln!(
        "Session {} in {} ({}), up to {}",
        opened.session_id,
        described.org_code,
        described.org_name,
        humanize(opened.lifetime_secs)
    );
    let mut listeners = Vec::new();
    for (index, (target, resolved)) in parsed.iter().zip(opened.targets.iter()).enumerate() {
        let port = local_port(
            args.local.get(index).copied(),
            u16::try_from(resolved.port).unwrap_or(0),
        );
        listeners.push(
            bind_forward(BindParams {
                bind: &args.bind,
                port,
                udp: target.udp,
                session: opened.session_id.clone(),
                target: targets[index].clone(),
                resolved: resolved.clone(),
                channel: channel.clone(),
                token: token.clone(),
            })
            .await?,
        );
    }

    // The session lives exactly as long as this stream: interrupting the client
    // drops it, and the server ends the session then rather than on a timer.
    let outcome = tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|err| CliError::Operational(format!("interrupt: {err}")))?;
            eprintln!("\nClosing {} forward(s)", listeners.len());
            Ok(())
        }
        closed = session_closed(&mut events) => closed,
    };
    drop(listeners);
    outcome
}

/// Waits for the server to end the session, and reports why.
pub(crate) async fn session_closed(
    events: &mut tonic::Streaming<crate::pb::SessionEvent>,
) -> Result<()> {
    let reason = match events.message().await {
        Ok(Some(event)) => match event.kind {
            Some(session_event::Kind::Closed(closed)) => closed.reason,
            _ => "the server said something unexpected".to_owned(),
        },
        Ok(None) => "the server closed the session".to_owned(),
        Err(status) => return Err(status_error(&status)),
    };
    Err(CliError::Operational(format!("session ended: {reason}")))
}

/// One bound local listener, forwarding to one target for the life of the value.
struct Listener {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct BindParams<'a> {
    bind: &'a str,
    port: u16,
    udp: bool,
    session: String,
    target: ForwardTarget,
    resolved: ResolvedTarget,
    channel: Channel,
    token: String,
}

/// Binds one local listener and starts accepting on it.
async fn bind_forward(params: BindParams<'_>) -> Result<Listener> {
    let address: IpAddr = params
        .bind
        .parse()
        .map_err(|_| CliError::Usage(format!("--bind {}: not an address", params.bind)))?;
    let local = SocketAddr::new(address, params.port);
    let kind = if params.udp { "udp" } else { "tcp" };
    let node = if params.resolved.node.is_empty() {
        "resolved per connection".to_owned()
    } else {
        params.resolved.node.clone()
    };
    eprintln!(
        "  {kind}://{local} -> {} [{}] via {node}, permission {}",
        params.resolved.display, params.resolved.endpoint, params.resolved.permission
    );

    let session = params.session.clone();
    let target = params.target.clone();
    let channel = params.channel.clone();
    let token = params.token.clone();
    let task = if params.udp {
        let socket = UdpSocket::bind(local)
            .await
            .map_err(|err| taken(local, &err))?;
        tokio::spawn(async move {
            serve_udp(socket, session, target, channel, token).await;
        })
    } else {
        let listener = TcpListener::bind(local)
            .await
            .map_err(|err| taken(local, &err))?;
        tokio::spawn(async move {
            serve_tcp(listener, session, target, channel, token).await;
        })
    };
    Ok(Listener { task })
}

/// A port somebody else already has, said so the reader knows which flag moves
/// it.
fn taken(local: SocketAddr, err: &std::io::Error) -> CliError {
    if err.kind() == std::io::ErrorKind::AddrInUse {
        CliError::Conflict(format!(
            "local port {} is already in use; choose another with -l",
            local.port()
        ))
    } else {
        CliError::Operational(format!("listen on {local}: {err}"))
    }
}

/// Accepts local connections and gives each one its own stream.
async fn serve_tcp(
    listener: TcpListener,
    session: String,
    target: ForwardTarget,
    channel: Channel,
    token: String,
) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            return;
        };
        let session = session.clone();
        let target = target.clone();
        let channel = channel.clone();
        let token = token.clone();
        tokio::spawn(async move {
            match forward_tcp(stream, &session, target, channel, &token).await {
                Ok(()) => {}
                Err(err) => eprintln!("  {peer}: {err}"),
            }
        });
    }
}

/// One local TCP connection over one `Forward` stream.
async fn forward_tcp(
    stream: TcpStream,
    session: &str,
    target: ForwardTarget,
    channel: Channel,
    token: &str,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let forward = open_forward(session, target, channel, token).await?;
    eprintln!("  connection -> {}", forward.node);
    forward.splice(stream).await
}

/// One `Forward` stream whose open has been answered: the connection is up, and
/// nothing has crossed it yet.
///
/// Opening and splicing are two steps because a SOCKS proxy has something to say
/// to its own client in between — the reply that says the CONNECT succeeded — and
/// it can only say it once the far end has answered.
pub(crate) struct ForwardStream {
    /// The node that terminates this connection.
    pub(crate) node: String,
    /// The address that node dialed.
    pub(crate) address: String,
    inbound: tonic::Streaming<ForwardFrame>,
    to_server: mpsc::Sender<ForwardFrame>,
}

/// Opens one connection on a session and waits for the server's `ready`.
pub(crate) async fn open_forward(
    session: &str,
    target: ForwardTarget,
    channel: Channel,
    token: &str,
) -> Result<ForwardStream> {
    let (to_server, outbound) = mpsc::channel::<ForwardFrame>(OUTBOUND_DEPTH);
    let mut client = AccessServiceClient::new(channel);
    to_server
        .send(open_frame(session, target))
        .await
        .map_err(|_| CliError::Operational("the stream closed before it opened".to_owned()))?;
    let mut inbound = client
        .forward(authorized(ReceiverStream::new(outbound), token)?)
        .await
        .map_err(|status| status_error(&status))?
        .into_inner();

    let ready = inbound
        .message()
        .await
        .map_err(|status| status_error(&status))?;
    let Some(forward_frame::Kind::Ready(ready)) = ready.and_then(|frame| frame.kind) else {
        return Err(CliError::Operational(
            "the server did not answer the open".to_owned(),
        ));
    };
    Ok(ForwardStream {
        node: ready.node,
        address: ready.address,
        inbound,
        to_server,
    })
}

impl ForwardStream {
    /// Carries `stream` and the forward until either end is done with it.
    pub(crate) async fn splice(self, stream: TcpStream) -> Result<()> {
        let Self {
            mut inbound,
            to_server,
            ..
        } = self;
        let (mut reader, mut writer) = stream.into_split();
        // Two directions, two tasks: a proxy that reads one side only after the
        // other has drained deadlocks the moment both peers are writing.
        let up = tokio::spawn(async move {
            let mut buf = vec![0u8; FRAME_BYTES];
            while let Ok(read) = reader.read(&mut buf).await {
                if read == 0 {
                    break;
                }
                let frame = ForwardFrame {
                    kind: Some(forward_frame::Kind::Data(bytes::Bytes::copy_from_slice(
                        &buf[..read],
                    ))),
                };
                if to_server.send(frame).await.is_err() {
                    return;
                }
            }
            let _ = to_server
                .send(ForwardFrame {
                    kind: Some(forward_frame::Kind::Close(crate::pb::ForwardClose {
                        reason: "client closed".to_owned(),
                        bytes_in: 0,
                        bytes_out: 0,
                    })),
                })
                .await;
        });
        while let Some(frame) = inbound
            .message()
            .await
            .map_err(|status| status_error(&status))?
        {
            match frame.kind {
                Some(forward_frame::Kind::Data(data)) => {
                    if writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
                // A close, an end of stream, or anything that is not payload: this
                // connection is over either way.
                _ => break,
            }
        }
        up.abort();
        let _ = writer.shutdown().await;
        Ok(())
    }
}

/// One datagram per frame, and one stream per peer: a udp forward is reliable
/// and ordered, which suits request/response protocols and not real-time media.
async fn serve_udp(
    socket: UdpSocket,
    session: String,
    target: ForwardTarget,
    channel: Channel,
    token: String,
) {
    let socket = Arc::new(socket);
    let peers: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<ForwardFrame>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; FRAME_BYTES];
    loop {
        let Ok((read, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let frame = ForwardFrame {
            kind: Some(forward_frame::Kind::Data(bytes::Bytes::copy_from_slice(
                &buf[..read],
            ))),
        };
        let sender = {
            let mut peers = peers.lock().await;
            match peers.get(&peer) {
                Some(sender) if !sender.is_closed() => sender.clone(),
                _ => {
                    let (to_server, outbound) = mpsc::channel::<ForwardFrame>(OUTBOUND_DEPTH);
                    if to_server
                        .send(open_frame(&session, target.clone()))
                        .await
                        .is_err()
                    {
                        continue;
                    }
                    peers.insert(peer, to_server.clone());
                    let socket = Arc::clone(&socket);
                    let channel = channel.clone();
                    let token = token.clone();
                    tokio::spawn(async move {
                        if let Err(err) =
                            pump_udp_peer(socket, peer, outbound, channel, &token).await
                        {
                            eprintln!("  {peer}: {err}");
                        }
                    });
                    to_server
                }
            }
        };
        let _ = sender.send(frame).await;
    }
}

/// Carries one udp peer's stream back onto the local socket.
async fn pump_udp_peer(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    outbound: mpsc::Receiver<ForwardFrame>,
    channel: Channel,
    token: &str,
) -> Result<()> {
    let mut client = AccessServiceClient::new(channel);
    let mut inbound = client
        .forward(authorized(ReceiverStream::new(outbound), token)?)
        .await
        .map_err(|status| status_error(&status))?
        .into_inner();
    while let Some(frame) = inbound
        .message()
        .await
        .map_err(|status| status_error(&status))?
    {
        match frame.kind {
            Some(forward_frame::Kind::Ready(ready)) => {
                eprintln!("  datagrams from {peer} -> {}", ready.node);
            }
            Some(forward_frame::Kind::Data(data)) => {
                if socket.send_to(&data, peer).await.is_err() {
                    break;
                }
            }
            _ => break,
        }
    }
    Ok(())
}

fn open_frame(session: &str, target: ForwardTarget) -> ForwardFrame {
    ForwardFrame {
        kind: Some(forward_frame::Kind::Open(ForwardOpen {
            session_id: session.to_owned(),
            target: Some(target),
        })),
    }
}

/// Turns one parsed target into the request the server authorizes.
fn build_target(target: &ParsedTarget, via: Option<&str>, suffix: &str) -> Result<ForwardTarget> {
    let kind = if target.udp {
        TunnelKind::Udp
    } else {
        TunnelKind::Tcp
    };
    if let Some(node) = via {
        let port = target.port.ok_or_else(|| {
            CliError::Usage(format!("--via {node}: the target needs a host:port"))
        })?;
        return Ok(ForwardTarget {
            kind: kind.into(),
            target: Some(forward_target::Target::Node(NodeTarget {
                node: node.to_owned(),
                host: target.name.clone(),
                port: u32::from(port),
            })),
        });
    }
    let name = parse_service_name(&target.name, suffix)?;
    Ok(ForwardTarget {
        kind: kind.into(),
        target: Some(forward_target::Target::Service(ServiceTarget {
            project: name.project,
            pool: name.pool,
            endpoint: String::new(),
            port: u32::from(target.port.unwrap_or(0)),
            slot: u32::from(name.slot),
        })),
    })
}

/// The server this session runs against: the one named, else the host `orc
/// login` stored a credential for.
///
/// The stored default is a registry *prefix* and may carry a namespace
/// (`v0.orc8r.com/acme`); only its host is a server, so only its host is taken.
pub(crate) fn server_host(server: Option<&str>, config: &StoredConfig) -> Result<String> {
    if let Some(server) = server {
        return Ok(server.to_owned());
    }
    config
        .default_registry
        .as_deref()
        .map(|prefix| registry_host(prefix).to_owned())
        .ok_or_else(|| {
            CliError::Usage("no server: pass --server, or run orc login <server> first".to_owned())
        })
}

/// The API key `orc login` stored for a server, which is what every RPC on the
/// access surface authenticates with.
pub(crate) fn credential_token(server: &str, config: &StoredConfig) -> Result<String> {
    config
        .credential_for(registry_host(server))
        .map(|credential| credential.token.clone())
        .ok_or_else(|| {
            CliError::Auth(format!(
                "no credential for {server}; run orc login {}",
                registry_host(server)
            ))
        })
}

/// The credential key for a server: the host, without a scheme or a path.
pub(crate) fn registry_host(server: &str) -> &str {
    server
        .split_once("://")
        .map_or(server, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or(server)
}

/// One HTTP/2 connection for the whole session.
pub(crate) async fn connect(server: &str) -> Result<Channel> {
    let url = if server.contains("://") {
        server.to_owned()
    } else {
        format!("https://{server}")
    };
    let tls = url.starts_with("https://");
    let mut endpoint = Endpoint::from_shared(url.clone())
        .map_err(|err| CliError::Usage(format!("{server}: {err}")))?
        .initial_connection_window_size(H2_CONNECTION_WINDOW)
        .initial_stream_window_size(H2_STREAM_WINDOW)
        .http2_keep_alive_interval(std::time::Duration::from_secs(30))
        .keep_alive_timeout(std::time::Duration::from_secs(10))
        .keep_alive_while_idle(true);
    if tls {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(|err| CliError::Operational(format!("{server}: {err}")))?;
    }
    endpoint
        .connect()
        .await
        .map_err(|err| CliError::Operational(format!("connect to {url}: {err}")))
}

/// Attaches the API key every RPC on this surface authenticates with.
pub(crate) fn authorized<T>(message: T, token: &str) -> Result<tonic::Request<T>> {
    let mut request = tonic::Request::new(message);
    let value = format!("Bearer {token}")
        .parse()
        .map_err(|_| CliError::Auth("the stored credential is not a usable token".to_owned()))?;
    request
        .metadata_mut()
        .insert(http::header::AUTHORIZATION.as_str(), value);
    Ok(request)
}

/// The server's own message, with the exit code its status class deserves.
pub(crate) fn status_error(status: &Status) -> CliError {
    let message = status.message().to_owned();
    match status.code() {
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => CliError::Auth(message),
        tonic::Code::NotFound => CliError::NotFound(message),
        tonic::Code::InvalidArgument => CliError::Usage(message),
        tonic::Code::AlreadyExists | tonic::Code::ResourceExhausted => CliError::Conflict(message),
        _ => CliError::Operational(message),
    }
}

/// Durations as an operator reads them.
pub(crate) fn humanize(secs: u64) -> String {
    match secs {
        0 => "no time at all".to_owned(),
        secs if secs % 3600 == 0 => format!("{}h", secs / 3600),
        secs if secs % 60 == 0 => format!("{}m", secs / 60),
        secs => format!("{secs}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_scheme_name_and_port() {
        assert_eq!(
            parse_target("db.shop.internal:5432").expect("parse"),
            ParsedTarget {
                udp: false,
                name: "db.shop.internal".to_owned(),
                port: Some(5432),
            }
        );
        assert_eq!(
            parse_target("udp://dns.shop.internal:53").expect("parse"),
            ParsedTarget {
                udp: true,
                name: "dns.shop.internal".to_owned(),
                port: Some(53),
            }
        );
        // `http` is a scheme, not a transport.
        assert!(!parse_target("http://grafana.obs:3000").expect("parse").udp);
        // A port is optional: the server picks the pool's sole endpoint.
        assert_eq!(parse_target("db.shop").expect("parse").port, None);
        // A break-glass literal, brackets and all.
        assert_eq!(
            parse_target("[fd00::5]:5432").expect("parse"),
            ParsedTarget {
                udp: false,
                name: "fd00::5".to_owned(),
                port: Some(5432),
            }
        );
    }

    #[test]
    fn an_unusable_target_is_refused_by_name() {
        for raw in ["sctp://db.shop:1", "db.shop:not-a-port", ":5432"] {
            assert!(parse_target(raw).is_err(), "{raw} must be refused");
        }
    }

    #[test]
    fn a_name_is_pool_project_and_an_optional_slot() {
        assert_eq!(
            parse_service_name("db.shop.internal", "internal").expect("parse"),
            ServiceName {
                pool: "db".to_owned(),
                slot: 0,
                project: "shop".to_owned(),
            }
        );
        assert_eq!(
            parse_service_name("db-2.shop.internal", "internal").expect("parse"),
            ServiceName {
                pool: "db".to_owned(),
                slot: 2,
                project: "shop".to_owned(),
            }
        );
        // The suffix is optional…
        assert_eq!(
            parse_service_name("db.shop", "internal")
                .expect("parse")
                .pool,
            "db"
        );
        // …and a suffix this deployment does not use is still just a suffix.
        assert_eq!(
            parse_service_name("db.shop.internal", "corp.example").expect("parse"),
            ServiceName {
                pool: "db".to_owned(),
                slot: 0,
                project: "shop".to_owned(),
            }
        );
        // A hyphen is part of a pool's name unless what follows it is a number.
        assert_eq!(
            parse_service_name("web-front.shop.internal", "internal")
                .expect("parse")
                .pool,
            "web-front"
        );
        assert!(parse_service_name("db", "internal").is_err());
    }

    #[test]
    fn a_local_port_defaults_to_the_remote_one() {
        assert_eq!(local_port(None, 5432), 5432);
        assert_eq!(local_port(Some(15432), 5432), 15432);
    }

    #[test]
    fn a_taken_port_names_the_flag_that_moves_it() {
        let err = taken(
            "127.0.0.1:5432".parse().expect("addr"),
            &std::io::Error::from(std::io::ErrorKind::AddrInUse),
        );
        assert!(err.to_string().contains("-l"), "{err}");
        assert_eq!(err.exit_code(), orc_app::error::ExitCode::Conflict);
    }

    #[test]
    fn the_credential_key_is_the_bare_host() {
        assert_eq!(registry_host("https://v0.orc8r.com"), "v0.orc8r.com");
        assert_eq!(registry_host("v0.orc8r.com"), "v0.orc8r.com");
        assert_eq!(registry_host("http://127.0.0.1:8080/x"), "127.0.0.1:8080");
    }
}
