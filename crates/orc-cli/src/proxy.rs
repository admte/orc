//! `orc proxy`: one SOCKS5 front door onto a whole project.
//!
//! `orc forward` needs a local port per service, which means knowing the list
//! before starting. A browser, a database tool with a dozen saved connections or a
//! script walking a project does not have that list: it has names. So this listens
//! once, and every CONNECT it takes decides a target of its own — authorized on the
//! session the moment it is first asked for ([`AuthorizeTargetRequest`]), cached for
//! the rest of the session, and carried on one `Forward` stream exactly like a
//! forward's connection.
//!
//! **Names are resolved by the access server**, never here: `db.shop.internal` means
//! nothing to this process's resolver, and it does not try. A client must therefore
//! be told to hand its names to the proxy (Firefox's "Proxy DNS when using SOCKS
//! v5", curl's `--socks5-hostname`); one that resolves first arrives with an address
//! literal, which only `--via` can carry.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use clap::Args;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tonic::Status;
use tonic::transport::Channel;

use crate::config::StoredConfig;
use crate::forward::{
    ForwardStream, authorized, connect, credential_token, humanize, open_forward, server_host,
    session_closed, split_slot, status_error,
};
use crate::pb::access_service_client::AccessServiceClient;
use crate::pb::{
    AuthorizeTargetRequest, DescribeRequest, DescribeResponse, ForwardTarget, NodeTarget,
    OpenSessionRequest, ResolvedTarget, ServiceTarget, TunnelKind, forward_target, session_event,
};
use crate::socks::{self, Command, Reply};
use orc_app::error::{CliError, Result};

#[derive(Debug, Args)]
#[command(after_help = "\
Names are resolved on the access server, not in this process: point the client's name lookups at \
the proxy (Firefox: \"Proxy DNS when using SOCKS v5\"; curl: --socks5-hostname; ssh: -o \
ProxyCommand). A client that resolves names itself arrives with an address literal, which only \
--via carries.\n\
Ctrl-C closes the listener, every connection and the session.")]
pub struct ProxyArgs {
    /// Project whose services the proxy reaches. A bare `{pool}` name is assumed
    /// to be in it, and `{pool}.{project}[.{suffix}]` must name it.
    #[arg(value_name = "PROJECT")]
    pub project: String,
    /// Local port for the SOCKS5 listener.
    #[arg(long, value_name = "PORT")]
    pub socks: u16,
    /// Local address to listen on.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1")]
    pub bind: String,
    /// Organization code (default: the stored one, or the only one in reach).
    #[arg(long, value_name = "CODE")]
    pub org: Option<String>,
    /// Break-glass: carry names and literals this project does not answer for
    /// through this node's own resolver. Requires `access_node`, and shortens the
    /// session to the hard break-glass lifetime.
    #[arg(long, value_name = "NODE")]
    pub via: Option<String>,
    /// Server to proxy through (default: the host `orc login` stored).
    #[arg(long, value_name = "HOST")]
    pub server: Option<String>,
}

/// What one CONNECT resolves to before the server has decided anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Route {
    /// A pool of the proxy's own project. The endpoint is chosen by the port the
    /// CONNECT asked for, so a port no endpoint declares is refused by the server
    /// rather than dialed.
    Service { pool: String, slot: u16, port: u16 },
    /// Anything else, dialed through the break-glass node's own resolver.
    Node { host: String, port: u16 },
}

/// A CONNECT this proxy will not carry, and the code the client is told it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refused {
    pub(crate) reply: Reply,
    pub(crate) reason: String,
}

/// One target this session has been authorized for, kept so the second connection
/// to a name costs no round trip.
#[derive(Clone)]
struct Known {
    target: ForwardTarget,
    resolved: ResolvedTarget,
}

/// The running proxy: one session, one project, and what it has decided so far.
struct Proxy {
    session: String,
    project: String,
    suffix: String,
    via: Option<String>,
    channel: Channel,
    token: String,
    /// What each name and port has been decided to be, admitted or refused. A
    /// refusal is kept only when it was a decision — a permission, a name nothing
    /// answers for — and never when it was a moment: a member that is down comes
    /// back, and a proxy that remembered otherwise would keep refusing it.
    known: Mutex<HashMap<(String, u16), std::result::Result<Known, Refused>>>,
}

/// Runs the SOCKS5 proxy until the client is interrupted or the server ends the
/// session.
///
/// # Errors
///
/// Returns a [`CliError`] when the arguments do not parse, the server refuses the
/// session, the local port is taken, or the session ends other than by interrupt.
pub async fn proxy(args: ProxyArgs, config: &StoredConfig) -> Result<()> {
    let server = server_host(args.server.as_deref(), config)?;
    let token = credential_token(&server, config)?;
    let address: IpAddr = args
        .bind
        .parse()
        .map_err(|_| CliError::Usage(format!("--bind {}: not an address", args.bind)))?;
    let local = SocketAddr::new(address, args.socks);

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

    // The session opens with no target at all: which ones it will need is decided
    // one CONNECT at a time. It has to say up front whether it may grow a
    // break-glass target, because that is what its lifetime is computed from.
    let mut events = client
        .open_session(authorized(
            OpenSessionRequest {
                org: org.clone(),
                targets: Vec::new(),
                break_glass: args.via.is_some(),
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

    let listener = TcpListener::bind(local)
        .await
        .map_err(|err| taken(local, &err))?;
    eprintln!(
        "Session {} in {} ({}), up to {}",
        opened.session_id,
        described.org_code,
        described.org_name,
        humanize(opened.lifetime_secs)
    );
    eprintln!(
        "SOCKS5 on {local} for project {} in org {}; names {{pool}}.{}{} resolve through the \
         server; {}",
        args.project,
        described.org_code,
        args.project,
        dotted(&described.internal_dns_suffix),
        match &args.via {
            Some(node) => format!("anything else goes through {node}"),
            None => "literals need --via".to_owned(),
        }
    );

    let proxy = Arc::new(Proxy {
        session: opened.session_id.clone(),
        project: args.project.clone(),
        suffix: described.internal_dns_suffix.clone(),
        via: args.via.clone(),
        channel,
        token,
        known: Mutex::new(HashMap::new()),
    });
    let accepting = tokio::spawn(accept(listener, Arc::clone(&proxy)));

    let outcome = tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|err| CliError::Operational(format!("interrupt: {err}")))?;
            eprintln!("\nClosing the proxy");
            Ok(())
        }
        closed = session_closed(&mut events) => closed,
    };
    accepting.abort();
    outcome
}

/// The suffix as it appears after a project label, or nothing when the zone has
/// none to report.
fn dotted(suffix: &str) -> String {
    let trimmed = suffix.trim_matches('.');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!(".{trimmed}")
    }
}

/// A port somebody else already has, said so the reader knows which flag moves it.
fn taken(local: SocketAddr, err: &std::io::Error) -> CliError {
    if err.kind() == std::io::ErrorKind::AddrInUse {
        CliError::Conflict(format!(
            "local port {} is already in use; choose another with --socks",
            local.port()
        ))
    } else {
        CliError::Operational(format!("listen on {local}: {err}"))
    }
}

/// Accepts local connections and gives each one its own task.
async fn accept(listener: TcpListener, proxy: Arc<Proxy>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            return;
        };
        let proxy = Arc::clone(&proxy);
        tokio::spawn(serve(stream, peer, proxy));
    }
}

/// One local connection: the handshake, the decision, and then the bytes.
async fn serve(mut stream: TcpStream, peer: SocketAddr, proxy: Arc<Proxy>) {
    let _ = stream.set_nodelay(true);
    if let Err(err) = socks::greet(&mut stream).await {
        eprintln!("  {peer}: {err}");
        return;
    }
    let request = match socks::read_request(&mut stream).await {
        Ok(request) => request,
        Err(err) => {
            eprintln!("  {peer}: {err}");
            return;
        }
    };
    let asked = format!("{}:{}", request.host, request.port);
    if request.command != Command::Connect {
        eprintln!(
            "  {peer}: {} is refused; this proxy carries CONNECT only",
            request.command.name()
        );
        let _ = socks::reply(&mut stream, Reply::CommandNotSupported).await;
        return;
    }

    let known = match proxy.decide(&request.host, request.port).await {
        Ok(known) => known,
        Err(refused) => {
            eprintln!("  {peer} CONNECT {asked} refused: {}", refused.reason);
            let _ = socks::reply(&mut stream, refused.reply).await;
            return;
        }
    };
    let forward = match open_forward(
        &proxy.session,
        known.target.clone(),
        proxy.channel.clone(),
        &proxy.token,
    )
    .await
    {
        Ok(forward) => forward,
        Err(err) => {
            eprintln!("  {peer} CONNECT {asked}: {err}");
            let _ = socks::reply(&mut stream, reply_for_error(&err)).await;
            return;
        }
    };
    announce(peer, &asked, &known.resolved, &forward);
    if socks::reply(&mut stream, Reply::Succeeded).await.is_err() {
        return;
    }
    if let Err(err) = forward.splice(stream).await {
        eprintln!("  {peer} CONNECT {asked}: {err}");
    }
}

/// One line per carried connection: what was asked for, what it reached, and the
/// permission that admitted it.
fn announce(peer: SocketAddr, asked: &str, resolved: &ResolvedTarget, forward: &ForwardStream) {
    let endpoint = if resolved.endpoint.is_empty() {
        String::new()
    } else {
        format!(" [{}]", resolved.endpoint)
    };
    eprintln!(
        "  {peer} CONNECT {asked} -> {}{endpoint} via {} ({}), permission {}",
        resolved.display, forward.node, forward.address, resolved.permission
    );
}

impl Proxy {
    /// The authorized target one CONNECT reaches: the cached decision, or a new
    /// one taken on the session.
    async fn decide(&self, host: &str, port: u16) -> std::result::Result<Known, Refused> {
        let key = (host.to_ascii_lowercase(), port);
        if let Some(decided) = self.known.lock().await.get(&key) {
            return decided.clone();
        }
        let route = route(host, port, &self.project, &self.suffix, self.via.as_deref())?;
        let target = forward_target(&route, &self.project, self.via.as_deref());
        // Outside the lock on purpose: authorizing is a round trip, and the server
        // answers a target it already holds with the decision it took the first
        // time, so two connections racing the same name cost one decision.
        let decided = match self.authorize(target.clone()).await {
            Ok(resolved) => Ok(Known { target, resolved }),
            Err(refused) => Err(refused),
        };
        // Remembering a refusal is what keeps a client that retries from writing an
        // audit event per attempt; a transient failure is deliberately not one.
        if decided
            .as_ref()
            .err()
            .is_none_or(|refused| refused.reply == Reply::NotAllowed)
        {
            self.known.lock().await.insert(key, decided.clone());
        }
        decided
    }

    async fn authorize(
        &self,
        target: ForwardTarget,
    ) -> std::result::Result<ResolvedTarget, Refused> {
        let request = AuthorizeTargetRequest {
            session_id: self.session.clone(),
            target: Some(target),
        };
        let request = authorized(request, &self.token).map_err(|err| Refused {
            reply: Reply::GeneralFailure,
            reason: err.to_string(),
        })?;
        AccessServiceClient::new(self.channel.clone())
            .authorize_target(request)
            .await
            .map(tonic::Response::into_inner)
            .map_err(|status| Refused {
                reply: reply_for_status(&status),
                reason: status.message().to_owned(),
            })
    }
}

/// Which target a CONNECT names.
///
/// A name of the project's own — `{pool}[-{slot}]`, or `{pool}[-{slot}].{project}`
/// with or without the zone's suffix — is a service target, and the port picks the
/// endpoint. Everything else is somebody else's name or an address this process
/// cannot interpret, and there is exactly one way to carry it: `--via`, which is
/// break-glass and says so.
pub(crate) fn route(
    host: &str,
    port: u16,
    project: &str,
    suffix: &str,
    via: Option<&str>,
) -> std::result::Result<Route, Refused> {
    let literal = host.parse::<IpAddr>().is_ok();
    if !literal && let Some((pool, slot)) = pool_in_project(host, project, suffix) {
        return Ok(Route::Service { pool, slot, port });
    }
    match via {
        Some(_) => Ok(Route::Node {
            host: host.to_owned(),
            port,
        }),
        None => Err(Refused {
            reply: Reply::NotAllowed,
            reason: format!(
                "{host} is not a name in project {project}; this proxy carries \
                 {{pool}}[-{{slot}}].{project}{} and nothing else — reach anything further \
                 with --via <node>",
                dotted(suffix)
            ),
        }),
    }
}

/// The pool a name asks for, when the name belongs to this proxy's project.
///
/// A bare `{pool}` is assumed to be in it — that is the whole point of naming the
/// project once — and a two-label name has to agree with it. Anything longer, after
/// the zone's own suffix is taken off, is another deployment's name.
fn pool_in_project(host: &str, project: &str, suffix: &str) -> Option<(String, u16)> {
    let trimmed = suffix.trim_matches('.');
    let stripped = if trimmed.is_empty() {
        host
    } else {
        host.strip_suffix(&format!(".{trimmed}")).unwrap_or(host)
    };
    let mut labels = stripped.split('.');
    let pool = labels.next().filter(|label| !label.is_empty())?;
    match labels.next() {
        None => Some(split_slot(pool)),
        Some(named) if named.eq_ignore_ascii_case(project) && labels.next().is_none() => {
            Some(split_slot(pool))
        }
        Some(_) => None,
    }
}

/// The request the server authorizes, built from a decided route. The project is
/// the proxy's own: a CONNECT never names another, and a name that tried was
/// refused before it got here.
fn forward_target(route: &Route, project: &str, via: Option<&str>) -> ForwardTarget {
    let target = match route {
        Route::Service { pool, slot, port } => forward_target::Target::Service(ServiceTarget {
            project: project.to_owned(),
            pool: pool.clone(),
            endpoint: String::new(),
            port: u32::from(*port),
            slot: u32::from(*slot),
        }),
        Route::Node { host, port } => forward_target::Target::Node(NodeTarget {
            node: via.unwrap_or_default().to_owned(),
            host: host.clone(),
            port: u32::from(*port),
        }),
    };
    ForwardTarget {
        kind: TunnelKind::Tcp.into(),
        target: Some(target),
    }
}

/// The reply code a refusal from the server deserves. A client acts on these: a
/// name the project does not answer for must not read as a network failure, and a
/// member that is down must not read as a policy refusal.
fn reply_for_status(status: &Status) -> Reply {
    match status.code() {
        tonic::Code::NotFound
        | tonic::Code::PermissionDenied
        | tonic::Code::Unauthenticated
        | tonic::Code::InvalidArgument => Reply::NotAllowed,
        tonic::Code::Unavailable => Reply::HostUnreachable,
        tonic::Code::FailedPrecondition | tonic::Code::DeadlineExceeded => Reply::ConnectionRefused,
        _ => Reply::GeneralFailure,
    }
}

/// The same, for a failure that has already been turned into the CLI's own error.
fn reply_for_error(err: &CliError) -> Reply {
    match err {
        CliError::Auth(_) | CliError::Usage(_) => Reply::NotAllowed,
        CliError::NotFound(_) => Reply::HostUnreachable,
        CliError::Conflict(_) | CliError::Operational(_) => Reply::ConnectionRefused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(host: &str, port: u16) -> std::result::Result<Route, Refused> {
        route(host, port, "shop", "internal", None)
    }

    #[test]
    fn a_name_of_the_project_is_a_service_target() {
        assert_eq!(
            service("db.shop.internal", 5432).expect("routed"),
            Route::Service {
                pool: "db".to_owned(),
                slot: 0,
                port: 5432,
            }
        );
        // The suffix is optional…
        assert_eq!(
            service("db.shop", 5432).expect("routed"),
            Route::Service {
                pool: "db".to_owned(),
                slot: 0,
                port: 5432,
            }
        );
        // …and so is the project, because the proxy already names it.
        assert_eq!(
            service("db", 5432).expect("routed"),
            Route::Service {
                pool: "db".to_owned(),
                slot: 0,
                port: 5432,
            }
        );
        // The slot form survives, and a hyphen that is not a slot stays in the name.
        assert_eq!(
            service("db-2.shop.internal", 5432).expect("routed"),
            Route::Service {
                pool: "db".to_owned(),
                slot: 2,
                port: 5432,
            }
        );
        assert_eq!(
            service("web-front", 80).expect("routed"),
            Route::Service {
                pool: "web-front".to_owned(),
                slot: 0,
                port: 80,
            }
        );
    }

    #[test]
    fn another_project_and_a_literal_are_refused_by_ruleset() {
        for host in [
            "db.other.internal",
            "db.other",
            "grafana.obs.corp.example",
            "10.0.0.5",
            "fd00::5",
        ] {
            let refused = service(host, 5432).expect_err("refused");
            assert_eq!(
                refused.reply,
                Reply::NotAllowed,
                "{host} is a policy refusal, not a network failure"
            );
            assert!(
                refused.reason.contains("--via"),
                "the refusal names the way through: {}",
                refused.reason
            );
        }
    }

    #[test]
    fn break_glass_carries_what_the_project_does_not_answer_for() {
        let routed = route("10.0.0.5", 5432, "shop", "internal", Some("n_a0o0q98c"))
            .expect("a literal is carried through the node");
        assert_eq!(
            routed,
            Route::Node {
                host: "10.0.0.5".to_owned(),
                port: 5432,
            }
        );
        let target = forward_target(&routed, "shop", Some("n_a0o0q98c"));
        match target.target.expect("a target") {
            forward_target::Target::Node(node) => {
                assert_eq!(node.node, "n_a0o0q98c");
                assert_eq!(node.host, "10.0.0.5");
                assert_eq!(node.port, 5432);
            }
            service @ forward_target::Target::Service(_) => {
                panic!("expected a node literal, got {service:?}")
            }
        }
        // The project's own names still go the ordinary way, even with --via.
        assert_eq!(
            route(
                "db.shop.internal",
                5432,
                "shop",
                "internal",
                Some("n_a0o0q98c")
            )
            .expect("routed"),
            Route::Service {
                pool: "db".to_owned(),
                slot: 0,
                port: 5432,
            }
        );
    }

    #[test]
    fn a_service_target_leaves_the_project_to_the_session() {
        let routed = service("db.shop.internal", 5432).expect("routed");
        match forward_target(&routed, "shop", None)
            .target
            .expect("a target")
        {
            forward_target::Target::Service(service) => {
                assert_eq!(service.pool, "db");
                assert_eq!(
                    service.project, "shop",
                    "the proxy's project, never the name's"
                );
                assert_eq!(service.port, 5432, "the port picks the endpoint");
                assert!(service.endpoint.is_empty());
            }
            node @ forward_target::Target::Node(_) => {
                panic!("expected a service target, got {node:?}")
            }
        }
    }

    #[test]
    fn a_refusal_reads_as_what_it_is() {
        assert_eq!(
            reply_for_status(&Status::not_found("no pool db in project shop")),
            Reply::NotAllowed
        );
        assert_eq!(
            reply_for_status(&Status::permission_denied("access_service")),
            Reply::NotAllowed
        );
        assert_eq!(
            reply_for_status(&Status::unavailable("node is offline")),
            Reply::HostUnreachable
        );
        assert_eq!(
            reply_for_status(&Status::failed_precondition("runtime lacks tunnel support")),
            Reply::ConnectionRefused
        );
        assert_eq!(
            reply_for_status(&Status::resource_exhausted("too many targets")),
            Reply::GeneralFailure
        );
        assert_eq!(
            reply_for_error(&CliError::NotFound("gone".to_owned())),
            Reply::HostUnreachable
        );
    }

    #[test]
    fn a_taken_port_names_the_flag_that_moves_it() {
        let err = taken(
            "127.0.0.1:1080".parse().expect("addr"),
            &std::io::Error::from(std::io::ErrorKind::AddrInUse),
        );
        assert!(err.to_string().contains("--socks"), "{err}");
        assert_eq!(err.exit_code(), orc_app::error::ExitCode::Conflict);
    }
}
