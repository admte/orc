//! Endpoint readiness probes (spec 180).
//!
//! Probes run in the host runtime beside the app. Only *transitions* leave this
//! module (see [`ProbeState`]); a passing probe that keeps passing reports nothing.
//!
//! Hosts use this module in three steps: [`plan_endpoint_probes`] turns an app's
//! declared endpoints into one plan each, [`AppProbes::spawn`] drives those plans
//! for a running app, and dropping the returned handle stops every probe — that is
//! how a stopped or draining app leaves the endpoint-healthy set.
//!
//! A probe dials *every* address its endpoint is served on and passes only when all
//! of them answer, which is what makes "endpoint-healthy" mean "reachable by the
//! consumers this member is offered to" rather than "listening somewhere"
//! ([`ProbeContext::probe_targets`]).

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::{AppConfig, CommandValue, EndpointProbe, EndpointProtocol};
use crate::lifecycle::{parse_duration, probe_command};

/// Poll spacing when the manifest declares no `interval`.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(10);
/// Per-probe deadline when the manifest declares no `timeout`.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Consecutive failures before an endpoint goes unready (one success restores it).
pub const FAILURE_THRESHOLD: u32 = 3;

/// Address probes fall back to when the node's own is unknown.
///
/// Only reached before a node has a recorded address; an app bound to the routable
/// address alone reads as unready until one arrives, which is the honest answer —
/// consumers cannot reach it either.
const FALLBACK_PROBE_HOST: &str = "127.0.0.1";

// A transition's `reason` explains a *failure*: `ready` always carries an empty one,
// matching the public status contract (a ready endpoint has nothing to
// explain, and an operator reading a stale "probe passed" beside a live status would
// be misled).

/// Per-endpoint readiness as the host runtime sees it. `Unknown` is the pre-first-probe
/// state and is never reported; it is represented by the absence of a report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EndpointStatus {
    #[default]
    Unknown,
    Ready,
    Unready,
}

impl EndpointStatus {
    /// Wire spelling used by the public status contract.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Ready => "ready",
            Self::Unready => "unready",
        }
    }
}

/// What one endpoint's probe executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeKind {
    /// Connect to the endpoint port. The default for `tcp`, `http`, and `https`
    /// endpoints.
    Tcp { port: u16 },
    /// `GET` the path; 2xx and 3xx pass. Only http-family (`http`/`https`)
    /// endpoints can declare it. `tls` is set for `https`, where the probe dials
    /// over TLS instead of cleartext.
    Http { port: u16, path: String, tls: bool },
    /// Run the app's own check; exit 0 passes.
    Command(CommandValue),
    /// No probe at all (a `udp` endpoint without a `command` probe): readiness follows
    /// app readiness alone, so the endpoint reports `ready` once and never probes.
    AppReadiness,
}

/// One endpoint's resolved probe: what to run, how often, and how long to wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointProbePlan {
    pub endpoint: String,
    pub kind: ProbeKind,
    pub interval: Duration,
    pub timeout: Duration,
}

/// Builds the probe plan for every endpoint an app declares, in endpoint-name order.
///
/// Package validation already enforces the manifest rules (exactly one probe kind,
/// `http` probe only on http-family endpoints, well-formed durations), so this is deliberately
/// total: anything that slipped past validation degrades to the protocol default
/// rather than failing an app that is already running.
#[must_use]
pub fn plan_endpoint_probes(config: &AppConfig) -> Vec<EndpointProbePlan> {
    config
        .endpoints
        .iter()
        .map(|(name, endpoint)| {
            let probe = endpoint.probe.as_ref();
            EndpointProbePlan {
                endpoint: name.clone(),
                kind: probe_kind(endpoint.port, endpoint.protocol, probe),
                interval: probe_duration(
                    probe.and_then(|probe| probe.interval.as_deref()),
                    DEFAULT_PROBE_INTERVAL,
                ),
                timeout: probe_duration(
                    probe.and_then(|probe| probe.timeout.as_deref()),
                    DEFAULT_PROBE_TIMEOUT,
                ),
            }
        })
        .collect()
}

/// Resolves the probe an endpoint runs.
///
/// A declared kind wins; otherwise the protocol decides. `tcp: false` is the one
/// case spec 180 leaves open: it is read as an explicit opt-out of the default
/// connect probe, which leaves the endpoint following app readiness — the same
/// place a probe-less `udp` endpoint lands.
fn probe_kind(port: u16, protocol: EndpointProtocol, probe: Option<&EndpointProbe>) -> ProbeKind {
    if let Some(probe) = probe {
        if let Some(command) = &probe.command {
            return ProbeKind::Command(command.clone());
        }
        if let Some(path) = &probe.http {
            return ProbeKind::Http {
                port,
                path: path.clone(),
                tls: matches!(protocol, EndpointProtocol::Https),
            };
        }
        match probe.tcp {
            Some(true) => return ProbeKind::Tcp { port },
            Some(false) => return ProbeKind::AppReadiness,
            // A probe carrying only timing overrides declares no kind; fall through
            // to the protocol default rather than treating it as an opt-out.
            None => {}
        }
    }
    match protocol {
        EndpointProtocol::Tcp | EndpointProtocol::Http | EndpointProtocol::Https => {
            ProbeKind::Tcp { port }
        }
        EndpointProtocol::Udp => ProbeKind::AppReadiness,
    }
}

/// Parses a manifest duration override, falling back to `default`.
///
/// Author-time validation rejects malformed values, so a bad one here means a
/// package that predates a rule or was hand-assembled: probing on the default
/// cadence beats refusing to probe a running app. Zero is treated the same way —
/// a zero interval would busy-spin and a zero timeout could never pass.
fn probe_duration(value: Option<&str>, default: Duration) -> Duration {
    value
        .and_then(|value| parse_duration(value).ok())
        .filter(|duration| !duration.is_zero())
        .unwrap_or(default)
}

/// Reads the addresses an endpoint is delivered on *besides* the node's own — the
/// pool addresses a publicly exposed endpoint's clients actually dial.
///
/// Called by name because delivery is per endpoint: a pool address carries the pool's
/// publicly exposed ports and nothing else, so an endpoint exposed inside the project
/// alone is answered with an empty list and keeps probing its node address only.
///
/// A reader rather than a captured list because the set moves under a running app:
/// addresses are drawn and released, and a member joins and leaves a pool's delivery
/// without anything restarting. Read once per tick, so a change is picked up on the
/// next probe rather than needing one.
pub type DeliveredAddresses = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;

/// Probe execution context: the lifecycle-command context of the running app — its
/// work directory and the resolved-params environment captured when it started —
/// plus the addresses this node answers on.
#[derive(Clone, Default)]
pub struct ProbeContext {
    pub work_dir: PathBuf,
    pub env: BTreeMap<String, String>,
    /// The host's own reachable address. `None` when none is recorded yet.
    pub host: Option<String>,
    /// The delivery addresses an endpoint is *also* served on. `None` on a runtime
    /// whose nodes hold none.
    pub delivered_on: Option<DeliveredAddresses>,
}

impl std::fmt::Debug for ProbeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeContext")
            .field("work_dir", &self.work_dir)
            .field("env", &self.env)
            .field("host", &self.host)
            .field("delivered_on", &self.delivered_on.is_some())
            .finish()
    }
}

impl ProbeContext {
    /// Every address an endpoint's `tcp` and `http` probes must reach, node address
    /// first, deduplicated.
    ///
    /// Probing the addresses the endpoint is served on rather than loopback is what
    /// makes a passing probe mean what the endpoint-healthy set claims: the probe
    /// dials each of them exactly as a consumer of that address does, and an app that
    /// answers on only some of them is not serving the ones it misses. That is the
    /// whole of the multi-address rule — a node's own address is the one an internal
    /// consumer resolves, and a pool address is the destination public traffic still
    /// carries when it arrives here unrewritten, so an app bound to one family or one
    /// address answers one and refuses the other.
    fn probe_targets(&self, endpoint: &str) -> Vec<String> {
        let mut targets = vec![
            self.host
                .clone()
                .unwrap_or_else(|| FALLBACK_PROBE_HOST.to_owned()),
        ];
        if let Some(delivered_on) = &self.delivered_on {
            for address in delivered_on(endpoint) {
                if !targets.contains(&address) {
                    targets.push(address);
                }
            }
        }
        targets
    }
}

/// Runs one endpoint's probe once, against every address it is served on.
///
/// # Errors
///
/// Returns the operator-facing reason the probe failed: a refused connection, a
/// non-2xx/3xx response, a non-zero exit, or the deadline elapsing. Address-dialing
/// reasons name the address that answered that way, because "which of my addresses"
/// is the whole question when only one of them fails. Reasons are short and never
/// carry param values or other app secrets.
pub async fn run_probe(plan: &EndpointProbePlan, ctx: &ProbeContext) -> Result<(), String> {
    match &plan.kind {
        ProbeKind::Tcp { port } => {
            on_every_address(&ctx.probe_targets(&plan.endpoint), |host| {
                tcp_probe(host, *port, plan.timeout)
            })
            .await
        }
        ProbeKind::Http { port, path, tls } => {
            on_every_address(&ctx.probe_targets(&plan.endpoint), |host| {
                http_probe(host, *port, path, plan.timeout, *tls)
            })
            .await
        }
        // The app's own check, run once: a command probe answers for the app rather
        // than for an address, and has no address to be run against.
        ProbeKind::Command(command) => command_probe(command, plan.timeout, ctx).await,
        // Nothing to poll: the endpoint is as ready as the app is.
        ProbeKind::AppReadiness => Ok(()),
    }
}

/// Dials every address concurrently and passes only when all of them answer,
/// reporting the first failure in address order.
///
/// Concurrent because the endpoint's timeout is a deadline for the probe, not for
/// each address in turn: dialing them one after another would let two addresses take
/// twice the interval and drift the whole loop.
async fn on_every_address<'a, F, Fut>(addresses: &'a [String], probe: F) -> Result<(), String>
where
    F: Fn(&'a str) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    futures_util::future::join_all(addresses.iter().map(|address| probe(address)))
        .await
        .into_iter()
        .find(Result::is_err)
        .unwrap_or(Ok(()))
}

async fn tcp_probe(host: &str, port: u16, timeout: Duration) -> Result<(), String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(err)) => Err(format!("connect to {host} port {port} failed: {err}")),
        Err(_) => Err(format!("connect to {host} port {port} timed out")),
    }
}

async fn http_probe(
    host: &str,
    port: u16,
    path: &str,
    timeout: Duration,
    tls: bool,
) -> Result<(), String> {
    let client = if tls { https_client()? } else { http_client()? };
    // An IPv6 literal only parses as an authority in brackets.
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://{authority}{path}");
    let response = client
        .get(&url)
        .timeout(timeout)
        .send()
        .await
        .map_err(|err| {
            if err.is_timeout() {
                format!("http probe {path} on {host} timed out")
            } else {
                format!("http probe {path} on {host} failed: {err}")
            }
        })?;
    let status = response.status().as_u16();
    // 2xx and 3xx pass: a redirect still proves the endpoint is serving.
    if (200..400).contains(&status) {
        Ok(())
    } else {
        Err(format!("http probe {path} on {host} returned {status}"))
    }
}

/// The process-wide probe client.
///
/// One client for every probe in the process: building one costs a TLS config and
/// a connection pool, and probes tick forever. Redirects are not followed (a 3xx
/// already passes, and chasing one would probe a different endpoint) and proxies
/// are ignored — a probe dials this node's own address and must reach it directly,
/// whatever `HTTP_PROXY` says in the runtime environment. Per-request timeouts
/// keep each endpoint's own deadline.
fn http_client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .ok()
        })
        .as_ref()
        .ok_or_else(|| "http probe client unavailable".to_owned())
}

/// The process-wide probe client for `https` endpoints.
///
/// Identical posture to [`http_client`] (redirects off, no proxy, per-request
/// timeouts) but it does **not** verify the server certificate, deliberately:
///
/// 1. The prober dials this node's own address, not the service name, so
///    hostname/SAN validation is structurally impossible — the cert names the
///    service, never the raw node address the probe connects to.
/// 2. A readiness probe is a liveness check, not the security boundary. The real
///    boundary is the consumer validating the served cert against `ca.bundle`;
///    the probe only asks whether the app is up and answering over TLS.
///
/// This mirrors Kubernetes' HTTPS probe, which likewise skips verification.
fn https_client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
                .ok()
        })
        .as_ref()
        .ok_or_else(|| "https probe client unavailable".to_owned())
}

async fn command_probe(
    command: &CommandValue,
    timeout: Duration,
    ctx: &ProbeContext,
) -> Result<(), String> {
    let mut process = probe_command(command, &ctx.work_dir, &ctx.env)
        .map_err(|err| format!("probe command: {err}"))?;
    // A probe's verdict is its exit status; its chatter would otherwise interleave
    // with the app's own log every tick.
    process.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = process
        .spawn()
        .map_err(|err| format!("probe command failed to start: {err}"))?;
    let Ok(status) = tokio::time::timeout(timeout, child.wait()).await else {
        // Nothing reaps an abandoned probe child, so a slow one must be killed
        // before the next tick spawns its successor.
        let _ = child.kill().await;
        return Err("probe command timed out".to_owned());
    };
    let status = status.map_err(|err| format!("probe command failed: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("probe command exited with {status}"))
    }
}

/// A status change worth reporting, produced by [`ProbeState::observe`].
///
/// Carries no app or endpoint name: the state machine only knows outcomes, and the
/// probe task that owns the names assembles the [`EndpointTransition`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusChange {
    pub status: EndpointStatus,
    pub reason: String,
    /// Zero-based index of this transition for the endpoint.
    pub seq: u64,
}

/// Transition state machine for one endpoint (3 consecutive failures down, 1 success up).
///
/// The asymmetry is deliberate (spec 180): recovery is believed immediately so a
/// restarted endpoint returns to service on the next tick, while a single lost
/// connection — a restart, a GC pause, a dropped packet — must not evict a node
/// from the healthy set.
#[derive(Debug, Default)]
pub struct ProbeState {
    status: EndpointStatus,
    failures: u32,
    transitions: u64,
}

impl ProbeState {
    /// Current status, including the pre-first-probe `Unknown`.
    #[must_use]
    pub fn status(&self) -> EndpointStatus {
        self.status
    }

    /// Number of transitions observed so far — the host runtime uses it to build a
    /// stable per-transition report id (spec 120's dedup rule).
    #[must_use]
    pub fn transitions(&self) -> u64 {
        self.transitions
    }

    /// Feeds one probe outcome; returns `Some(_)` ONLY on a status transition.
    ///
    /// The first outcome always transitions out of `Unknown` — for a success
    /// immediately, for a failure once the threshold is met — so an endpoint that
    /// never passes still reports `unready` rather than staying silent.
    pub fn observe(&mut self, outcome: Result<(), String>) -> Option<StatusChange> {
        match outcome {
            Ok(()) => {
                self.failures = 0;
                self.transition_to(EndpointStatus::Ready, String::new())
            }
            Err(reason) => {
                self.failures = self.failures.saturating_add(1);
                if self.failures < FAILURE_THRESHOLD {
                    return None;
                }
                self.transition_to(EndpointStatus::Unready, reason)
            }
        }
    }

    fn transition_to(&mut self, status: EndpointStatus, reason: String) -> Option<StatusChange> {
        if self.status == status {
            return None;
        }
        self.status = status;
        let seq = self.transitions;
        self.transitions += 1;
        Some(StatusChange {
            status,
            reason,
            seq,
        })
    }
}

/// One reportable transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointTransition {
    pub app: String,
    pub endpoint: String,
    pub status: EndpointStatus,
    pub reason: String,
    pub seq: u64,
}

/// Sink the host runtime supplies; called once per transition, never per tick.
pub type TransitionSink =
    Arc<dyn Fn(EndpointTransition) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Owns one app's endpoint probe tasks. Dropping it stops every probe — that is how a
/// stopped or draining app leaves the endpoint-healthy set (spec 180).
pub struct AppProbes {
    tasks: Vec<JoinHandle<()>>,
}

impl AppProbes {
    /// Spawns one task per planned endpoint. Returns `None` when the app declares no
    /// endpoints, so hosts can keep `Option<AppProbes>` and pay nothing for plain apps.
    ///
    /// Must be called from a Tokio runtime context; the tasks live until the returned
    /// handle is dropped.
    #[must_use]
    // Hosts hand the app name and the sink over for the life of the app; owning them
    // here means a caller never has to outlive the probes it started.
    #[allow(clippy::needless_pass_by_value)]
    pub fn spawn(
        app: String,
        plans: Vec<EndpointProbePlan>,
        ctx: ProbeContext,
        sink: TransitionSink,
    ) -> Option<Self> {
        if plans.is_empty() {
            return None;
        }
        let ctx = Arc::new(ctx);
        let tasks = plans
            .into_iter()
            .map(|plan| {
                let app = app.clone();
                let ctx = Arc::clone(&ctx);
                let sink = Arc::clone(&sink);
                tokio::spawn(probe_loop(app, plan, ctx, sink))
            })
            .collect();
        Some(Self { tasks })
    }
}

impl Drop for AppProbes {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// One endpoint's probe loop: probe, report any transition, wait, repeat.
///
/// The first probe runs with no initial delay so a healthy endpoint reports `ready`
/// as soon as it answers instead of after a whole interval of silence.
async fn probe_loop(
    app: String,
    plan: EndpointProbePlan,
    ctx: Arc<ProbeContext>,
    sink: TransitionSink,
) {
    if matches!(plan.kind, ProbeKind::AppReadiness) {
        // Nothing to poll: report the one transition this endpoint will ever make
        // and stop, leaving its readiness to the app's own.
        sink(EndpointTransition {
            app,
            endpoint: plan.endpoint,
            status: EndpointStatus::Ready,
            reason: String::new(),
            seq: 0,
        })
        .await;
        return;
    }
    let mut state = ProbeState::default();
    loop {
        // The addresses are resolved inside `run_probe`, on this tick: an address
        // drawn or released while the app runs changes what the next probe dials
        // without anything having to restart the loop.
        let outcome = run_probe(&plan, &ctx).await;
        if let Some(change) = state.observe(outcome) {
            sink(EndpointTransition {
                app: app.clone(),
                endpoint: plan.endpoint.clone(),
                status: change.status,
                reason: change.reason,
                seq: change.seq,
            })
            .await;
        }
        tokio::time::sleep(plan.interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppEndpoint;

    fn failure() -> Result<(), String> {
        Err("connection refused".to_owned())
    }

    #[test]
    fn three_consecutive_failures_report_one_unready_transition() {
        let mut state = ProbeState::default();
        assert!(state.observe(failure()).is_none());
        assert!(state.observe(failure()).is_none());
        assert_eq!(state.status(), EndpointStatus::Unknown);

        let change = state.observe(failure()).expect("third failure transitions");
        assert_eq!(change.status, EndpointStatus::Unready);
        assert_eq!(change.reason, "connection refused");
        assert_eq!(change.seq, 0);
        assert_eq!(state.status(), EndpointStatus::Unready);

        // Staying down is not news.
        assert!(state.observe(failure()).is_none());
        assert!(state.observe(failure()).is_none());
        assert_eq!(state.transitions(), 1);
    }

    #[test]
    fn one_success_reports_ready_and_repeats_are_silent() {
        let mut state = ProbeState::default();
        let change = state.observe(Ok(())).expect("first success transitions");
        assert_eq!(change.status, EndpointStatus::Ready);
        assert_eq!(change.seq, 0);
        assert!(state.observe(Ok(())).is_none());
        assert!(state.observe(Ok(())).is_none());
        assert_eq!(state.transitions(), 1);
    }

    #[test]
    fn recovery_reports_ready_with_an_increasing_seq() {
        let mut state = ProbeState::default();
        for _ in 0..FAILURE_THRESHOLD {
            let _ = state.observe(failure());
        }
        let change = state.observe(Ok(())).expect("recovery transitions");
        assert_eq!(change.status, EndpointStatus::Ready);
        assert_eq!(change.seq, 1);
        assert_eq!(state.transitions(), 2);
    }

    #[test]
    fn a_success_resets_the_failure_counter() {
        let mut state = ProbeState::default();
        assert!(state.observe(failure()).is_none());
        assert!(state.observe(failure()).is_none());
        assert!(state.observe(Ok(())).is_some());
        assert!(state.observe(failure()).is_none());
        assert!(state.observe(failure()).is_none());
        assert_eq!(state.status(), EndpointStatus::Ready);
        assert_eq!(state.transitions(), 1);
    }

    #[test]
    fn status_strings_match_the_wire_vocabulary() {
        assert_eq!(EndpointStatus::Unknown.as_str(), "unknown");
        assert_eq!(EndpointStatus::Ready.as_str(), "ready");
        assert_eq!(EndpointStatus::Unready.as_str(), "unready");
    }

    fn endpoint(
        port: u16,
        protocol: EndpointProtocol,
        probe: Option<EndpointProbe>,
    ) -> AppEndpoint {
        AppEndpoint {
            port,
            protocol,
            probe,
            // Readiness is per member whatever the mode says: the probe decides
            // whether *this* member serves, the mode decides who the names offer.
            ..AppEndpoint::default()
        }
    }

    fn config(endpoints: [(&str, AppEndpoint); 1]) -> AppConfig {
        AppConfig {
            endpoints: endpoints
                .into_iter()
                .map(|(name, endpoint)| (name.to_owned(), endpoint))
                .collect(),
            ..AppConfig::default()
        }
    }

    fn only_plan(config: &AppConfig) -> EndpointProbePlan {
        let mut plans = plan_endpoint_probes(config);
        assert_eq!(plans.len(), 1);
        plans.remove(0)
    }

    #[test]
    fn tcp_and_http_endpoints_default_to_a_connect_probe() {
        let tcp = only_plan(&config([(
            "pg",
            endpoint(5432, EndpointProtocol::Tcp, None),
        )]));
        assert_eq!(tcp.kind, ProbeKind::Tcp { port: 5432 });
        assert_eq!(tcp.interval, DEFAULT_PROBE_INTERVAL);
        assert_eq!(tcp.timeout, DEFAULT_PROBE_TIMEOUT);

        let http = only_plan(&config([(
            "api",
            endpoint(8080, EndpointProtocol::Http, None),
        )]));
        assert_eq!(http.kind, ProbeKind::Tcp { port: 8080 });
    }

    #[test]
    fn an_https_endpoint_defaults_to_a_connect_probe() {
        let https = only_plan(&config([(
            "api",
            endpoint(8443, EndpointProtocol::Https, None),
        )]));
        assert_eq!(https.kind, ProbeKind::Tcp { port: 8443 });
    }

    #[test]
    fn a_declared_http_probe_on_an_https_endpoint_dials_over_tls() {
        let plan = only_plan(&config([(
            "api",
            endpoint(
                8443,
                EndpointProtocol::Https,
                Some(EndpointProbe {
                    http: Some("/healthz".to_owned()),
                    ..EndpointProbe::default()
                }),
            ),
        )]));
        assert_eq!(
            plan.kind,
            ProbeKind::Http {
                port: 8443,
                path: "/healthz".to_owned(),
                tls: true,
            }
        );
    }

    #[test]
    fn a_declared_http_probe_becomes_an_http_get() {
        let plan = only_plan(&config([(
            "api",
            endpoint(
                8080,
                EndpointProtocol::Http,
                Some(EndpointProbe {
                    http: Some("/healthz".to_owned()),
                    interval: Some("5s".to_owned()),
                    timeout: Some("2s".to_owned()),
                    ..EndpointProbe::default()
                }),
            ),
        )]));
        assert_eq!(
            plan.kind,
            ProbeKind::Http {
                port: 8080,
                path: "/healthz".to_owned(),
                tls: false,
            }
        );
        assert_eq!(plan.interval, Duration::from_secs(5));
        assert_eq!(plan.timeout, Duration::from_secs(2));
    }

    #[test]
    fn udp_endpoints_follow_app_readiness_unless_they_declare_a_command() {
        let bare = only_plan(&config([(
            "gossip",
            endpoint(7946, EndpointProtocol::Udp, None),
        )]));
        assert_eq!(bare.kind, ProbeKind::AppReadiness);

        let checked = only_plan(&config([(
            "gossip",
            endpoint(
                7946,
                EndpointProtocol::Udp,
                Some(EndpointProbe {
                    command: Some(CommandValue::Argv(vec![
                        "check".to_owned(),
                        "gossip".to_owned(),
                    ])),
                    ..EndpointProbe::default()
                }),
            ),
        )]));
        match checked.kind {
            ProbeKind::Command(CommandValue::Argv(argv)) => assert_eq!(argv, ["check", "gossip"]),
            other => panic!("expected a command probe, got {other:?}"),
        }
    }

    #[test]
    fn tcp_false_opts_out_of_the_default_connect_probe() {
        let plan = only_plan(&config([(
            "pg",
            endpoint(
                5432,
                EndpointProtocol::Tcp,
                Some(EndpointProbe {
                    tcp: Some(false),
                    ..EndpointProbe::default()
                }),
            ),
        )]));
        assert_eq!(plan.kind, ProbeKind::AppReadiness);
    }

    #[test]
    fn a_probe_with_only_timing_keeps_the_protocol_default() {
        let plan = only_plan(&config([(
            "pg",
            endpoint(
                5432,
                EndpointProtocol::Tcp,
                Some(EndpointProbe {
                    interval: Some("1m".to_owned()),
                    ..EndpointProbe::default()
                }),
            ),
        )]));
        assert_eq!(plan.kind, ProbeKind::Tcp { port: 5432 });
        assert_eq!(plan.interval, Duration::from_secs(60));
    }

    #[test]
    fn unparseable_and_zero_timings_fall_back_to_the_defaults() {
        let plan = only_plan(&config([(
            "pg",
            endpoint(
                5432,
                EndpointProtocol::Tcp,
                Some(EndpointProbe {
                    tcp: Some(true),
                    interval: Some("soon".to_owned()),
                    timeout: Some("0s".to_owned()),
                    ..EndpointProbe::default()
                }),
            ),
        )]));
        assert_eq!(plan.interval, DEFAULT_PROBE_INTERVAL);
        assert_eq!(plan.timeout, DEFAULT_PROBE_TIMEOUT);
    }

    #[test]
    fn plans_are_ordered_by_endpoint_name() {
        let config = AppConfig {
            endpoints: ["pg", "api", "metrics"]
                .into_iter()
                .map(|name| (name.to_owned(), endpoint(5432, EndpointProtocol::Tcp, None)))
                .collect(),
            ..AppConfig::default()
        };
        let names: Vec<_> = plan_endpoint_probes(&config)
            .into_iter()
            .map(|plan| plan.endpoint)
            .collect();
        assert_eq!(names, ["api", "metrics", "pg"]);
        assert!(plan_endpoint_probes(&AppConfig::default()).is_empty());
    }

    #[tokio::test]
    async fn tcp_probe_passes_on_a_listening_port_and_fails_on_a_closed_one() {
        let listener = tokio::net::TcpListener::bind((FALLBACK_PROBE_HOST, 0))
            .await
            .expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let ctx = ProbeContext::default();
        run_probe(
            &planned(ProbeKind::Tcp { port }, Duration::from_secs(1)),
            &ctx,
        )
        .await
        .expect("listening port passes");

        drop(listener);
        let reason = run_probe(
            &planned(ProbeKind::Tcp { port }, Duration::from_secs(1)),
            &ctx,
        )
        .await
        .expect_err("closed port fails");
        assert!(reason.contains(&port.to_string()), "{reason}");
    }

    /// One endpoint's plan, for the probe-running tests: the kind and the deadline
    /// are what they exercise, and the name is what resolves the addresses to dial.
    fn planned(kind: ProbeKind, timeout: Duration) -> EndpointProbePlan {
        EndpointProbePlan {
            endpoint: "pg".to_owned(),
            kind,
            interval: DEFAULT_PROBE_INTERVAL,
            timeout,
        }
    }

    fn ctx_on(host: &str) -> ProbeContext {
        ProbeContext {
            host: Some(host.to_owned()),
            ..ProbeContext::default()
        }
    }

    /// A context whose endpoint is delivered on `addresses` as well as on `host` —
    /// the shape a publicly exposed endpoint on a member holding a pool address has.
    fn ctx_delivered_on(host: &str, addresses: &[&str]) -> ProbeContext {
        let addresses: Vec<String> = addresses.iter().map(|a| (*a).to_owned()).collect();
        ProbeContext {
            delivered_on: Some(Arc::new(move |_endpoint: &str| addresses.clone())),
            ..ctx_on(host)
        }
    }

    #[tokio::test]
    async fn probes_dial_the_context_address_not_loopback() {
        let listener = tokio::net::TcpListener::bind((FALLBACK_PROBE_HOST, 0))
            .await
            .expect("listener");
        let port = listener.local_addr().expect("addr").port();

        // TEST-NET-1: nothing answers, so reaching the loopback listener anyway would
        // mean the probe ignored the node address it was handed.
        let reason = run_probe(
            &planned(ProbeKind::Tcp { port }, Duration::from_millis(250)),
            &ctx_on("192.0.2.1"),
        )
        .await
        .expect_err("a probe aimed elsewhere must not reach loopback");
        assert!(reason.contains(&port.to_string()), "{reason}");

        run_probe(
            &planned(ProbeKind::Tcp { port }, Duration::from_secs(1)),
            &ctx_on(FALLBACK_PROBE_HOST),
        )
        .await
        .expect("the same port passes when the address points at it");
    }

    /// The failure a single-address probe called healthy: an app that binds one
    /// address family alone answers the node's own address and refuses the address
    /// public traffic arrives on — a member admitted to the serving set and then
    /// dark to every client that reaches it there.
    ///
    /// The probe must fail, and the reason must name the address that refused:
    /// "it is listening" and "it is listening where I am sending traffic" are
    /// different statements, and only the second one admits a member.
    #[tokio::test]
    async fn an_endpoint_answering_one_address_fails_the_one_it_is_delivered_on() {
        // AF_INET only, the way a `0.0.0.0` bind is.
        let listener = tokio::net::TcpListener::bind((FALLBACK_PROBE_HOST, 0))
            .await
            .expect("listener");
        let port = listener.local_addr().expect("addr").port();

        let reason = run_probe(
            &planned(ProbeKind::Tcp { port }, Duration::from_millis(250)),
            &ctx_delivered_on(FALLBACK_PROBE_HOST, &["::1"]),
        )
        .await
        .expect_err("an address the app does not answer on fails the probe");
        assert!(reason.contains("::1"), "{reason}");
        assert!(reason.contains(&port.to_string()), "{reason}");

        // The same app, same port: probing the node address alone is what called it
        // ready, which is the whole of the bug.
        run_probe(
            &planned(ProbeKind::Tcp { port }, Duration::from_secs(1)),
            &ctx_on(FALLBACK_PROBE_HOST),
        )
        .await
        .expect("the node address alone answers, which is why this looked healthy");
    }

    /// An app answering both address families passes every delivered-address probe.
    #[tokio::test]
    async fn an_endpoint_answering_every_delivered_address_is_ready() {
        // Bind loopback in each family explicitly: Windows defaults IPv6 sockets
        // to IPv6-only, while Unix wildcard listeners may accept both families.
        let Ok(ipv6) = tokio::net::TcpListener::bind("[::1]:0").await else {
            return;
        };
        let port = ipv6.local_addr().expect("addr").port();
        let _ipv4 = tokio::net::TcpListener::bind((FALLBACK_PROBE_HOST, port))
            .await
            .expect("IPv4 listener on the same port");

        run_probe(
            &planned(ProbeKind::Tcp { port }, Duration::from_secs(1)),
            &ctx_delivered_on(FALLBACK_PROBE_HOST, &["::1"]),
        )
        .await
        .expect("both listeners answer their delivered addresses");
    }

    /// An app bound to the node's routable address alone — the false negative a
    /// loopback probe produced. Linux-only: it needs a second local address.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_endpoint_bound_off_loopback_probes_ready_on_the_node_address() {
        const NODE_HOST: &str = "127.0.0.2";

        let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind((NODE_HOST, 0))
            .await
            .expect("listener");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let http = ProbeKind::Http {
            port,
            path: "/healthz".to_owned(),
            tls: false,
        };
        run_probe(
            &planned(ProbeKind::Tcp { port }, Duration::from_secs(1)),
            &ctx_on(NODE_HOST),
        )
        .await
        .expect("tcp probe reaches the node address");
        run_probe(
            &planned(http.clone(), Duration::from_secs(2)),
            &ctx_on(NODE_HOST),
        )
        .await
        .expect("http probe reaches the node address");

        // Without an address the probe falls back to loopback and misses the endpoint.
        let ctx = ProbeContext::default();
        run_probe(
            &planned(ProbeKind::Tcp { port }, Duration::from_millis(250)),
            &ctx,
        )
        .await
        .expect_err("loopback does not serve this endpoint");
        run_probe(&planned(http, Duration::from_millis(250)), &ctx)
            .await
            .expect_err("loopback does not serve this endpoint");
    }

    #[test]
    fn an_unknown_node_address_falls_back_to_loopback() {
        assert_eq!(
            ProbeContext::default().probe_targets("pg"),
            [FALLBACK_PROBE_HOST]
        );
        assert_eq!(ctx_on("10.0.0.7").probe_targets("pg"), ["10.0.0.7"]);
    }

    /// A node holding no pool address probes exactly what it always did: its own
    /// address, once. The delivery reader is consulted and answers nothing — for an
    /// endpoint exposed inside the project it always will — and nothing is added.
    #[test]
    fn an_endpoint_delivered_nowhere_else_probes_the_node_address_alone() {
        let ctx = ProbeContext {
            delivered_on: Some(Arc::new(|_endpoint: &str| Vec::new())),
            ..ctx_on("10.0.0.7")
        };
        assert_eq!(ctx.probe_targets("pg"), ["10.0.0.7"]);
    }

    /// The delivery addresses follow the node's own, in the order the reader gave
    /// them, and an address that *is* the node's own is not dialed twice.
    #[test]
    fn delivery_addresses_extend_the_node_address_without_repeating_it() {
        let ctx = ctx_delivered_on("10.0.0.7", &["2001:db8::5", "10.0.0.7", "203.0.113.5"]);
        assert_eq!(
            ctx.probe_targets("pg"),
            ["10.0.0.7", "2001:db8::5", "203.0.113.5"]
        );
    }

    /// The reader is called on every probe, not captured when the app starts: an
    /// address drawn under a running app is dialed by the next tick.
    #[test]
    fn delivery_addresses_are_read_on_every_probe() {
        let drawn = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ctx = ProbeContext {
            delivered_on: Some(Arc::new({
                let drawn = Arc::clone(&drawn);
                move |_endpoint: &str| {
                    if drawn.load(std::sync::atomic::Ordering::Relaxed) {
                        vec!["2001:db8::5".to_owned()]
                    } else {
                        Vec::new()
                    }
                }
            })),
            ..ctx_on("10.0.0.7")
        };
        assert_eq!(ctx.probe_targets("pg"), ["10.0.0.7"]);
        drawn.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(ctx.probe_targets("pg"), ["10.0.0.7", "2001:db8::5"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_probe_passes_on_exit_zero_and_fails_otherwise() {
        let dir = tempfile::tempdir().expect("work dir");
        let ctx = ProbeContext {
            work_dir: dir.path().to_path_buf(),
            ..ProbeContext::default()
        };
        run_probe(
            &planned(
                ProbeKind::Command(CommandValue::String("exit 0".to_owned())),
                Duration::from_secs(1),
            ),
            &ctx,
        )
        .await
        .expect("exit 0 passes");

        let reason = run_probe(
            &planned(
                ProbeKind::Command(CommandValue::String("exit 1".to_owned())),
                Duration::from_secs(1),
            ),
            &ctx,
        )
        .await
        .expect_err("exit 1 fails");
        assert!(reason.contains("exited with"), "{reason}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_probe_that_outlives_its_timeout_fails_as_a_timeout() {
        let dir = tempfile::tempdir().expect("work dir");
        let ctx = ProbeContext {
            work_dir: dir.path().to_path_buf(),
            ..ProbeContext::default()
        };
        let reason = run_probe(
            &planned(
                ProbeKind::Command(CommandValue::String("sleep 30".to_owned())),
                Duration::from_millis(200),
            ),
            &ctx,
        )
        .await
        .expect_err("a hung probe fails");
        assert!(reason.contains("timed out"), "{reason}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_probes_run_in_the_app_work_dir_with_the_param_environment() {
        let dir = tempfile::tempdir().expect("work dir");
        let ctx = ProbeContext {
            work_dir: dir.path().to_path_buf(),
            env: BTreeMap::from([("PGDATA".to_owned(), "ok".to_owned())]),
            ..ProbeContext::default()
        };
        run_probe(
            &planned(
                ProbeKind::Command(CommandValue::String(
                    r#"test "$PGDATA" = ok && test "$PWD" = "$(pwd -P)""#.to_owned(),
                )),
                Duration::from_secs(1),
            ),
            &ctx,
        )
        .await
        .expect("probe sees the param environment");
        // The command ran with the work dir as its cwd: writing a relative path lands there.
        run_probe(
            &planned(
                ProbeKind::Command(CommandValue::String("touch probe-ran".to_owned())),
                Duration::from_secs(1),
            ),
            &ctx,
        )
        .await
        .expect("probe runs");
        assert!(dir.path().join("probe-ran").exists());
    }

    /// Serves the three answers an http probe must classify, on loopback.
    async fn http_probe_server() -> u16 {
        let app = axum::Router::new()
            .route("/healthz", axum::routing::get(|| async { "ok" }))
            .route(
                "/moved",
                axum::routing::get(|| async {
                    (
                        axum::http::StatusCode::FOUND,
                        [(axum::http::header::LOCATION, "/healthz")],
                    )
                }),
            )
            .route(
                "/down",
                axum::routing::get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
            );
        let listener = tokio::net::TcpListener::bind((FALLBACK_PROBE_HOST, 0))
            .await
            .expect("probe server listener");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        port
    }

    #[tokio::test]
    async fn http_probe_passes_on_2xx_and_3xx_and_fails_on_5xx() {
        let port = http_probe_server().await;
        let ctx = ProbeContext::default();
        let probe = |path: &str| ProbeKind::Http {
            port,
            path: path.to_owned(),
            tls: false,
        };

        run_probe(&planned(probe("/healthz"), Duration::from_secs(2)), &ctx)
            .await
            .expect("200 passes");
        // A redirect is not followed — answering at all proves the endpoint serves.
        run_probe(&planned(probe("/moved"), Duration::from_secs(2)), &ctx)
            .await
            .expect("302 passes");

        let reason = run_probe(&planned(probe("/down"), Duration::from_secs(2)), &ctx)
            .await
            .expect_err("503 fails");
        assert!(reason.contains("503"), "{reason}");

        // An unrouted path answers 404: serving is not the same as being ready.
        let reason = run_probe(&planned(probe("/missing"), Duration::from_secs(2)), &ctx)
            .await
            .expect_err("404 fails");
        assert!(reason.contains("404"), "{reason}");
    }

    /// A minimal TLS listener serving one `200 OK` per connection under a fresh
    /// self-signed cert. It exists to prove the https probe both speaks TLS and
    /// accepts a cert no CA vouches for.
    async fn https_probe_server() -> u16 {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("self-signed cert");
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
            .expect("key der");
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let tls_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));

        let listener = tokio::net::TcpListener::bind((FALLBACK_PROBE_HOST, 0))
            .await
            .expect("tls listener");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    // Drain the request line/headers enough to answer; a probe sends
                    // a bare GET, so one read reaches the blank-line terminator.
                    let mut buf = [0_u8; 1024];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn https_probe_dials_over_tls_and_accepts_a_self_signed_cert() {
        let port = https_probe_server().await;
        let ctx = ProbeContext::default();
        let probe = ProbeKind::Http {
            port,
            path: "/healthz".to_owned(),
            tls: true,
        };
        run_probe(&planned(probe, Duration::from_secs(5)), &ctx)
            .await
            .expect("https probe reaches the app over TLS and ignores the self-signed cert");

        // The cleartext client would refuse the TLS handshake: proof the https path
        // selects the accept-invalid client and the https scheme, not the http one.
        let cleartext = ProbeKind::Http {
            port,
            path: "/healthz".to_owned(),
            tls: false,
        };
        run_probe(&planned(cleartext, Duration::from_secs(5)), &ctx)
            .await
            .expect_err("cleartext http cannot speak to a TLS listener");
    }

    fn channel_sink() -> (
        TransitionSink,
        tokio::sync::mpsc::UnboundedReceiver<EndpointTransition>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let sink: TransitionSink = Arc::new(move |transition| {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(transition);
            })
        });
        (sink, rx)
    }

    #[tokio::test]
    async fn app_probes_report_one_ready_transition_and_stop_when_dropped() {
        let listener = tokio::net::TcpListener::bind((FALLBACK_PROBE_HOST, 0))
            .await
            .expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let (sink, mut rx) = channel_sink();
        let probes = AppProbes::spawn(
            "pg".to_owned(),
            vec![EndpointProbePlan {
                endpoint: "sql".to_owned(),
                kind: ProbeKind::Tcp { port },
                interval: Duration::from_millis(20),
                timeout: Duration::from_millis(200),
            }],
            ProbeContext::default(),
            sink,
        )
        .expect("an app with endpoints spawns probes");

        let transition = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("a transition arrives")
            .expect("sink alive");
        assert_eq!(
            transition,
            EndpointTransition {
                app: "pg".to_owned(),
                endpoint: "sql".to_owned(),
                status: EndpointStatus::Ready,
                // A ready transition explains nothing: `reason` carries probe failures.
                reason: String::new(),
                seq: 0,
            }
        );

        // Ticks are never reported: only the first pass transitions.
        drop(probes);
        drop(listener);
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            rx.try_recv().is_err(),
            "a dropped handle must stop every probe"
        );
    }

    #[tokio::test]
    async fn an_app_without_endpoints_spawns_nothing() {
        let (sink, _rx) = channel_sink();
        assert!(
            AppProbes::spawn(
                "plain".to_owned(),
                Vec::new(),
                ProbeContext::default(),
                sink
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn an_app_readiness_endpoint_reports_ready_once_and_parks() {
        let (sink, mut rx) = channel_sink();
        let _probes = AppProbes::spawn(
            "gossip".to_owned(),
            vec![EndpointProbePlan {
                endpoint: "peers".to_owned(),
                kind: ProbeKind::AppReadiness,
                interval: Duration::from_millis(20),
                timeout: Duration::from_millis(200),
            }],
            ProbeContext::default(),
            sink,
        )
        .expect("spawned");
        let transition = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("a transition arrives")
            .expect("sink alive");
        assert_eq!(transition.status, EndpointStatus::Ready);
        assert_eq!(transition.seq, 0);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(rx.try_recv().is_err(), "an unprobed endpoint reports once");
    }
}
