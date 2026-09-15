//! The `endpoint.*` sourced-param rules, shared by both app runtimes.
//!
//! An app that needs its own address — a base URL for absolute links, an OAuth
//! callback, a `root_url` — declares an `endpoint.name`/`endpoint.port`/`endpoint.url`
//! param and the platform fills it in. Different host runtimes obtain the endpoint
//! surface from their own state, then use these shared rules to resolve it.
//!
//! Everything **after** those facts lives here: which endpoint a declaration means,
//! which zone its canonical name hangs under, how a URL is spelled, and the exact
//! wording of every refusal. One implementation, so the two runtimes cannot drift
//! into telling an author two different stories about the same package — and so the
//! wording is pinned by the tests at the bottom of this file rather than by matching
//! assertions maintained on both sides.

/// Which fact about an endpoint one `endpoint.*` source kind asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointFact {
    Name,
    Port,
    Url,
}

impl EndpointFact {
    /// The fact an `x-source` kind asks for, or `None` when the kind is not one of
    /// the endpoint kinds. Both runtimes dispatch through this, so neither can come
    /// to support a kind the other does not.
    #[must_use]
    pub fn from_kind(kind: &str) -> Option<Self> {
        match kind {
            "endpoint.name" => Some(Self::Name),
            "endpoint.port" => Some(Self::Port),
            "endpoint.url" => Some(Self::Url),
            _ => None,
        }
    }

    /// The source kind this fact belongs to, as the error messages name it.
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Self::Name => "endpoint.name",
            Self::Port => "endpoint.port",
            Self::Url => "endpoint.url",
        }
    }
}

/// One endpoint of a deployment's settled surface, as an `endpoint.*` source reads
/// it. Borrowed: each runtime owns its rows in its own shape and lends them here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceEndpoint<'a> {
    /// Endpoint name, unique across the pool's assignments.
    pub endpoint: &'a str,
    /// The protocol the package **declared** — `tcp` | `udp` | `http` | `https` —
    /// never the transport it collapses to. Empty means the runtime could not learn
    /// it, which is a refusal rather than a guess ([`Refusal::FactsUnavailable`]).
    pub declared_protocol: &'a str,
    /// Effective listen port: declared, with the deployment's override applied.
    pub port: u16,
    /// `project` | `org` | `public`.
    pub expose: &'a str,
    /// Service name the request chose, or `None` when the endpoint answers under the
    /// pool's own derived name alone.
    pub service_name: Option<&'a str>,
    /// The org zone (`{org}.{domain}`) this endpoint's public name was **settled**
    /// under, empty for a surface settled before names were stamped.
    ///
    /// A public name belongs to the domain that was active when its pool's surface
    /// was settled, not to whatever is active now: a zone that adds a domain must
    /// not rename a service that has not been reconfigured. Empty falls back to the
    /// zone naming below, which is what an older runtime or incomplete state snapshot
    /// still answers with.
    pub public_zone: &'a str,
}

impl SurfaceEndpoint<'_> {
    /// Whether this endpoint is exposed to the internet.
    #[must_use]
    pub fn is_public(&self) -> bool {
        is_public_scope(self.expose)
    }
}

/// Whether an exposure scope is the public one.
///
/// Spelled over the projected string rather than a parsed enum because that is the
/// shape both runtimes carry; an unreadable value is not public, which can only
/// narrow an answer. Shared so that every reader of a pushed scope — a canonical
/// name, an endpoint probe's delivery addresses — asks the same question of it.
#[must_use]
pub fn is_public_scope(expose: &str) -> bool {
    expose == "public"
}

/// The labels a canonical name hangs under, plus the pool whose derived name an
/// undecorated endpoint falls back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneNaming<'a> {
    /// The org's code — the first label of its public zone `{org}.{base}`.
    pub org_code: &'a str,
    /// The project's code — the first label of its internal zone `{project}.{suffix}`.
    pub project_code: &'a str,
    /// The zone's internal DNS suffix.
    pub internal_suffix: &'a str,
    /// The zone's public base domain. Empty means the deployment does no public
    /// naming at all, so public names do not exist to fall back *from*.
    pub public_base_domain: &'a str,
    /// The pool's own derived name.
    pub pool_name: &'a str,
}

/// Why an `endpoint.*` declaration could not be answered.
///
/// Every variant here is deterministic: a replacement node under the same assignment
/// and the same pushed state would fail identically, so both runtimes report these as
/// configuration failures rather than retrying. Guessing instead — the first
/// endpoint, the lowest port, `tcp` for an unknown protocol — would hand an app a
/// plausible address for the wrong port, and only whoever eventually connected would
/// find out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The app declares no endpoints at all.
    NoEndpoints,
    /// Several endpoints and no `params.endpoint` to choose between them.
    Ambiguous,
    /// `params.endpoint` names an endpoint the app does not declare.
    Undeclared,
    /// The runtime holds the endpoint but not the facts a name or a scheme is built from.
    FactsUnavailable,
}

/// `{label}.{zone}` — a qualified name, and the only place the two are joined.
#[must_use]
pub fn qualify(label: &str, zone: &str) -> String {
    format!("{label}.{zone}")
}

/// `{project}.{suffix}` — a project's internal zone.
#[must_use]
pub fn internal_zone(project: &str, suffix: &str) -> String {
    format!("{project}.{suffix}")
}

/// `{org}.{base}` — an org's public zone, or `None` when either half is missing.
///
/// A deployment with no public base domain has no public zone, and therefore no
/// public names: that is not a degraded state to warn about, it is simply a
/// deployment that does not do public naming.
#[must_use]
pub fn org_zone(org_code: &str, public_base_domain: &str) -> Option<String> {
    if public_base_domain.is_empty() || org_code.is_empty() {
        return None;
    }
    Some(qualify(org_code, public_base_domain))
}

/// The endpoint an `endpoint.*` declaration means: the one `requested` names, or the
/// app's sole endpoint when it names none.
///
/// # Errors
///
/// Returns the [`Refusal`] and the message an author has to act on.
pub fn select<'a, 'e>(
    declared: &'a [SurfaceEndpoint<'e>],
    app: &str,
    requested: Option<&str>,
) -> Result<&'a SurfaceEndpoint<'e>, (Refusal, String)> {
    let names = || {
        declared
            .iter()
            .map(|entry| entry.endpoint)
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(wanted) = requested.filter(|name| !name.is_empty()) {
        return declared
            .iter()
            .find(|entry| entry.endpoint == wanted)
            .ok_or_else(|| {
                if declared.is_empty() {
                    (
                        Refusal::NoEndpoints,
                        format!(
                            "app {app:?} declares no endpoints, so {wanted:?} cannot be \
                             sourced; declare the endpoint in the app package or drop this param"
                        ),
                    )
                } else {
                    (
                        Refusal::Undeclared,
                        format!(
                            "app {app:?} declares no endpoint {wanted:?}; set params.endpoint \
                             to one of: {}",
                            names()
                        ),
                    )
                }
            });
    }
    match declared {
        [] => Err((
            Refusal::NoEndpoints,
            format!(
                "app {app:?} declares no endpoints, so there is none to source; declare an \
                 endpoint in the app package or drop this param"
            ),
        )),
        [only] => Ok(only),
        many => Err((
            Refusal::Ambiguous,
            format!(
                "app {app:?} declares {} endpoints ({}), so the sole-endpoint default does \
                 not apply; set params.endpoint to the one this param means",
                many.len(),
                names()
            ),
        )),
    }
}

/// The endpoint's canonical FQDN — its public name where it is publicly exposed, its
/// internal one everywhere else.
///
/// A publicly exposed service presents a public certificate, which cannot carry an
/// internal SAN, so the public name is the name it is known by *everywhere* —
/// including from inside the project, where the resolver answers it with overlay
/// member addresses. A zone that configures no public base domain has no public names
/// at all, so an endpoint exposed there still answers to its internal one.
///
/// The label is the service name the request chose, falling back to the pool's own
/// derived name, which always exists — the same default the public record derivation
/// applies.
#[must_use]
pub fn canonical_name(endpoint: &SurfaceEndpoint<'_>, naming: &ZoneNaming<'_>) -> String {
    let label = endpoint.service_name.unwrap_or(naming.pool_name);
    if endpoint.is_public() {
        // The zone the surface settled under wins over the one configured now: the
        // name an app is handed has to be the name its records and its certificate
        // carry, and those are settlement-bound too.
        if !endpoint.public_zone.is_empty() {
            return qualify(label, endpoint.public_zone);
        }
        if let Some(zone) = org_zone(naming.org_code, naming.public_base_domain) {
            return qualify(label, &zone);
        }
    }
    qualify(
        label,
        &internal_zone(naming.project_code, naming.internal_suffix),
    )
}

/// `{scheme}://{fqdn}` with the port appended unless it is the scheme's default.
///
/// The scheme is the **declared protocol**, never the exposure scope: `https` and
/// `http` are the schemes of the endpoints declared as such, and a `tcp`/`udp`
/// endpoint gets its transport's name so the value is still a parseable URL. Nothing
/// upgrades a scheme on exposure — a plaintext `http` endpoint cannot be publicly
/// exposed at all, submission rejects it, so the two can never disagree.
///
/// A web scheme on its default port elides it, matching what a browser and every link
/// a console renders would do; every other combination carries `:{port}`, the
/// transport schemes included — they have no default to elide.
#[must_use]
pub fn endpoint_url(endpoint: &SurfaceEndpoint<'_>, fqdn: &str) -> String {
    let scheme = endpoint.declared_protocol;
    let default_port = match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };
    if default_port == Some(endpoint.port) {
        format!("{scheme}://{fqdn}")
    } else {
        format!("{scheme}://{fqdn}:{}", endpoint.port)
    }
}

/// The refusal a runtime raises when it holds endpoints but not the facts they are
/// named from.
///
/// `subject` names what arrived incomplete, the way the runtime can see it: one
/// endpoint where that is what was inspected, the whole pushed surface where the
/// absence is wholesale. Built here rather than spelled at each call site so the
/// sentence an author reads is the same wherever it is raised.
#[must_use]
pub fn facts_unavailable(param: &str, fact: EndpointFact, subject: &str) -> (Refusal, String) {
    (
        Refusal::FactsUnavailable,
        format!(
            "x-source param {param:?} ({}): {subject} arrived without endpoint exposure \
             facts, so this runtime cannot name it; refresh the deployment metadata",
            fact.kind()
        ),
    )
}

/// One `endpoint.*` param, resolved end to end: pick the endpoint, then answer the
/// fact that was asked for.
///
/// # Errors
///
/// Returns the [`Refusal`] and its message, already prefixed with the param and the
/// source kind — the whole string a runtime reports, so neither of them spells it.
pub fn resolve(
    param: &str,
    fact: EndpointFact,
    declared: &[SurfaceEndpoint<'_>],
    app: &str,
    requested: Option<&str>,
    naming: &ZoneNaming<'_>,
) -> Result<String, (Refusal, String)> {
    let fail = |(refusal, detail): (Refusal, String)| {
        (
            refusal,
            format!("x-source param {param:?} ({}): {detail}", fact.kind()),
        )
    };
    let endpoint = select(declared, app, requested).map_err(fail)?;
    // A surface row that reached us without its declared protocol came from a server
    // that predates the field. Nothing here can be recovered from it: the scheme is
    // that value, and the exposure it travels with decides the zone — so refuse
    // rather than hand back `://host` or an internal name for a public service.
    //
    // The backstop, not the whole check: a runtime that can see its surface is
    // wholesale stale should say so *before* narrowing it to one app, or an old
    // server's missing `app` turns into "your app declares no endpoints" and sends
    // the author to edit a package that is fine.
    if endpoint.declared_protocol.is_empty() {
        return Err(facts_unavailable(
            param,
            fact,
            &format!("endpoint {:?}", endpoint.endpoint),
        ));
    }
    Ok(match fact {
        EndpointFact::Name => canonical_name(endpoint, naming),
        EndpointFact::Port => endpoint.port.to_string(),
        EndpointFact::Url => endpoint_url(endpoint, &canonical_name(endpoint, naming)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface<'a>(
        endpoint: &'a str,
        declared_protocol: &'a str,
        port: u16,
    ) -> SurfaceEndpoint<'a> {
        SurfaceEndpoint {
            endpoint,
            declared_protocol,
            port,
            expose: "project",
            service_name: None,
            public_zone: "",
        }
    }

    fn naming() -> ZoneNaming<'static> {
        ZoneNaming {
            org_code: "acme",
            project_code: "demo",
            internal_suffix: "internal",
            public_base_domain: "",
            pool_name: "db",
        }
    }

    fn resolved(
        fact: EndpointFact,
        declared: &[SurfaceEndpoint<'_>],
        requested: Option<&str>,
        naming: &ZoneNaming<'_>,
    ) -> Result<String, (Refusal, String)> {
        resolve("value", fact, declared, "db", requested, naming)
    }

    #[test]
    fn the_kinds_map_to_facts_and_back() {
        for (kind, fact) in [
            ("endpoint.name", EndpointFact::Name),
            ("endpoint.port", EndpointFact::Port),
            ("endpoint.url", EndpointFact::Url),
        ] {
            assert_eq!(EndpointFact::from_kind(kind), Some(fact));
            assert_eq!(fact.kind(), kind);
        }
        assert_eq!(EndpointFact::from_kind("endpoint.host"), None);
        assert_eq!(EndpointFact::from_kind("peers.first"), None);
    }

    #[test]
    fn a_sole_endpoint_is_the_default() {
        let declared = [surface("pg", "tcp", 5432)];
        assert_eq!(
            resolved(EndpointFact::Name, &declared, None, &naming()).expect("name"),
            "db.demo.internal"
        );
        assert_eq!(
            resolved(EndpointFact::Port, &declared, None, &naming()).expect("port"),
            "5432"
        );
        assert_eq!(
            resolved(EndpointFact::Url, &declared, None, &naming()).expect("url"),
            "tcp://db.demo.internal:5432"
        );
    }

    #[test]
    fn the_endpoint_param_picks_one_of_several() {
        let declared = [surface("metrics", "http", 9187), surface("pg", "tcp", 5432)];
        assert_eq!(
            resolved(EndpointFact::Url, &declared, Some("metrics"), &naming()).expect("url"),
            "http://db.demo.internal:9187"
        );
        assert_eq!(
            resolved(EndpointFact::Port, &declared, Some("pg"), &naming()).expect("port"),
            "5432"
        );
    }

    /// A settled surface names itself under the zone it was settled on, whatever the
    /// zone is configured with now (spec 183): the name an app is handed has to be
    /// the name its records and its certificate carry.
    #[test]
    fn a_settled_public_endpoint_keeps_the_zone_it_settled_under() {
        let naming = ZoneNaming {
            public_base_domain: "orc8r.app",
            ..naming()
        };
        let declared = [SurfaceEndpoint {
            expose: "public",
            service_name: Some("shop"),
            public_zone: "acme.v0.orc8r.com",
            ..surface("web", "https", 443)
        }];
        assert_eq!(
            resolved(EndpointFact::Name, &declared, Some("web"), &naming).expect("settled"),
            "shop.acme.v0.orc8r.com"
        );
        assert_eq!(
            resolved(EndpointFact::Url, &declared, Some("web"), &naming).expect("settled url"),
            "https://shop.acme.v0.orc8r.com"
        );

        // An unstamped surface — settled before names were stamped, or pushed by an
        // older server — still falls back to the zone the snapshot names.
        let unstamped = [SurfaceEndpoint {
            expose: "public",
            service_name: Some("shop"),
            ..surface("web", "https", 443)
        }];
        assert_eq!(
            resolved(EndpointFact::Name, &unstamped, Some("web"), &naming).expect("fallback"),
            "shop.acme.orc8r.app"
        );
    }

    #[test]
    fn a_public_endpoint_is_named_publicly_and_a_project_one_internally() {
        let naming = ZoneNaming {
            public_base_domain: "v0.orc8r.com",
            ..naming()
        };
        let declared = [
            SurfaceEndpoint {
                expose: "public",
                service_name: Some("shop"),
                ..surface("web", "https", 8443)
            },
            SurfaceEndpoint {
                service_name: Some("inner"),
                ..surface("admin", "https", 9443)
            },
        ];
        assert_eq!(
            resolved(EndpointFact::Name, &declared, Some("web"), &naming).expect("public"),
            "shop.acme.v0.orc8r.com"
        );
        assert_eq!(
            resolved(EndpointFact::Name, &declared, Some("admin"), &naming).expect("internal"),
            "inner.demo.internal"
        );
    }

    #[test]
    fn a_public_endpoint_without_a_base_domain_falls_back_to_its_internal_name() {
        // Public naming does not exist in a zone with no base domain, so there is no
        // public name to fall back *from* — the endpoint answers to its internal one.
        let declared = [SurfaceEndpoint {
            expose: "public",
            service_name: Some("shop"),
            ..surface("web", "https", 8443)
        }];
        assert_eq!(
            resolved(EndpointFact::Url, &declared, None, &naming()).expect("url"),
            "https://shop.demo.internal:8443"
        );
    }

    #[test]
    fn the_url_scheme_follows_the_declared_protocol() {
        for (protocol, port, expected) in [
            ("https", 3000, "https://db.demo.internal:3000"),
            ("http", 8080, "http://db.demo.internal:8080"),
            ("tcp", 5432, "tcp://db.demo.internal:5432"),
            ("udp", 53, "udp://db.demo.internal:53"),
        ] {
            let declared = [surface("only", protocol, port)];
            assert_eq!(
                resolved(EndpointFact::Url, &declared, None, &naming()).expect("url"),
                expected
            );
        }
    }

    #[test]
    fn a_web_scheme_on_its_default_port_elides_it() {
        for (protocol, port, expected) in [
            ("https", 443, "https://db.demo.internal"),
            ("http", 80, "http://db.demo.internal"),
            // The transports have no default to elide: 443 over raw TCP is still a
            // port a client has to be told about.
            ("tcp", 443, "tcp://db.demo.internal:443"),
        ] {
            let declared = [surface("only", protocol, port)];
            assert_eq!(
                resolved(EndpointFact::Url, &declared, None, &naming()).expect("url"),
                expected
            );
        }
    }

    /// The refusal wording, pinned once so every host runtime reports the same sentence
    /// and an author can apply the same fix.
    #[test]
    fn every_refusal_names_the_fix() {
        let none: [SurfaceEndpoint<'_>; 0] = [];
        let (refusal, message) =
            resolved(EndpointFact::Url, &none, None, &naming()).expect_err("no endpoints");
        assert_eq!(refusal, Refusal::NoEndpoints);
        assert_eq!(
            message,
            "x-source param \"value\" (endpoint.url): app \"db\" declares no endpoints, so \
             there is none to source; declare an endpoint in the app package or drop this param"
        );

        let (refusal, message) = resolved(EndpointFact::Name, &none, Some("pg"), &naming())
            .expect_err("no endpoints, named");
        assert_eq!(refusal, Refusal::NoEndpoints);
        assert_eq!(
            message,
            "x-source param \"value\" (endpoint.name): app \"db\" declares no endpoints, so \
             \"pg\" cannot be sourced; declare the endpoint in the app package or drop this param"
        );

        let several = [surface("metrics", "http", 9187), surface("pg", "tcp", 5432)];
        let (refusal, message) =
            resolved(EndpointFact::Name, &several, None, &naming()).expect_err("ambiguous");
        assert_eq!(refusal, Refusal::Ambiguous);
        assert_eq!(
            message,
            "x-source param \"value\" (endpoint.name): app \"db\" declares 2 endpoints \
             (metrics, pg), so the sole-endpoint default does not apply; set params.endpoint \
             to the one this param means"
        );

        let (refusal, message) =
            resolved(EndpointFact::Port, &several, Some("pgg"), &naming()).expect_err("undeclared");
        assert_eq!(refusal, Refusal::Undeclared);
        assert_eq!(
            message,
            "x-source param \"value\" (endpoint.port): app \"db\" declares no endpoint \
             \"pgg\"; set params.endpoint to one of: metrics, pg"
        );

        // A row without exposure facts. Nothing about it can
        // be answered, and every fact is refused the same way — including the port,
        // which is present, because delivering it would leave a sibling `endpoint.url`
        // param the only thing that failed and the app half-configured.
        let stale = [surface("pg", "", 5432)];
        let (refusal, message) =
            resolved(EndpointFact::Port, &stale, None, &naming()).expect_err("stale push");
        assert_eq!(refusal, Refusal::FactsUnavailable);
        assert_eq!(
            message,
            "x-source param \"value\" (endpoint.port): endpoint \"pg\" arrived without \
             endpoint exposure facts, so this runtime cannot name it; refresh the deployment \
             metadata"
        );

        // The same sentence about a whole surface, which is how a runtime raises it
        // when it can see the absence before narrowing to one app.
        let (refusal, message) = facts_unavailable("value", EndpointFact::Url, "pool \"db\"");
        assert_eq!(refusal, Refusal::FactsUnavailable);
        assert_eq!(
            message,
            "x-source param \"value\" (endpoint.url): pool \"db\" arrived without endpoint \
             exposure facts, so this runtime cannot name it; refresh the deployment metadata"
        );
    }

    #[test]
    fn an_empty_endpoint_param_is_no_param_at_all() {
        // A recipe that templated the param to nothing meant "the default", not "the
        // endpoint whose name is the empty string".
        let declared = [surface("pg", "tcp", 5432)];
        assert_eq!(
            resolved(EndpointFact::Port, &declared, Some(""), &naming()).expect("port"),
            "5432"
        );
    }
}
