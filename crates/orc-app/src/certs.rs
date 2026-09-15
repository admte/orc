//! Renewal scheduling for orchestrator-delivered TLS leaf certificates.
//!
//! A runtime that hands an app a signed leaf reads the certificate's own validity
//! window and arms **one** timer from it. Nothing polls, and no runtime needs to know
//! the issuer's lifetime policy — the leaf carries it. When the timer fires the app is
//! taken back through the ordinary convergence path, which re-resolves its sourced
//! params (minting a fresh leaf) and restarts it: the app receives the replacement
//! exactly the way it received its first certificate, so no app-facing contract or
//! hot-reload machinery is involved.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use x509_parser::extensions::GeneralName;
use x509_parser::pem::Pem;

/// Fraction of the validity window after which a leaf is replaced. Renewing at two
/// thirds leaves the remaining third to retry in before the leaf actually expires.
const RENEW_FRACTION: f64 = 2.0 / 3.0;

/// Jitter around the renewal point, as a fraction of the validity window. Every
/// member of a pool is issued its leaf within seconds of the others, so without this
/// they would all renew — and therefore all restart — at the same instant.
const JITTER_FRACTION: f64 = 0.10;

/// Floor on the armed delay. A leaf already past its renewal point (a long runtime
/// outage, a clock correction, a very short-lived issuer) still gets a settle window
/// rather than restarting the app as fast as the loop can spin.
pub const MIN_RENEWAL_DELAY: Duration = Duration::from_secs(30);

/// What a caller needs to know about a delivered leaf besides its bytes.
///
/// Both facts are the certificate's own: nothing about them is remembered
/// separately, so a stored chain and its metadata cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafFacts {
    /// Expiry, as seconds since the epoch.
    pub not_after: i64,
    /// Serial number, lower-case hex — how a certificate is named in a
    /// Certificate Transparency log and in an operator's own records.
    pub serial_hex: String,
}

/// Reads the leaf's expiry and serial out of `cert_pem`.
///
/// `cert_pem` is leaf-first: only the first block is read, so a full chain and a
/// bare leaf answer identically.
///
/// # Errors
///
/// Returns the reason the certificate could not be read — no PEM block, or a
/// block that does not parse as a certificate.
pub fn leaf_facts(cert_pem: &str) -> Result<LeafFacts, String> {
    let block = Pem::iter_from_buffer(cert_pem.as_bytes())
        .next()
        .ok_or_else(|| "no certificate PEM block".to_owned())?
        .map_err(|err| format!("certificate PEM does not decode: {err}"))?;
    let leaf = block
        .parse_x509()
        .map_err(|err| format!("leaf certificate does not parse: {err}"))?;
    Ok(LeafFacts {
        not_after: leaf.validity().not_after.timestamp(),
        serial_hex: format!("{:x}", leaf.serial),
    })
}

/// The DNS names the leaf in `cert_pem` is valid for, lower-cased.
///
/// Read from the subject alternative name extension and nowhere else: the common name
/// has not been what a client checks for many years, and a CA is free to omit it. A
/// certificate carrying no SAN extension therefore covers nothing, which is the honest
/// answer rather than an error.
///
/// `cert_pem` is leaf-first, like [`leaf_facts`]: only the first block is read, so an
/// issuer's own names can never be mistaken for the leaf's.
///
/// # Errors
///
/// Returns the reason the certificate could not be read — no PEM block, a block that
/// does not parse as a certificate, or a subject alternative name extension that does
/// not parse.
pub fn dns_names(cert_pem: &str) -> Result<Vec<String>, String> {
    let block = Pem::iter_from_buffer(cert_pem.as_bytes())
        .next()
        .ok_or_else(|| "no certificate PEM block".to_owned())?
        .map_err(|err| format!("certificate PEM does not decode: {err}"))?;
    let leaf = block
        .parse_x509()
        .map_err(|err| format!("leaf certificate does not parse: {err}"))?;
    let Some(san) = leaf
        .subject_alternative_name()
        .map_err(|err| format!("subject alternative names do not parse: {err}"))?
    else {
        return Ok(Vec::new());
    };
    Ok(san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_lowercase()),
            _ => None,
        })
        .collect())
}

/// The DNS namespaces the issuer in `cert_pem` is permitted to sign under, lower-cased
/// and without a trailing dot.
///
/// Read from the RFC 5280 name constraints extension, permitted subtrees only. An
/// intermediate is pinned to a namespace when it is minted, so the constraint is a
/// snapshot of what that namespace was at that moment: comparing it against the
/// namespace in force now is how a stale issuer — one that can no longer sign the names
/// its own project asks for — is spotted before it refuses a leaf.
///
/// A certificate carrying no name constraints extension is **unconstrained**: it permits
/// every name, not none. The empty vec is the honest report of "nothing constrains this",
/// which is why it is not an error and why a caller must decide what the absence means to
/// it rather than reading it as "matches nothing". A staleness check should read it as the
/// opposite of reassuring: an issuer that constrains nothing is free to sign any name under
/// its root, which is the state the constraint exists to prevent.
///
/// `cert_pem` is issuer-first, like [`leaf_facts`]: only the first block is read, so a
/// chain and a bare certificate answer identically.
///
/// # Errors
///
/// Returns the reason the certificate could not be read — no PEM block, a block that does
/// not decode, a block that does not parse as a certificate, or a name constraints
/// extension that does not parse.
pub fn permitted_dns_subtrees(cert_pem: &str) -> Result<Vec<String>, String> {
    let block = Pem::iter_from_buffer(cert_pem.as_bytes())
        .next()
        .ok_or_else(|| "no certificate PEM block".to_owned())?
        .map_err(|err| format!("certificate PEM does not decode: {err}"))?;
    let issuer = block
        .parse_x509()
        .map_err(|err| format!("issuer certificate does not parse: {err}"))?;
    let Some(constraints) = issuer
        .name_constraints()
        .map_err(|err| format!("name constraints do not parse: {err}"))?
    else {
        return Ok(Vec::new());
    };
    let Some(permitted) = constraints.value.permitted_subtrees.as_ref() else {
        return Ok(Vec::new());
    };
    Ok(permitted
        .iter()
        .filter_map(|subtree| match &subtree.base {
            GeneralName::DNSName(dns) => Some(dns.trim_end_matches('.').to_lowercase()),
            _ => None,
        })
        .collect())
}

/// Whether the leaf in `cert_pem` covers every one of `names`.
///
/// Exact and case-insensitive, never wildcard-expanding. The question being answered is
/// "was this certificate issued for the set we are configured to serve" — a holder that
/// reorders when the answer is no is the whole mechanism by which a changed name list
/// takes effect. Letting `*.example.com` answer for `www.example.com` would pass that
/// check with a certificate nobody configured.
///
/// # Errors
///
/// Returns the reason the certificate could not be read.
pub fn covers(cert_pem: &str, names: &[String]) -> Result<bool, String> {
    let present = dns_names(cert_pem)?;
    Ok(names
        .iter()
        .all(|name| present.iter().any(|have| have.eq_ignore_ascii_case(name))))
}

/// The delay from `now` after which the leaf in `cert_pem` must be replaced.
///
/// `cert_pem` is the delivered certificate value: the leaf first, its issuer chain
/// after. Only the leaf's own validity window decides the schedule.
///
/// # Errors
///
/// Returns the reason the certificate could not be scheduled — no PEM block, a
/// certificate that does not parse, or an empty/inverted validity window. Callers arm
/// no timer and log it loudly: an app is then running with a leaf that will expire
/// unattended.
pub fn renewal_delay(cert_pem: &str, now: SystemTime) -> Result<Duration, String> {
    // Uniform over the full jitter band, centred on the renewal point.
    renewal_delay_jittered(cert_pem, now, rand::random::<f64>().mul_add(2.0, -1.0))
}

/// [`renewal_delay`] with the jitter draw supplied: `jitter` is the position within
/// the band, `-1.0` earliest and `1.0` latest. Split out so the schedule can be
/// asserted exactly instead of over a random draw.
///
/// # Errors
///
/// As [`renewal_delay`].
#[allow(
    clippy::cast_precision_loss,
    reason = "certificate timestamps are seconds since the epoch; f64 is exact far \
              beyond any certificate lifetime"
)]
fn renewal_delay_jittered(
    cert_pem: &str,
    now: SystemTime,
    jitter: f64,
) -> Result<Duration, String> {
    let block = Pem::iter_from_buffer(cert_pem.as_bytes())
        .next()
        .ok_or_else(|| "no certificate PEM block".to_owned())?
        .map_err(|err| format!("certificate PEM does not decode: {err}"))?;
    let leaf = block
        .parse_x509()
        .map_err(|err| format!("leaf certificate does not parse: {err}"))?;
    let not_before = leaf.validity().not_before.timestamp();
    let not_after = leaf.validity().not_after.timestamp();
    let window = not_after - not_before;
    if window <= 0 {
        return Err(format!(
            "leaf validity window is empty (notBefore {not_before}, notAfter {not_after})"
        ));
    }
    let window = window as f64;
    let fraction = JITTER_FRACTION.mul_add(jitter.clamp(-1.0, 1.0), RENEW_FRACTION);
    let renew_at = window.mul_add(fraction, not_before as f64);
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |since| since.as_secs_f64());
    let delay = renew_at - now;
    if delay <= MIN_RENEWAL_DELAY.as_secs_f64() {
        return Ok(MIN_RENEWAL_DELAY);
    }
    Ok(Duration::from_secs_f64(delay))
}

#[cfg(test)]
mod tests {
    use super::*;

    use rcgen::{
        BasicConstraints, CertificateParams, CidrSubnet, GeneralSubtree, IsCa, KeyPair,
        NameConstraints,
    };
    use time::OffsetDateTime;

    /// A self-signed leaf carrying `names` as its subject alternative names.
    fn leaf_for(names: &[&str]) -> String {
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("params");
        params.self_signed(&key).expect("cert").pem()
    }

    /// A self-signed leaf whose validity window opens `before` seconds ago and closes
    /// `after` seconds from now.
    fn leaf(before: i64, after: i64) -> String {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec!["leaf.test".to_owned()]).expect("params");
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::seconds(before);
        params.not_after = now + time::Duration::seconds(after);
        params.self_signed(&key).expect("cert").pem()
    }

    #[test]
    fn renewal_lands_two_thirds_into_the_validity_window() {
        // Window: 900s, opened 300s ago. Two thirds of 900 is 600, so the unjittered
        // renewal point is 300s from now.
        let delay = renewal_delay_jittered(&leaf(300, 600), SystemTime::now(), 0.0).expect("delay");
        let secs = delay.as_secs_f64();
        assert!(
            (295.0..=305.0).contains(&secs),
            "unjittered renewal must sit at two thirds of the window; got {secs}s"
        );
    }

    #[test]
    fn jitter_stays_within_a_tenth_of_the_window_either_side() {
        // Same 900s window. The band is 2/3 ± 1/10 of it: 510s..=690s from notBefore,
        // i.e. 210s..=390s from now.
        let cert = leaf(300, 600);
        let now = SystemTime::now();
        let earliest = renewal_delay_jittered(&cert, now, -1.0).expect("earliest");
        let latest = renewal_delay_jittered(&cert, now, 1.0).expect("latest");
        assert!(
            (205.0..=215.0).contains(&earliest.as_secs_f64()),
            "earliest draw must be a tenth of the window early; got {earliest:?}"
        );
        assert!(
            (385.0..=395.0).contains(&latest.as_secs_f64()),
            "latest draw must be a tenth of the window late; got {latest:?}"
        );
        // Whatever the draw, renewal must leave real time before expiry: the latest
        // point is 690s into a 900s window, so 210s of retry room remains.
        assert!(
            latest.as_secs_f64() < 600.0,
            "renewal must precede notAfter"
        );
    }

    #[test]
    fn a_random_draw_stays_inside_the_band() {
        let cert = leaf(300, 600);
        for _ in 0..64 {
            let delay = renewal_delay(&cert, SystemTime::now()).expect("delay");
            let secs = delay.as_secs_f64();
            assert!(
                (205.0..=395.0).contains(&secs),
                "random draw escaped the jitter band; got {secs}s"
            );
        }
    }

    #[test]
    fn a_leaf_past_its_renewal_point_renews_after_the_floor() {
        // Window: 900s, opened 800s ago — well past the two-thirds point. The floor
        // keeps this from restarting the app as fast as the converge loop can spin.
        let delay = renewal_delay(&leaf(800, 100), SystemTime::now()).expect("delay");
        assert_eq!(delay, MIN_RENEWAL_DELAY);
    }

    #[test]
    fn an_expired_leaf_still_schedules_a_renewal() {
        // Fully expired: renewal is the only thing that can recover the app, so it is
        // scheduled at the floor rather than refused.
        let delay = renewal_delay(&leaf(9_000, -3_600), SystemTime::now()).expect("delay");
        assert_eq!(delay, MIN_RENEWAL_DELAY);
    }

    #[test]
    fn a_chain_is_scheduled_from_the_leaf_not_the_issuer() {
        // The delivered value is leaf-then-chain. Appending a much longer-lived block
        // must not move the schedule.
        let cert = format!("{}{}", leaf(300, 600), leaf(0, 86_400));
        let delay = renewal_delay_jittered(&cert, SystemTime::now(), 0.0).expect("delay");
        assert!(
            (295.0..=305.0).contains(&delay.as_secs_f64()),
            "the first block is the leaf; the chain after it must be ignored"
        );
    }

    /// The metadata a store keeps beside a chain comes out of the chain itself,
    /// leaf first — so it can never describe the issuer, and never drift.
    #[test]
    fn leaf_facts_read_the_first_block_only() {
        let leaf_pem = leaf(0, 86_400);
        let facts = leaf_facts(&leaf_pem).expect("facts");
        assert!(!facts.serial_hex.is_empty());
        assert!(
            facts.not_after > chrono_free_now(),
            "a freshly minted leaf expires in the future"
        );

        let chained = format!("{leaf_pem}{}", leaf(0, 10 * 86_400));
        assert_eq!(
            leaf_facts(&chained).expect("chain facts"),
            facts,
            "an appended issuer must not move the answer"
        );

        assert!(leaf_facts("not a certificate").is_err());
    }

    fn chrono_free_now() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("epoch")
                .as_secs(),
        )
        .expect("timestamp")
    }

    /// The names come out of the SAN extension, lower-cased, and only the leaf's.
    #[test]
    fn dns_names_read_the_leaf_s_subject_alternative_names() {
        let leaf_pem = leaf_for(&["Orc.Example.Com", "www.orc.example.com"]);
        assert_eq!(
            dns_names(&leaf_pem).expect("names"),
            vec![
                "orc.example.com".to_owned(),
                "www.orc.example.com".to_owned()
            ],
            "DNS is case-insensitive, so the answer is folded once here rather than at \
             every comparison"
        );

        let chained = format!("{leaf_pem}{}", leaf_for(&["issuer.example.com"]));
        assert_eq!(
            dns_names(&chained).expect("chain names"),
            dns_names(&leaf_pem).expect("leaf names"),
            "an appended issuer must not contribute names"
        );

        assert!(dns_names("not a certificate").is_err());
    }

    /// Coverage is exact set membership, case-insensitive — the question a holder asks
    /// before deciding whether the certificate it stored is still the one configured.
    #[test]
    fn coverage_is_every_configured_name_and_nothing_less() {
        let both = leaf_for(&["orc.example.com", "www.orc.example.com"]);
        let apex_only = leaf_for(&["orc.example.com"]);

        let configured = vec![
            "orc.example.com".to_owned(),
            "www.orc.example.com".to_owned(),
        ];
        assert!(covers(&both, &configured).expect("covers"));
        assert!(
            !covers(&apex_only, &configured).expect("covers"),
            "the certificate that predates an added alternative name must not satisfy it"
        );

        // The converse: dropping a name from the configuration leaves a certificate that
        // covers more than asked, which is still a certificate that covers what is asked.
        assert!(covers(&both, &["orc.example.com".to_owned()]).expect("covers"));

        assert!(
            covers(&both, &["WWW.ORC.EXAMPLE.COM".to_owned()]).expect("covers"),
            "a configured name differing only in case is the same name"
        );
        assert!(
            !covers(&both, &["other.example.com".to_owned()]).expect("covers"),
            "an unrelated name is not covered"
        );
    }

    /// A wildcard is never expanded: this check exists to decide whether the stored
    /// certificate is the one we ordered, and a wildcard that happens to match is not.
    #[test]
    fn a_wildcard_does_not_stand_in_for_the_name_it_would_match() {
        let wildcard = leaf_for(&["*.example.com"]);
        assert!(!covers(&wildcard, &["www.example.com".to_owned()]).expect("covers"));
    }

    /// A self-signed intermediate-shaped CA whose permitted subtrees are `permitted` —
    /// the shape a project intermediate is minted in.
    fn ca_permitting(permitted: Vec<GeneralSubtree>) -> String {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted,
            excluded_subtrees: vec![],
        });
        params.self_signed(&key).expect("cert").pem()
    }

    /// The namespace an intermediate was pinned to is read back off the certificate
    /// itself, so a stale pin can be compared against the namespace in force now.
    #[test]
    fn permitted_subtrees_are_the_issuer_s_dns_namespaces() {
        let ca = ca_permitting(vec![
            GeneralSubtree::DnsName("shop.internal".to_owned()),
            GeneralSubtree::DnsName("shop.corp.example".to_owned()),
        ]);
        assert_eq!(
            permitted_dns_subtrees(&ca).expect("subtrees"),
            vec!["shop.internal".to_owned(), "shop.corp.example".to_owned()]
        );

        let chained = format!(
            "{ca}{}",
            ca_permitting(vec![GeneralSubtree::DnsName("other.internal".to_owned())])
        );
        assert_eq!(
            permitted_dns_subtrees(&chained).expect("chain subtrees"),
            permitted_dns_subtrees(&ca).expect("issuer subtrees"),
            "an appended block must not contribute subtrees"
        );
    }

    /// Absent extension means the issuer may sign anything. The empty answer reports
    /// "nothing constrains this" — it is deliberately not an error, and deliberately not
    /// the same thing as a constraint that happens to permit nothing.
    #[test]
    fn an_issuer_without_name_constraints_reports_no_subtrees() {
        assert_eq!(
            permitted_dns_subtrees(&leaf_for(&["orc.example.com"])).expect("subtrees"),
            Vec::<String>::new()
        );
    }

    /// Folded once here, the way [`dns_names`] folds the leaf's own names, so a caller
    /// comparing a constraint against a configured zone never has to care about the
    /// presentation a CA happened to choose.
    #[test]
    fn subtree_names_are_normalized_before_they_are_compared() {
        let ca = ca_permitting(vec![GeneralSubtree::DnsName(
            "Shop.Corp.EXAMPLE.".to_owned(),
        )]);
        assert_eq!(
            permitted_dns_subtrees(&ca).expect("subtrees"),
            vec!["shop.corp.example".to_owned()],
            "DNS is case-insensitive and the root dot is implicit; both are absorbed here"
        );
    }

    /// A name constraint may pin non-DNS name forms in the same extension. Only the
    /// dNSName subtrees answer a question about a DNS namespace.
    #[test]
    fn only_dns_subtrees_are_reported() {
        let ca = ca_permitting(vec![
            GeneralSubtree::Rfc822Name("ops@shop.corp.example".to_owned()),
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([10, 0, 0, 0], 8)),
            GeneralSubtree::DnsName("shop.internal".to_owned()),
        ]);
        assert_eq!(
            permitted_dns_subtrees(&ca).expect("subtrees"),
            vec!["shop.internal".to_owned()]
        );
    }

    #[test]
    fn a_malformed_certificate_constrains_nothing() {
        let err = permitted_dns_subtrees("not a certificate").expect_err("garbage must not read");
        assert!(err.contains("no certificate PEM block"), "{err}");

        let err = permitted_dns_subtrees(
            "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n",
        )
        .expect_err("a non-certificate PEM body must not read");
        assert!(err.contains("does not parse"), "{err}");
    }

    #[test]
    fn a_malformed_certificate_schedules_nothing() {
        let err = renewal_delay("not a certificate", SystemTime::now())
            .expect_err("garbage must not schedule");
        assert!(err.contains("no certificate PEM block"), "{err}");

        let err = renewal_delay(
            "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n",
            SystemTime::now(),
        )
        .expect_err("a non-certificate PEM body must not schedule");
        assert!(err.contains("does not parse"), "{err}");
    }
}
