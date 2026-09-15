//! Source-agnostic evaluation of an app's declared version-discovery recipe.
//!
//! Given a [`VersionDiscovery`] block this fetches the declared source (GitHub or
//! GitLab releases and tags, a JSON document, a plain-text list, a `NuGet` feed, or
//! a `WinGet` feed), merges in any static `list`, applies the recipe's own `filter`,
//! and caps the result to a caller-supplied [`DiscoveryLimits`]. Evaluation is
//! deterministic by contract: identical source data yields an identical list on any
//! host, so every discovery consumer can share one implementation.
//!
//! The pipeline is a fixed sequence — fetch, extract, filter, sort, prune, limit —
//! and every stage whose recipe field is omitted is a no-op, so a recipe that
//! declares none of the newer fields evaluates exactly as it always did.
//!
//! A fetch or parse failure is reported as data (`DiscoveryOutcome::source_error`)
//! rather than as an error, so a background refresh can keep the previously committed
//! list instead of dropping it.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::time::Duration;

use crate::app::{VersionDiscovery, VersionFilter};
use crate::error::{CliError, Result};

/// Caller-owned policy applied on top of the recipe's own `filter`.
///
/// Defaults provide a bounded discovery budget: 100 versions, a 5-second per-fetch
/// timeout, and a 16 MiB response cap. The GitHub bearer token is optional
/// context — the CLI forwards a stored `ghcr.io` credential so private release
/// listings work; callers without credentials pass `None`.
#[derive(Debug, Clone)]
pub struct DiscoveryLimits {
    /// Hard cap on the returned version count, applied after `filter.limit`.
    pub max_versions: usize,
    /// Per-fetch request timeout.
    pub timeout: Duration,
    /// Maximum accepted response body size, in bytes.
    pub max_response_bytes: usize,
    /// Optional bearer token for the `github_releases` source.
    pub github_token: Option<String>,
    /// HTTP client to fetch with. `None` uses a shared process-wide client, which
    /// is what every caller wants; a caller with its own connection policy can
    /// hand one in.
    pub client: Option<reqwest::Client>,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_versions: 100,
            timeout: Duration::from_secs(5),
            max_response_bytes: 16 * 1024 * 1024,
            github_token: None,
            client: None,
        }
    }
}

/// The process-wide discovery client.
///
/// A background refresh evaluates many repositories back to back, so building a client
/// per evaluation would throw away the connection pool (and its TLS sessions)
/// every time. The timeout is applied per request instead of baked in here, so
/// one shared client still honors each caller's budget.
fn shared_client() -> Result<&'static reqwest::Client> {
    static CLIENT: std::sync::OnceLock<std::result::Result<reqwest::Client, String>> =
        std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .user_agent(concat!("orc-app/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|err| err.to_string())
        })
        .as_ref()
        .map_err(|err| CliError::Operational(format!("build discovery client: {err}")))
}

/// Optional per-evaluation context that turns a full evaluation into an
/// incremental one.
///
/// [`Default`] — no known set, no validator — is a full evaluation, byte-for-byte
/// what the CLI has always run. A caller that owns a previously committed list
/// passes it plus the validator it stored last time; the release sources then
/// issue a conditional request and stop reading their page as soon as it overlaps
/// what the caller already has.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryRequest<'a> {
    /// Versions the caller already holds, as stored — that is, post-extraction.
    /// `None` asks for a full evaluation.
    pub known_versions: Option<&'a BTreeSet<String>>,
    /// Validator from the previous fetch, sent as `If-None-Match`.
    pub validator: Option<&'a str>,
    /// Read a paginated source to its end rather than stopping at one page.
    ///
    /// The cheap path reads a single page and lives with knowing less. A caller
    /// that is going to *reconcile* against the result — retire whatever the
    /// answer omits — cannot: on a source with more entries than fit a page, one
    /// page is never the whole offering, so nothing could ever be retired. Setting
    /// this walks successive pages until one underfills or the caller's
    /// `max_versions` worth of versions has been retained, which makes the fetch
    /// complete by construction. Only the deliberate, infrequent triggers should
    /// pay for that walk.
    pub paginate: bool,
}

/// The result of evaluating a discovery recipe.
///
/// On any fetch or parse failure `versions` is empty and `source_error` carries
/// the message; evaluation never panics and never returns `Err`.
///
/// In incremental mode `versions` holds the *candidates* read off the newest-first
/// page rather than a complete list: the caller owns the stored list and folds
/// these into it with [`merge_versions`]. `not_modified` short-circuits even that —
/// the source said nothing changed, so `versions` is empty and the caller keeps
/// what it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryOutcome {
    /// Filtered, sorted, and capped versions.
    pub versions: Vec<String>,
    /// The failure message when the source could not be fetched or parsed.
    pub source_error: Option<String>,
    /// Validator the source returned, to be stored for the next conditional fetch.
    pub validator: Option<String>,
    /// The source answered `304 Not Modified`; nothing was fetched.
    pub not_modified: bool,
    /// Whether this evaluation learned *everything* the declaration offers, so
    /// `versions` is the complete list rather than candidates to merge.
    ///
    /// True for a source read in one shot — `http`, `json`, `nuget`, `winget`, a
    /// recipe's own `list` — on every successful evaluation, incremental request
    /// or not. For a paginated forge endpoint it needs both halves: the page came
    /// back short of the size it asked for (so there is no next page) *and* the
    /// overlap cut did not fire. A full page is never complete, however it was
    /// filtered afterwards — a release train of prereleases that the recipe drops
    /// leaves an empty result that is emphatically not the whole offering — and
    /// neither is a `304`, which read nothing at all.
    ///
    /// A caller reconciling stored state uses this rather than the mode it asked
    /// for: only an evaluation that saw everything may conclude that something it
    /// did not list is gone.
    pub complete: bool,
}

impl DiscoveryOutcome {
    fn failed(err: &CliError) -> Self {
        Self {
            versions: Vec::new(),
            source_error: Some(err.to_string()),
            validator: None,
            not_modified: false,
            // A failed fetch learned nothing; it must never license a demotion.
            complete: false,
        }
    }
}

/// Evaluates `discovery` for `app_name` in full, honoring `limits`.
///
/// `app_name` is the app's repository, used to derive the package id for the
/// `NuGet` and `WinGet` feeds. Failure to reach or parse the source is folded into
/// [`DiscoveryOutcome::source_error`] rather than surfaced as an error.
pub async fn evaluate(
    discovery: &VersionDiscovery,
    app_name: &str,
    limits: &DiscoveryLimits,
) -> DiscoveryOutcome {
    evaluate_with(discovery, app_name, limits, &DiscoveryRequest::default()).await
}

/// Evaluates `discovery` with optional incremental context.
///
/// With a [`DiscoveryRequest::default`] request this is exactly [`evaluate`]: the
/// whole declaration is evaluated and the returned list is complete.
///
/// Two obligations come with the incremental form:
///
/// - A stored validator belongs to the declaration that produced it. Whenever the
///   `versions:` block changes — a new source, a new URL, an edited `filter`, an
///   added static `list` entry — the caller MUST discard the validator, or a `304`
///   will report "nothing changed" about a recipe that did.
/// - [`merge_versions`] re-runs only sort, prune, and limit. Edits to `pattern`,
///   `exclude`, or `prerelease` reshape versions the caller already stored, and
///   those take effect only through a full evaluation.
pub async fn evaluate_with(
    discovery: &VersionDiscovery,
    app_name: &str,
    limits: &DiscoveryLimits,
    request: &DiscoveryRequest<'_>,
) -> DiscoveryOutcome {
    evaluate_inner(discovery, app_name, limits, request)
        .await
        .unwrap_or_else(|err| DiscoveryOutcome::failed(&err))
}

/// Folds incremental candidates into a caller's stored list.
///
/// Only the order-and-prune tail of the pipeline re-runs (sort, `latest_per`,
/// `limit`, then the caller's own cap). Extraction deliberately does not: stored
/// versions were extracted when first seen, and an extracting pattern would no
/// longer match its own output.
///
/// # Errors
///
/// Returns a usage error when `filter.sort` or `filter.latest_per` names a mode
/// that does not exist.
pub fn merge_versions(
    stored: &[String],
    candidates: &[String],
    filter: &VersionFilter,
    limits: &DiscoveryLimits,
) -> Result<Vec<String>> {
    let mut merged: Vec<String> = stored.to_vec();
    let seen: BTreeSet<&String> = stored.iter().collect();
    merged.extend(
        candidates
            .iter()
            .filter(|version| !seen.contains(version))
            .cloned(),
    );
    let mut merged = order_and_prune(merged, filter)?;
    merged.truncate(limits.max_versions);
    Ok(merged)
}

/// How much of a recipe's curation an evaluation keeps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VersionScope {
    /// The recipe's full pipeline: what the curated catalog offers.
    #[default]
    Curated,
    /// Every version the sources publish: `latest_per` and `limit` are dropped and
    /// the caller's `max_versions` cap is lifted, while `pattern`, `prerelease`,
    /// `exclude`, and `sort` still apply.
    All,
}

/// Evaluates `discovery` for `app_name` under `scope`.
///
/// Every caller that wants the uncurated list — the author-facing `--all` listing
/// and install-time resolution of a version the catalog does not offer — comes
/// through here, so "uncurated" means one thing across the product.
pub async fn evaluate_scoped(
    discovery: &VersionDiscovery,
    app_name: &str,
    limits: &DiscoveryLimits,
    scope: VersionScope,
    reach: Reach,
) -> DiscoveryOutcome {
    let request = DiscoveryRequest {
        paginate: reach == Reach::WholeListing,
        ..DiscoveryRequest::default()
    };
    match scope {
        VersionScope::Curated => evaluate_with(discovery, app_name, limits, &request).await,
        VersionScope::All => {
            let uncurated = VersionDiscovery {
                filter: uncurated_filter(&discovery.filter),
                ..discovery.clone()
            };
            // The caller's own cap curates too: at the default 100 an exact version
            // sitting below the newest hundred raw entries would be unreachable,
            // even though it is a version the source genuinely publishes. Lifting
            // it means an uncurated walk ends at the listing rather than the cap.
            let limits = DiscoveryLimits {
                max_versions: usize::MAX,
                ..limits.clone()
            };
            evaluate_with(&uncurated, app_name, &limits, &request).await
        }
    }
}

/// How much of a paginated source an evaluation is willing to read.
///
/// The distinction only matters to a source with more entries than fit a page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Reach {
    /// One page — the cheap read, for a caller that can act on a partial answer.
    #[default]
    FirstPage,
    /// To the end of the listing, so the answer is the whole offering. What a
    /// caller needs when it is going to reconcile against the result, or when it
    /// needs the complete discoverable set.
    WholeListing,
}

/// The recipe's filter with its curation stages taken out: `latest_per` and
/// `limit` choose *which* published versions to offer, while `pattern`,
/// `prerelease`, `exclude`, and `sort` decide what counts as a version at all and
/// in what order, so those stay.
///
/// Destructured exhaustively on purpose. A filter field added later stops
/// compiling right here, which forces whoever adds it to classify it rather than
/// let it drift into whichever half `..` happened to put it in.
fn uncurated_filter(filter: &VersionFilter) -> VersionFilter {
    let VersionFilter {
        prerelease,
        pattern,
        exclude,
        latest_per: _,
        limit: _,
        sort,
    } = filter;
    VersionFilter {
        prerelease: *prerelease,
        pattern: pattern.clone(),
        exclude: exclude.clone(),
        latest_per: None,
        limit: None,
        sort: sort.clone(),
    }
}

async fn evaluate_inner(
    discovery: &VersionDiscovery,
    app_name: &str,
    limits: &DiscoveryLimits,
    request: &DiscoveryRequest<'_>,
) -> Result<DiscoveryOutcome> {
    let client = match limits.client.as_ref() {
        Some(client) => client,
        None => shared_client()?,
    };

    let mut fetched = fetch_source(client, discovery, app_name, limits, request, 1).await?;
    if request.paginate && !fetched.not_modified {
        walk_remaining_pages(client, discovery, app_name, limits, request, &mut fetched).await?;
    }
    if fetched.not_modified {
        // Nothing was read, so there is nothing to merge; the caller keeps its list.
        return Ok(DiscoveryOutcome {
            versions: Vec::new(),
            source_error: None,
            validator: fetched.validator,
            not_modified: true,
            complete: false,
        });
    }

    let pattern = discovery.filter.pattern.as_deref();
    let mut fetched_entries = extract_versions(fetched.entries, pattern)?;
    // The overlap cut is only sound where the source enumerates newest-first, and
    // only over what the source returned: the static `list` is recipe-owned and
    // would otherwise cut the page at its first entry.
    let mut cut = false;
    if let Some(known) = request.known_versions.filter(|_| fetched.newest_first)
        && let Some(overlap) = fetched_entries
            .iter()
            .position(|entry| known.contains(&entry.value))
    {
        fetched_entries.truncate(overlap);
        cut = true;
    }

    // The static `list` is part of the recipe, not of the source, so it joins the
    // fetched entries before filtering and carries no prerelease marking.
    let mut entries = extract_versions(
        discovery
            .list
            .iter()
            .map(|version| RawVersion::release(version.clone()))
            .collect(),
        pattern,
    )?;
    entries.extend(fetched_entries);

    let mut versions = finish_pipeline(entries, &discovery.filter)?;
    versions.truncate(limits.max_versions);
    Ok(DiscoveryOutcome {
        versions,
        source_error: None,
        validator: fetched.validator,
        not_modified: false,
        // Both halves: the fetch reached the end of what the source offers, and the
        // cut did not stop this pass part way down the page. Filtering happens after
        // this point and cannot make an incomplete read complete.
        complete: fetched.whole_offering && !cut,
    })
}

/// A hard ceiling on a walk, for a source that answers every page in full — one
/// that ignores the `page` parameter, say. Reaching it means the walk learned a
/// great deal and still cannot claim to have seen everything, so the fetch stays
/// incomplete and the caller merges instead of reconciling.
const MAX_WALKED_PAGES: usize = 20;

/// Reads pages after the first until the listing ends or enough versions are in
/// hand, extending `fetched` in place.
///
/// Two stops, and which one fired decides what the fetch may claim. An underfilled
/// page is the end of the listing. Otherwise the walk stops once the recipe would
/// retain `max_versions` from what has been read — everything past that point is
/// beyond what the caller could keep anyway, so it is as complete as completeness
/// can matter. The count is taken after the recipe's own pipeline, not off the raw
/// entries: a recipe pruning to one version per minor retains a handful per page,
/// and stopping on raw volume would cut the walk off long before it had them.
async fn walk_remaining_pages(
    client: &reqwest::Client,
    discovery: &VersionDiscovery,
    app_name: &str,
    limits: &DiscoveryLimits,
    request: &DiscoveryRequest<'_>,
    fetched: &mut SourceFetch,
) -> Result<()> {
    let mut page = 1;
    while !fetched.whole_offering {
        if retained_from(&fetched.entries, discovery, limits)? >= limits.max_versions {
            // As much as can be kept: complete for every purpose the caller has.
            fetched.whole_offering = true;
            break;
        }
        if page >= MAX_WALKED_PAGES {
            break;
        }
        page += 1;
        let next = fetch_source(client, discovery, app_name, limits, request, page).await?;
        // A source that answers an out-of-range page with nothing has ended too.
        let ended = next.whole_offering || next.entries.is_empty();
        fetched.entries.extend(next.entries);
        fetched.whole_offering = ended;
    }
    Ok(())
}

/// How many versions the recipe would retain from `entries` as they stand — the
/// whole pipeline bar the caller's own cap, which is what it is compared against.
fn retained_from(
    entries: &[RawVersion],
    discovery: &VersionDiscovery,
    limits: &DiscoveryLimits,
) -> Result<usize> {
    let extracted = extract_versions(entries.to_vec(), discovery.filter.pattern.as_deref())?;
    Ok(finish_pipeline(extracted, &discovery.filter)?
        .len()
        .min(limits.max_versions))
}

/// One raw entry as the source produced it: the version string plus whatever the
/// source itself knows about it. Sources without a prerelease concept mark every
/// entry a release and leave `filter.pattern` as the recipe author's guard.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawVersion {
    value: String,
    prerelease: bool,
}

impl RawVersion {
    fn release(value: String) -> Self {
        Self {
            value,
            prerelease: false,
        }
    }
}

/// What one source produced, plus the conditional-request bookkeeping.
struct SourceFetch {
    entries: Vec<RawVersion>,
    validator: Option<String>,
    not_modified: bool,
    /// Whether the source enumerates newest-first, which is what makes the
    /// overlap cut sound. Only the release endpoints promise it: tag listings are
    /// ordered by name or by commit date, so a familiar tag partway down says
    /// nothing about what follows.
    newest_first: bool,
    /// Whether this fetch saw the source's **whole** offering.
    ///
    /// A source that is read in one shot — a file, a JSON document, a recipe's
    /// own `list` — always does. A paginated forge endpoint only does when the
    /// page came back *short* of the size it asked for: a full page is evidence
    /// of nothing except that there was at least a page, and the next one may
    /// hold versions this fetch never saw.
    whole_offering: bool,
}

impl SourceFetch {
    /// A source read in one request, whole: no pagination, no validator.
    fn plain(entries: Vec<RawVersion>) -> Self {
        Self {
            entries,
            validator: None,
            not_modified: false,
            newest_first: false,
            whole_offering: true,
        }
    }
}

/// The bounds one fetch runs under, carried together so every request applies
/// both.
#[derive(Debug, Clone, Copy)]
struct FetchBudget {
    timeout: Duration,
    max_bytes: usize,
}

impl FetchBudget {
    fn of(limits: &DiscoveryLimits) -> Self {
        Self {
            timeout: limits.timeout,
            max_bytes: limits.max_response_bytes,
        }
    }
}

/// Fetches page `page` (1-based) of a source under the request's terms.
///
/// Every budget the caller set — the per-fetch timeout and the response cap —
/// applies to each page on its own, so a walk over a long listing is bounded the
/// same way a single read is.
async fn fetch_source(
    client: &reqwest::Client,
    discovery: &VersionDiscovery,
    app_name: &str,
    limits: &DiscoveryLimits,
    request: &DiscoveryRequest<'_>,
    page: usize,
) -> Result<SourceFetch> {
    let budget = FetchBudget::of(limits);
    // A walk asks for the largest page the forges serve: the recipe's `limit`
    // shapes what is offered, and reading the listing in `limit`-sized bites would
    // only multiply the requests it takes to reach the same end.
    let per_page = if request.paginate {
        FORGE_MAX_PAGE_SIZE
    } else {
        forge_page_size(&discovery.filter)
    };
    let token = limits.github_token.as_deref();
    // A validator describes the first page, and answers `304` for it alone.
    let validator = request.validator.filter(|_| page == 1);
    match discovery.source.as_str() {
        "github_releases" => {
            list_github_releases(
                client,
                &discovery.url,
                token,
                budget,
                per_page,
                validator,
                page,
            )
            .await
        }
        "github_tags" => {
            list_github_tags(
                client,
                &discovery.url,
                token,
                budget,
                per_page,
                validator,
                page,
            )
            .await
        }
        "gitlab_releases" => {
            list_gitlab_releases(client, &discovery.url, budget, per_page, validator, page).await
        }
        "gitlab_tags" => {
            list_gitlab_tags(client, &discovery.url, budget, per_page, validator, page).await
        }
        "json" => Ok(SourceFetch::plain(
            fetch_json_versions(client, discovery, budget).await?,
        )),
        "http" => Ok(SourceFetch::plain(
            fetch_http_versions(client, &discovery.url, budget)
                .await?
                .into_iter()
                .map(RawVersion::release)
                .collect(),
        )),
        "nuget" => Ok(SourceFetch::plain(
            fetch_nuget_versions(client, &discovery.url, app_name, budget)
                .await?
                .into_iter()
                .map(RawVersion::release)
                .collect(),
        )),
        "winget" => Ok(SourceFetch::plain(
            fetch_winget_versions(client, &discovery.url, app_name, budget)
                .await?
                .into_iter()
                .map(RawVersion::release)
                .collect(),
        )),
        // Neither fetches: `registry` enumerates the app's own repository tags,
        // which the caller lists itself, and an omitted source is a recipe that
        // carries only a static `list`. Both still merge that `list` below.
        "registry" | "" => Ok(SourceFetch::plain(Vec::new())),
        // A misspelled source must not read as an empty upstream: name it.
        other => Err(CliError::Usage(format!(
            "invalid version source {other:?}; expected registry, github_releases, github_tags, \
             gitlab_releases, gitlab_tags, json, http, nuget, or winget"
        ))),
    }
}

/// Descending semver comparison used to order rows outside this module.
///
/// Newest first, with prereleases sorted below their release, then a lexical
/// tiebreak so the ordering is total.
///
/// Tolerant of the tag styles a publisher mixes across a repository's history:
/// one leading `v` is ignored ([`strip_version_prefix`]) and a numbered
/// prerelease counts up numerically ([`alnum_runs`]), so `v0.5.0-rc1` is newer
/// than `0.4.0-rc88` and `0.4.0-rc88` is newer than `0.4.0-rc9`.
#[must_use]
pub fn compare_semver_desc(left: &str, right: &str) -> Ordering {
    compare_semver_asc(right, left).then_with(|| right.cmp(left))
}

/// Whether `version` lies on the version line named by `request`.
///
/// A request is a prefix that has to end on a component boundary: `1.5` covers
/// `1.5` and `1.5.7` but never `1.55.0`. It is tried raw first and then in
/// normalized form — trailing dots dropped, one leading `v` stripped — so an
/// operator typing `1.5.` or `v1.5` is understood, while a source that genuinely
/// publishes `v`-prefixed versions still matches its own line. A request that
/// normalizes away to nothing (`v`, `.`, empty) names no line and matches nothing.
#[must_use]
pub fn version_line_matches(version: &str, request: &str) -> bool {
    let normalized = normalize_version_line(request);
    (!request.is_empty() && on_version_line(version, request))
        || (!normalized.is_empty() && on_version_line(version, normalized))
}

/// Whether `request` reads as a version line rather than a version of its own.
///
/// A line is a partial version: one or two numeric components (`1`, `1.5`), under
/// the same normalization [`version_line_matches`] applies. Anything else — a
/// full `1.5.7`, a prerelease, a word like `stable` — names a version, even one
/// nothing publishes yet. The distinction decides who owns a request that matches
/// nothing: a line can only ever have meant "newest on this line", so an empty
/// line is an error the operator must see, while a version may simply not have
/// been pushed yet and is stored as written.
#[must_use]
pub fn is_version_line(request: &str) -> bool {
    let normalized = normalize_version_line(request);
    if normalized.is_empty() {
        return false;
    }
    normalized.split('.').count() < 3
        && normalized
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// What `request` names in `versions`: itself when it is one of them, otherwise
/// the newest version on the line it names, **preferring a stable release**.
///
/// Exact wins outright — `2` means the version `2` even where a `2.1.0` exists,
/// and `1.5.8-rc1` means itself even where a `1.5.8-rc1.2` sits above it on the
/// same line. Failing that, a prefix names a line: `1.5` resolves to `1.5.7`
/// even when the source also publishes `1.5.8-rc1`, and reaches a prerelease only
/// when the line has nothing else, so a line that is all prereleases resolves to
/// the newest of them rather than to nothing.
///
/// `versions` must arrive in the caller's own newest-first order, and that order
/// is what "newest" means here: a recipe's `sort` decides which of its versions
/// is newest, and this must not overrule it. A caller holding an unordered set —
/// install records read off disk — sorts before calling.
#[must_use]
pub fn newest_on_version_line<'a>(
    versions: impl IntoIterator<Item = &'a str>,
    request: &str,
) -> Option<&'a str> {
    let mut stable: Option<&'a str> = None;
    let mut prerelease: Option<&'a str> = None;
    for version in versions {
        if version == request {
            return Some(version);
        }
        if !version_line_matches(version, request) {
            continue;
        }
        // First match in the caller's order is the newest by the caller's rule;
        // the stable one only loses if there is none.
        if is_prerelease(version) {
            prerelease.get_or_insert(version);
        } else {
            stable.get_or_insert(version);
        }
    }
    stable.or(prerelease)
}

/// Whether `version` carries a semver prerelease suffix — everything after the
/// first `-`, the same split the ordering parses.
fn is_prerelease(version: &str) -> bool {
    semver_key(version).prerelease.is_some()
}

fn on_version_line(version: &str, line: &str) -> bool {
    version
        .strip_prefix(line)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

fn normalize_version_line(request: &str) -> &str {
    let request = request.trim_end_matches('.');
    request.strip_prefix('v').unwrap_or(request)
}

fn compare_versions(left: &str, right: &str, sort: VersionSort) -> Ordering {
    match sort {
        VersionSort::Semver => compare_semver_desc(left, right),
        VersionSort::Numeric => numeric_key(right)
            .cmp(&numeric_key(left))
            .then_with(|| right.cmp(left)),
        VersionSort::String => right.cmp(left),
    }
}

fn compare_semver_asc(left: &str, right: &str) -> Ordering {
    let left = semver_key(left);
    let right = semver_key(right);
    compare_core_parts(&left.core, &right.core).then_with(|| {
        match (&left.prerelease, &right.prerelease) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => left.cmp(right),
        }
    })
}

fn semver_key(version: &str) -> SemverKey {
    let version = strip_version_prefix(version);
    let without_build = version.split_once('+').map_or(version, |(core, _)| core);
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    SemverKey {
        core: core
            .split('.')
            .map(parse_core_part)
            .collect::<Vec<VersionPart>>(),
        prerelease: prerelease.map(|value| {
            value
                .split('.')
                .map(parse_prerelease_part)
                .collect::<Vec<PrereleasePart>>()
        }),
    }
}

fn parse_core_part(part: &str) -> VersionPart {
    part.parse::<u64>()
        .map_or_else(|_| VersionPart::Text(part.to_owned()), VersionPart::Number)
}

fn parse_prerelease_part(part: &str) -> PrereleasePart {
    part.parse::<u64>().map_or_else(
        |_| PrereleasePart::Text(alnum_runs(part)),
        PrereleasePart::Number,
    )
}

/// Strips one leading `v` from a version that then starts with a digit, so
/// `v0.5.0` and `0.4.0` compare as the versions they name rather than as text.
///
/// The digit test keeps a genuinely alphabetic version (`vega`) intact instead of
/// silently comparing it as `ega`.
fn strip_version_prefix(version: &str) -> &str {
    version
        .strip_prefix('v')
        .filter(|rest| rest.starts_with(|char: char| char.is_ascii_digit()))
        .unwrap_or(version)
}

/// Splits an alphanumeric identifier into its digit and non-digit runs.
///
/// Semver compares such an identifier as plain text, which puts `rc9` above
/// `rc88` — the wrong way round for a release train that counts its candidates
/// up. Comparing run by run, with the digit runs numeric, orders them the way
/// their publisher numbered them.
fn alnum_runs(part: &str) -> Vec<AlnumRun> {
    let mut runs = Vec::new();
    let mut rest = part;
    while !rest.is_empty() {
        let digits = rest.starts_with(|char: char| char.is_ascii_digit());
        let end = rest
            .find(|char: char| char.is_ascii_digit() != digits)
            .unwrap_or(rest.len());
        let (run, tail) = rest.split_at(end);
        runs.push(match run.parse::<u64>() {
            // A digit run too long for u64 is no longer a count; keep it as text.
            Ok(number) if digits => AlnumRun::Number(number),
            _ => AlnumRun::Text(run.to_owned()),
        });
        rest = tail;
    }
    runs
}

fn compare_core_parts(left: &[VersionPart], right: &[VersionPart]) -> Ordering {
    let max_len = left.len().max(right.len());
    for idx in 0..max_len {
        let ordering = core_part_at(left, idx).cmp(&core_part_at(right, idx));
        if !ordering.is_eq() {
            return ordering;
        }
    }
    Ordering::Equal
}

fn core_part_at(parts: &[VersionPart], idx: usize) -> VersionPart {
    parts.get(idx).cloned().unwrap_or(VersionPart::Number(0))
}

fn numeric_key(version: &str) -> Vec<u64> {
    version
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<u64>().unwrap_or(u64::MAX))
        .collect()
}

fn version_sort(filter: &VersionFilter) -> Result<VersionSort> {
    match filter.sort.as_deref().unwrap_or("semver") {
        "semver" => Ok(VersionSort::Semver),
        "numeric" => Ok(VersionSort::Numeric),
        "string" => Ok(VersionSort::String),
        sort => Err(CliError::Usage(format!(
            "invalid version filter sort {sort:?}; expected semver, numeric, or string"
        ))),
    }
}

fn normalize_release_tag(tag: &str) -> String {
    tag.strip_prefix('v').unwrap_or(tag).to_owned()
}

/// The tail of the pipeline over already-extracted entries: filter, sort, prune,
/// limit.
fn finish_pipeline(entries: Vec<RawVersion>, filter: &VersionFilter) -> Result<Vec<String>> {
    let include_prereleases = filter.prerelease.unwrap_or(false);
    let excluded = filter.exclude.iter().collect::<BTreeSet<_>>();
    let mut versions: Vec<String> = entries
        .into_iter()
        .filter(|entry| include_prereleases || !entry.prerelease)
        .map(|entry| entry.value)
        .filter(|version| !excluded.contains(version))
        .collect();
    // Distinct raw tags can extract or normalize to one version (`v1.2.3` and
    // `1.2.3`), and a duplicate would otherwise survive all the way to storage.
    let mut seen = BTreeSet::new();
    versions.retain(|version| seen.insert(version.clone()));
    order_and_prune(versions, filter)
}

/// The name of the group that, when a pattern declares it, carries the version.
const VERSION_GROUP: &str = "version";

/// Applies `filter.pattern` and screens what survives.
///
/// A pattern that declares a `(?P<version>…)` group extracts: the group's text
/// replaces the string every later stage sees — `exclude`, sorting, pruning, the
/// caller's storage. Any other pattern, including one with ordinary groups, is a
/// match-only filter that carries its input verbatim; grouping for alternation
/// (`^(rust-v)?1\.`) is common and must not silently rewrite versions.
///
/// Whatever comes out must be usable as an OCI tag, since a discovered version is
/// referenced as `name:version`. An unusable string is dropped rather than
/// emitted: server-side, one illegal entry would fail validation for the whole
/// snapshot.
fn extract_versions(entries: Vec<RawVersion>, pattern: Option<&str>) -> Result<Vec<RawVersion>> {
    let mut entries = match pattern {
        None => entries,
        Some(pattern) => {
            let pattern = regex::Regex::new(pattern)
                .map_err(|err| CliError::Usage(format!("invalid version filter pattern: {err}")))?;
            let extracting = pattern
                .capture_names()
                .any(|name| name == Some(VERSION_GROUP));
            entries
                .into_iter()
                .filter_map(|entry| {
                    let found = pattern.captures(&entry.value)?;
                    // A `version` group that did not participate in the match
                    // yields no version string, so the entry is dropped rather
                    // than guessed at.
                    let value = if extracting {
                        found.name(VERSION_GROUP)?.as_str().to_owned()
                    } else {
                        entry.value
                    };
                    Some(RawVersion {
                        value,
                        prerelease: entry.prerelease,
                    })
                })
                .collect()
        }
    };
    entries.retain(|entry| crate::reference::is_valid_tag(&entry.value));
    Ok(entries)
}

/// Sort, prune, and limit an already-extracted list. Shared by the merge path,
/// which must not re-extract.
fn order_and_prune(mut versions: Vec<String>, filter: &VersionFilter) -> Result<Vec<String>> {
    let sort = version_sort(filter)?;
    let prune = latest_per(filter)?;
    versions.sort_by(|left, right| compare_versions(left, right, sort));
    prune_lines(&mut versions, prune);
    if let Some(limit) = filter.limit {
        versions.truncate(limit);
    }
    Ok(versions)
}

/// Keeps the first — that is, the newest under the active sort — version of each
/// line. Versions with no parseable line are never grouped and never dropped.
fn prune_lines(versions: &mut Vec<String>, prune: LatestPer) {
    if prune == LatestPer::None {
        return;
    }
    let mut seen: BTreeSet<Vec<u64>> = BTreeSet::new();
    versions.retain(|version| version_line(version, prune).is_none_or(|line| seen.insert(line)));
}

/// The `major` or `major.minor` line a version belongs to, or `None` when the
/// numeric components a line needs are not there (`R2025a`, `2024b`, a bare `1`
/// under `minor`).
///
/// Grouping reads the same parse the sort does, so a version can never sort as
/// one thing and group as another.
fn version_line(version: &str, prune: LatestPer) -> Option<Vec<u64>> {
    let wanted = match prune {
        LatestPer::None => return None,
        LatestPer::Major => 1,
        LatestPer::Minor => 2,
    };
    let line: Vec<u64> = semver_key(version)
        .core
        .into_iter()
        .take(wanted)
        .map(|part| match part {
            VersionPart::Number(number) => Some(number),
            VersionPart::Text(_) => None,
        })
        .collect::<Option<Vec<u64>>>()?;
    (line.len() == wanted).then_some(line)
}

fn latest_per(filter: &VersionFilter) -> Result<LatestPer> {
    match filter.latest_per.as_deref().unwrap_or("none") {
        "none" => Ok(LatestPer::None),
        "major" => Ok(LatestPer::Major),
        "minor" => Ok(LatestPer::Minor),
        other => Err(CliError::Usage(format!(
            "invalid version filter latest_per {other:?}; expected major, minor, or none"
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LatestPer {
    None,
    Major,
    Minor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionSort {
    Semver,
    Numeric,
    String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemverKey {
    core: Vec<VersionPart>,
    prerelease: Option<Vec<PrereleasePart>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VersionPart {
    Number(u64),
    Text(String),
}

impl Ord for VersionPart {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Number(left), Self::Number(right)) => left.cmp(right),
            (Self::Text(left), Self::Text(right)) => left.cmp(right),
            (Self::Number(_), Self::Text(_)) => Ordering::Greater,
            (Self::Text(_), Self::Number(_)) => Ordering::Less,
        }
    }
}

impl PartialOrd for VersionPart {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One `.`-separated prerelease identifier: numeric when it is all digits, else
/// its alphanumeric runs ([`alnum_runs`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum PrereleasePart {
    Number(u64),
    Text(Vec<AlnumRun>),
}

/// A digit or non-digit run inside one alphanumeric prerelease identifier.
///
/// Derived ordering: a text run sorts below a number run, text runs compare
/// lexically and number runs numerically, and a `Vec` of them compares run by
/// run — so `rc` then `9` lands below `rc` then `88`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum AlnumRun {
    Text(String),
    Number(u64),
}

impl Ord for PrereleasePart {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Number(left), Self::Number(right)) => left.cmp(right),
            (Self::Text(left), Self::Text(right)) => left.cmp(right),
            (Self::Number(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Number(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for PrereleasePart {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Page size for the forge list endpoints, bounded by the recipe's own
/// `filter.limit`.
///
/// A release entry carries full notes and asset metadata, so a fixed
/// 100-entry page can dwarf any response budget (openai/codex serves
/// ~27 MiB). Fetching only what the recipe keeps may undershoot after
/// prerelease/pattern filtering — that trade-off belongs to the recipe
/// author.
///
/// The clamp is off once `latest_per` is active: pruning happens before `limit`,
/// so `limit` no longer describes how many entries the source has to yield.
/// The largest page the forges serve, and what a full walk asks for.
const FORGE_MAX_PAGE_SIZE: usize = 100;

/// The `page` query fragment for a forge request, empty for the first page: page 1
/// is every API's default, so omitting it keeps a single-page read byte for byte
/// what it has always sent.
fn page_query(page: usize) -> String {
    if page > 1 {
        format!("&page={page}")
    } else {
        String::new()
    }
}

fn forge_page_size(filter: &VersionFilter) -> usize {
    if matches!(latest_per(filter), Ok(LatestPer::None)) {
        filter.limit.map_or(100, |limit| limit.clamp(1, 100))
    } else {
        100
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
}

/// Lists releases newest-first. GitHub marks prereleases and hides drafts, so the
/// marking rides along and `filter.prerelease` decides later.
async fn list_github_releases(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    budget: FetchBudget,
    per_page: usize,
    validator: Option<&str>,
    page: usize,
) -> Result<SourceFetch> {
    let (owner, repo) = parse_github_repo_url(url)?;
    let path = format!(
        "/repos/{owner}/{repo}/releases?per_page={per_page}{}",
        page_query(page)
    );
    let response = github_get(client, &path, token, budget, validator).await?;
    response.decode("GitHub", NEWEST_FIRST, per_page, |body| {
        let releases: Vec<Release> = serde_json::from_slice(body)?;
        Ok(releases
            .into_iter()
            .map(|release| RawVersion {
                value: normalize_release_tag(&release.tag_name),
                prerelease: release.prerelease,
            })
            .collect())
    })
}

/// Decodes a tag listing. Tag endpoints order by name or commit date, never by
/// release chronology, so the whole page is always read.
fn decode_tags(body: &[u8]) -> std::result::Result<Vec<RawVersion>, serde_json::Error> {
    let entries: Vec<TagEntry> = serde_json::from_slice(body)?;
    Ok(entries
        .into_iter()
        .map(|entry| RawVersion::release(normalize_release_tag(&entry.name)))
        .collect())
}

/// Whether a source's page is ordered newest-first, which is the precondition for
/// cutting it at the first version the caller already knows.
const NEWEST_FIRST: bool = true;
const ANY_ORDER: bool = false;

/// Flattens an error's cause chain into one line.
///
/// `reqwest`'s `Display` stops at the outermost layer ("error sending request
/// for url (…)"), hiding the part that matters — a timeout, a refused
/// connection, a TLS failure. Discovery failures are stored as opaque status
/// strings, so the chain has to be flattened before the cause is lost.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// One forge API response: the body, or nothing when the forge answered `304`.
struct ApiResponse {
    body: Option<Vec<u8>>,
    validator: Option<String>,
}

impl ApiResponse {
    /// Turns a body into source entries, or reports the unchanged page.
    ///
    /// `per_page` is the page size that was asked for, which is the only handle a
    /// single-page fetch has on whether it saw everything: a page that came back
    /// short is the end of the listing, a full one says nothing.
    fn decode(
        self,
        label: &str,
        newest_first: bool,
        per_page: usize,
        parse: impl FnOnce(&[u8]) -> std::result::Result<Vec<RawVersion>, serde_json::Error>,
    ) -> Result<SourceFetch> {
        let Some(body) = self.body else {
            return Ok(SourceFetch {
                entries: Vec::new(),
                validator: self.validator,
                not_modified: true,
                newest_first,
                whole_offering: false,
            });
        };
        let entries = parse(&body)
            .map_err(|err| CliError::Operational(format!("decode {label} response: {err}")))?;
        Ok(SourceFetch {
            whole_offering: entries.len() < per_page,
            entries,
            validator: self.validator,
            not_modified: false,
            newest_first,
        })
    }
}

async fn github_get(
    client: &reqwest::Client,
    path: &str,
    token: Option<&str>,
    budget: FetchBudget,
    validator: Option<&str>,
) -> Result<ApiResponse> {
    let api_base = std::env::var("ORC_GITHUB_API_BASE_URL")
        .unwrap_or_else(|_| "https://api.github.com".to_owned())
        .trim_end_matches('/')
        .to_owned();
    forge_get(
        client,
        "GitHub",
        &format!("{api_base}{path}"),
        path,
        token,
        budget,
        validator,
    )
    .await
}

/// One authenticated forge API GET with the shared status mapping, conditional
/// request, and body cap. `display` is the path used in operator-facing errors, so
/// a test base URL never leaks into a stored status string.
async fn forge_get(
    client: &reqwest::Client,
    label: &str,
    url: &str,
    display: &str,
    token: Option<&str>,
    budget: FetchBudget,
    validator: Option<&str>,
) -> Result<ApiResponse> {
    let mut request = client.get(url).timeout(budget.timeout);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(validator) = validator {
        request = request.header(reqwest::header::IF_NONE_MATCH, validator);
    }
    let response = request.send().await.map_err(|err| {
        CliError::Operational(format!("{label} GET {display}: {}", error_chain(&err)))
    })?;
    let status = response.status();
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if status == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(ApiResponse {
            body: None,
            // A 304 need not repeat the ETag; keep the one that produced it.
            validator: etag.or_else(|| validator.map(str::to_owned)),
        });
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(CliError::Auth(format!(
            "{label} access denied for {display}"
        )));
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(CliError::NotFound(format!(
            "{label} resource not found: {display}"
        )));
    }
    if !status.is_success() {
        return Err(CliError::Operational(format!(
            "{label} GET {display} returned {status}"
        )));
    }
    let body = read_capped(response, display, budget.max_bytes).await?;
    Ok(ApiResponse {
        body: Some(body),
        validator: etag,
    })
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TagEntry {
    name: String,
}

/// Lists tag names for a repository. Some projects (aws/aws-cli) tag every
/// release without publishing GitHub releases, so tags are the only
/// enumerable source; there is no prerelease concept — the recipe's
/// `filter.pattern` is the author's guard.
async fn list_github_tags(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    budget: FetchBudget,
    per_page: usize,
    validator: Option<&str>,
    page: usize,
) -> Result<SourceFetch> {
    let (owner, repo) = parse_github_repo_url(url)?;
    let path = format!(
        "/repos/{owner}/{repo}/tags?per_page={per_page}{}",
        page_query(page)
    );
    let response = github_get(client, &path, token, budget, validator).await?;
    response.decode("GitHub", ANY_ORDER, per_page, decode_tags)
}

/// A GitLab release. `upcoming_release` is the only prerelease signal the API
/// carries, and projects that never set a future `released_at` simply never
/// produce one.
#[derive(Debug, Clone, serde::Deserialize)]
struct GitlabRelease {
    tag_name: String,
    #[serde(default)]
    upcoming_release: bool,
}

async fn list_gitlab_releases(
    client: &reqwest::Client,
    url: &str,
    budget: FetchBudget,
    per_page: usize,
    validator: Option<&str>,
    page: usize,
) -> Result<SourceFetch> {
    let endpoint = GitlabProject::parse(url)?.endpoint(&["releases"], per_page, page)?;
    let response = gitlab_get(client, &endpoint, budget, validator).await?;
    response.decode("GitLab", NEWEST_FIRST, per_page, |body| {
        let releases: Vec<GitlabRelease> = serde_json::from_slice(body)?;
        Ok(releases
            .into_iter()
            .map(|release| RawVersion {
                value: normalize_release_tag(&release.tag_name),
                prerelease: release.upcoming_release,
            })
            .collect())
    })
}

/// Lists repository tags for projects that tag releases without publishing GitLab
/// releases. No prerelease concept — `filter.pattern` is the author's guard.
async fn list_gitlab_tags(
    client: &reqwest::Client,
    url: &str,
    budget: FetchBudget,
    per_page: usize,
    validator: Option<&str>,
    page: usize,
) -> Result<SourceFetch> {
    let endpoint = GitlabProject::parse(url)?.endpoint(&["repository", "tags"], per_page, page)?;
    let response = gitlab_get(client, &endpoint, budget, validator).await?;
    response.decode("GitLab", ANY_ORDER, per_page, decode_tags)
}

async fn gitlab_get(
    client: &reqwest::Client,
    endpoint: &reqwest::Url,
    budget: FetchBudget,
    validator: Option<&str>,
) -> Result<ApiResponse> {
    let display = endpoint.query().map_or_else(
        || endpoint.path().to_owned(),
        |query| format!("{}?{query}", endpoint.path()),
    );
    forge_get(
        client,
        "GitLab",
        endpoint.as_str(),
        &display,
        None,
        budget,
        validator,
    )
    .await
}

/// A GitLab project reference: the instance the project lives on plus the
/// namespaced project path, which the API takes as one URL-encoded id
/// (`group/sub/proj` → `group%2Fsub%2Fproj`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct GitlabProject {
    /// Instance origin, e.g. `https://gitlab.example.com:8443`.
    origin: String,
    path: String,
}

impl GitlabProject {
    fn parse(url: &str) -> Result<Self> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|err| CliError::Usage(format!("invalid GitLab project URL {url:?}: {err}")))?;
        if !matches!(parsed.scheme(), "https" | "http") {
            return Err(CliError::Usage(format!(
                "unsupported GitLab project URL {url:?}"
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| CliError::Usage(format!("GitLab project URL {url:?} has no host")))?;
        // A project may be nested in subgroups, so the whole path is the id; a
        // `.git` suffix and the web UI's `/-/…` tail are not part of it.
        let path = parsed.path();
        let path = path.split("/-/").next().unwrap_or(path);
        let path = path.trim_matches('/').trim_end_matches(".git");
        if path.is_empty() {
            return Err(CliError::Usage(format!(
                "missing GitLab project path in {url:?}"
            )));
        }
        let origin = match parsed.port() {
            Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        };
        Ok(Self {
            origin,
            path: path.to_owned(),
        })
    }

    /// Builds `{api base}/projects/{project}/{tail…}?per_page=N`. The project id
    /// is pushed as one path segment, so `Url` encodes the separators that make it
    /// nested.
    fn endpoint(&self, tail: &[&str], per_page: usize, page: usize) -> Result<reqwest::Url> {
        let base = self.api_base();
        let mut url = reqwest::Url::parse(&base)
            .map_err(|err| CliError::Usage(format!("invalid GitLab API base {base:?}: {err}")))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| CliError::Usage(format!("invalid GitLab API base {base:?}")))?;
            segments.pop_if_empty();
            segments.push("projects").push(&self.path);
            segments.extend(tail);
        }
        url.query_pairs_mut()
            .append_pair("per_page", &per_page.to_string());
        // Page 1 is the default everywhere; leaving it off keeps the request
        // identical to what a single-page read has always sent.
        if page > 1 {
            url.query_pairs_mut().append_pair("page", &page.to_string());
        }
        Ok(url)
    }

    /// The v4 API of the instance hosting the project, so a self-hosted GitLab
    /// needs no extra configuration. The env override exists for tests.
    fn api_base(&self) -> String {
        std::env::var("ORC_GITLAB_API_BASE_URL")
            .unwrap_or_else(|_| format!("{}/api/v4", self.origin))
            .trim_end_matches('/')
            .to_owned()
    }
}

fn parse_github_repo_url(url: &str) -> Result<(&str, &str)> {
    let trimmed = url.trim_end_matches('/');
    let path = trimmed
        .strip_prefix("https://github.com/")
        .or_else(|| trimmed.strip_prefix("http://github.com/"))
        .ok_or_else(|| CliError::Usage(format!("unsupported GitHub releases URL {url:?}")))?;
    let mut parts = path.split('/');
    let owner = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Usage(format!("missing GitHub owner in {url:?}")))?;
    let repo = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Usage(format!("missing GitHub repo in {url:?}")))?;
    Ok((owner, repo))
}

async fn fetch_http_versions(
    client: &reqwest::Client,
    url: &str,
    budget: FetchBudget,
) -> Result<Vec<String>> {
    let response = client
        .get(url)
        .timeout(budget.timeout)
        .send()
        .await
        .map_err(|err| {
            CliError::Operational(format!("fetch version list {url}: {}", error_chain(&err)))
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(CliError::Operational(format!(
            "fetch version list {url} returned {status}"
        )));
    }
    let body = read_capped(response, url, budget.max_bytes).await?;
    Ok(parse_http_versions(&String::from_utf8_lossy(&body)))
}

/// Reads a JSON document and pulls the versions out of the selected node.
async fn fetch_json_versions(
    client: &reqwest::Client,
    discovery: &VersionDiscovery,
    budget: FetchBudget,
) -> Result<Vec<RawVersion>> {
    let document: serde_json::Value = fetch_json(client, &discovery.url, budget).await?;
    let selected = select_node(&document, discovery.select.as_deref(), &discovery.url)?;
    json_versions(selected, discovery.field.as_deref(), &discovery.url)
}

/// Resolves `select` as an RFC 6901 pointer, or hands back the document root.
fn select_node<'a>(
    document: &'a serde_json::Value,
    select: Option<&str>,
    url: &str,
) -> Result<&'a serde_json::Value> {
    let Some(pointer) = select.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(document);
    };
    if !pointer.starts_with('/') {
        return Err(CliError::Usage(format!(
            "invalid select {pointer:?} for {url}: a JSON pointer starts with '/'"
        )));
    }
    document.pointer(pointer).ok_or_else(|| {
        CliError::Operational(format!(
            "select {pointer:?} not found in version source {url}"
        ))
    })
}

/// Reads the selected node by shape: an array of strings is the list, an array of
/// objects yields each element's `field`, an object yields its keys. Anything else
/// is a source error rather than a guess.
fn json_versions(
    node: &serde_json::Value,
    field: Option<&str>,
    url: &str,
) -> Result<Vec<RawVersion>> {
    match node {
        serde_json::Value::Array(items) if items.iter().all(serde_json::Value::is_string) => {
            Ok(items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(|version| RawVersion::release(version.to_owned()))
                .collect())
        }
        serde_json::Value::Array(items) if items.iter().all(serde_json::Value::is_object) => {
            let field = field.ok_or_else(|| {
                CliError::Usage(format!(
                    "version source {url} selects an array of objects; set `field` to the version property"
                ))
            })?;
            // Every entry must carry it. Skipping the ones that do not would let a
            // typo'd field name commit a partial list as if it were the whole one.
            items
                .iter()
                .map(|item| {
                    item.get(field)
                        .and_then(serde_json::Value::as_str)
                        .map(|version| RawVersion::release(version.to_owned()))
                        .ok_or_else(|| {
                            CliError::Operational(format!(
                                "entry in version source {url} has no string field {field:?}"
                            ))
                        })
                })
                .collect()
        }
        serde_json::Value::Array(_) => Err(CliError::Operational(format!(
            "version source {url} selects a mixed array; expected strings or objects"
        ))),
        serde_json::Value::Object(map) => Ok(map
            .keys()
            .map(|version| RawVersion::release(version.clone()))
            .collect()),
        other => Err(CliError::Operational(format!(
            "version source {url} selects {}; expected an array or an object",
            json_shape(other)
        ))),
    }
}

fn json_shape(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

async fn fetch_nuget_versions(
    client: &reqwest::Client,
    url: &str,
    repository: &str,
    budget: FetchBudget,
) -> Result<Vec<String>> {
    let package_id = package_id_from_repository(repository).to_ascii_lowercase();
    let base_url = if url.is_empty() {
        "https://api.nuget.org/v3/registration5-semver2"
    } else {
        url
    };
    let index_url = format!("{}/{package_id}/index.json", base_url.trim_end_matches('/'));
    let index = fetch_json::<NugetRegistrationIndex>(client, &index_url, budget).await?;
    let mut versions = Vec::new();
    for page in index.items {
        if let Some(items) = page.items {
            collect_nuget_versions(items, &mut versions);
        } else if let Some(page_url) = page.id {
            let page = fetch_json::<NugetRegistrationPage>(client, &page_url, budget).await?;
            if let Some(items) = page.items {
                collect_nuget_versions(items, &mut versions);
            }
        }
    }
    Ok(versions)
}

async fn fetch_winget_versions(
    client: &reqwest::Client,
    url: &str,
    repository: &str,
    budget: FetchBudget,
) -> Result<Vec<String>> {
    let package_id = package_id_from_repository(repository);
    let base_url = if url.is_empty() {
        "https://cdn.winget.microsoft.com/cache"
    } else {
        url
    };
    let endpoint = format!(
        "{}/packages/{package_id}/versions",
        base_url.trim_end_matches('/')
    );
    let mut versions = Vec::new();
    let mut continuation: Option<String> = None;
    loop {
        let mut request_url = reqwest::Url::parse(&endpoint).map_err(|err| {
            CliError::Usage(format!("invalid winget feed URL {endpoint:?}: {err}"))
        })?;
        if let Some(token) = &continuation {
            request_url
                .query_pairs_mut()
                .append_pair("ContinuationToken", token);
        }
        let response =
            fetch_json::<WingetVersionResponse>(client, request_url.as_str(), budget).await?;
        versions.extend(
            response
                .data
                .into_iter()
                .filter_map(|version| version.version),
        );
        continuation = response
            .continuation_token
            .filter(|token| !token.is_empty());
        if continuation.is_none() {
            break;
        }
    }
    Ok(versions)
}

fn parse_http_versions(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn collect_nuget_versions(items: Vec<NugetRegistrationLeaf>, versions: &mut Vec<String>) {
    versions.extend(items.into_iter().filter_map(|leaf| {
        let entry = leaf.catalog_entry?;
        if !entry.listed.unwrap_or(true) {
            return None;
        }
        entry.version
    }));
}

fn package_id_from_repository(repository: &str) -> &str {
    repository
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or(repository)
}

async fn fetch_json<T>(client: &reqwest::Client, url: &str, budget: FetchBudget) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let response = client
        .get(url)
        .timeout(budget.timeout)
        .send()
        .await
        .map_err(|err| CliError::Operational(format!("GET {url}: {}", error_chain(&err))))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(CliError::NotFound(format!("resource not found: {url}")));
    }
    if !status.is_success() {
        return Err(CliError::Operational(format!(
            "GET {url} returned {status}"
        )));
    }
    let body = read_capped(response, url, budget.max_bytes).await?;
    serde_json::from_slice(&body)
        .map_err(|err| CliError::Operational(format!("decode response from {url}: {err}")))
}

/// Reads a response body, rejecting anything over `max_bytes`.
///
/// The advertised `Content-Length` is checked first so an oversized source is
/// refused before its body is buffered; the buffered length is re-checked for
/// chunked responses that omit the header.
async fn read_capped(response: reqwest::Response, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    if let Some(len) = response.content_length()
        && len > max_bytes as u64
    {
        return Err(CliError::Operational(format!(
            "version source {url} exceeds {max_bytes}-byte limit"
        )));
    }
    let body = response.bytes().await.map_err(|err| {
        CliError::Operational(format!("read version source {url}: {}", error_chain(&err)))
    })?;
    if body.len() > max_bytes {
        return Err(CliError::Operational(format!(
            "version source {url} exceeds {max_bytes}-byte limit"
        )));
    }
    Ok(body.to_vec())
}

#[derive(Debug, serde::Deserialize)]
struct NugetRegistrationIndex {
    #[serde(default)]
    items: Vec<NugetRegistrationPage>,
}

#[derive(Debug, serde::Deserialize)]
struct NugetRegistrationPage {
    #[serde(rename = "@id", default)]
    id: Option<String>,
    #[serde(default)]
    items: Option<Vec<NugetRegistrationLeaf>>,
}

#[derive(Debug, serde::Deserialize)]
struct NugetRegistrationLeaf {
    #[serde(rename = "catalogEntry", default)]
    catalog_entry: Option<NugetCatalogEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct NugetCatalogEntry {
    version: Option<String>,
    #[serde(default)]
    listed: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
struct WingetVersionResponse {
    #[serde(rename = "Data", default)]
    data: Vec<WingetVersion>,
    #[serde(rename = "ContinuationToken", default)]
    continuation_token: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct WingetVersion {
    #[serde(rename = "PackageVersion", default)]
    version: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Each recorded request: path with query, plus its `If-None-Match`.
    type SeenRequests = Arc<Mutex<Vec<(String, Option<String>)>>>;

    /// One canned response, keyed by request path.
    #[derive(Clone)]
    struct MockRoute {
        body: String,
        /// When set, a matching `If-None-Match` is answered `304`.
        etag: Option<String>,
    }

    impl MockRoute {
        fn json(body: &serde_json::Value) -> Self {
            Self {
                body: body.to_string(),
                etag: None,
            }
        }

        fn tagged(body: &serde_json::Value, etag: &str) -> Self {
            Self {
                body: body.to_string(),
                etag: Some(etag.to_owned()),
            }
        }
    }

    #[derive(Clone)]
    struct MockState {
        routes: Arc<BTreeMap<String, MockRoute>>,
        seen: SeenRequests,
    }

    /// A throwaway HTTP source: fixed bodies per path, recording each request's
    /// path and `If-None-Match` so conditional behavior is assertable.
    struct MockSource {
        base: String,
        seen: SeenRequests,
    }

    impl MockSource {
        async fn start(routes: BTreeMap<String, MockRoute>) -> Self {
            use axum::extract::State;
            use axum::http::{HeaderMap, StatusCode, Uri, header};
            use axum::response::{IntoResponse as _, Response};

            async fn serve(
                State(state): State<MockState>,
                uri: Uri,
                headers: HeaderMap,
            ) -> Response {
                let conditional = headers
                    .get(header::IF_NONE_MATCH)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                state
                    .seen
                    .lock()
                    .expect("seen")
                    .push((uri.to_string(), conditional.clone()));
                // Routes key on the path alone unless one names a query too, which
                // is how a test serves a different body per page.
                let Some(route) = uri
                    .path_and_query()
                    .and_then(|full| state.routes.get(full.as_str()))
                    .or_else(|| state.routes.get(uri.path()))
                else {
                    return (StatusCode::NOT_FOUND, "no route").into_response();
                };
                match (&route.etag, &conditional) {
                    (Some(etag), Some(sent)) if etag == sent => {
                        (StatusCode::NOT_MODIFIED, [(header::ETAG, etag.clone())], ())
                            .into_response()
                    }
                    (Some(etag), _) => (
                        [
                            (header::ETAG, etag.clone()),
                            (header::CONTENT_TYPE, "application/json".to_owned()),
                        ],
                        route.body.clone(),
                    )
                        .into_response(),
                    (None, _) => (
                        [(header::CONTENT_TYPE, "application/json")],
                        route.body.clone(),
                    )
                        .into_response(),
                }
            }

            let seen = Arc::new(Mutex::new(Vec::new()));
            let state = MockState {
                routes: Arc::new(routes),
                seen: Arc::clone(&seen),
            };
            let app = axum::Router::new()
                .fallback(axum::routing::any(serve))
                .with_state(state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock source");
            let addr = listener.local_addr().expect("mock addr");
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            Self {
                base: format!("http://{addr}"),
                seen,
            }
        }

        fn requests(&self) -> Vec<(String, Option<String>)> {
            self.seen.lock().expect("seen").clone()
        }
    }

    fn limits() -> DiscoveryLimits {
        DiscoveryLimits::default()
    }

    /// The whole pipeline over plain strings, the shape most stages are tested at.
    fn apply_version_filter(versions: Vec<String>, filter: &VersionFilter) -> Result<Vec<String>> {
        run_pipeline(
            versions.into_iter().map(RawVersion::release).collect(),
            filter,
        )
    }

    fn run_pipeline(entries: Vec<RawVersion>, filter: &VersionFilter) -> Result<Vec<String>> {
        let entries = extract_versions(entries, filter.pattern.as_deref())?;
        finish_pipeline(entries, filter)
    }

    #[test]
    fn parses_github_repo_urls() {
        assert_eq!(
            parse_github_repo_url("https://github.com/jenkinsci/swarm-plugin").expect("parsed"),
            ("jenkinsci", "swarm-plugin")
        );
        assert!(parse_github_repo_url("https://example.com/acme/tool").is_err());
    }

    #[test]
    fn forge_page_size_follows_the_recipe_limit() {
        assert_eq!(forge_page_size(&VersionFilter::default()), 100);
        let limited = VersionFilter {
            limit: Some(30),
            ..VersionFilter::default()
        };
        assert_eq!(forge_page_size(&limited), 30);
        let oversized = VersionFilter {
            limit: Some(500),
            ..VersionFilter::default()
        };
        assert_eq!(forge_page_size(&oversized), 100);
        let zero = VersionFilter {
            limit: Some(0),
            ..VersionFilter::default()
        };
        assert_eq!(forge_page_size(&zero), 1);
    }

    #[test]
    fn release_tags_drop_common_v_prefix() {
        assert_eq!(normalize_release_tag("v3.46"), "3.46");
        assert_eq!(normalize_release_tag("release-1"), "release-1");
    }

    #[test]
    fn http_version_lists_ignore_blank_lines_and_comments() {
        assert_eq!(
            parse_http_versions("\n# comment\n3.46\n 3.45 \n"),
            ["3.46", "3.45"]
        );
    }

    #[test]
    fn nuget_registration_versions_ignore_unlisted_versions() {
        let items = serde_json::from_value::<Vec<NugetRegistrationLeaf>>(serde_json::json!([
            {"catalogEntry": {"version": "1.0.0", "listed": true}},
            {"catalogEntry": {"version": "1.1.0", "listed": false}},
            {"catalogEntry": {"version": "1.2.0"}}
        ]))
        .expect("nuget leaves");
        let mut versions = Vec::new();
        collect_nuget_versions(items, &mut versions);
        assert_eq!(versions, ["1.0.0", "1.2.0"]);
    }

    #[test]
    fn winget_version_response_reads_package_versions() {
        let response = serde_json::from_value::<WingetVersionResponse>(serde_json::json!({
            "Data": [
                {"PackageVersion": "2.0.0"},
                {"PackageVersion": "1.0.0"}
            ],
            "ContinuationToken": "next"
        }))
        .expect("winget response");
        assert_eq!(
            response
                .data
                .into_iter()
                .filter_map(|version| version.version)
                .collect::<Vec<_>>(),
            ["2.0.0", "1.0.0"]
        );
        assert_eq!(response.continuation_token.as_deref(), Some("next"));
    }

    #[test]
    fn version_filter_excludes_exact_values_and_limits_after_sorting() {
        let filter = VersionFilter {
            pattern: Some(r"^3\.".to_owned()),
            exclude: vec!["3.47".to_owned()],
            limit: Some(2),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "4.0".to_owned(),
                    "3.45".to_owned(),
                    "3.47".to_owned(),
                    "3.46".to_owned(),
                ],
                &filter
            )
            .expect("filter"),
            ["3.46", "3.45"]
        );
    }

    #[test]
    fn version_filter_supports_numeric_and_string_sort_modes() {
        let numeric = VersionFilter {
            sort: Some("numeric".to_owned()),
            limit: Some(2),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "item-9".to_owned(),
                    "item-10".to_owned(),
                    "item-2".to_owned()
                ],
                &numeric
            )
            .expect("numeric sort"),
            ["item-10", "item-9"]
        );

        let string = VersionFilter {
            sort: Some("string".to_owned()),
            limit: Some(2),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "item-9".to_owned(),
                    "item-10".to_owned(),
                    "item-2".to_owned()
                ],
                &string
            )
            .expect("string sort"),
            ["item-9", "item-2"]
        );
    }

    #[test]
    fn invalid_version_filter_pattern_is_usage_error() {
        let filter = VersionFilter {
            pattern: Some("(".to_owned()),
            ..VersionFilter::default()
        };
        assert!(matches!(
            apply_version_filter(vec!["1.0".to_owned()], &filter),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn invalid_version_filter_sort_is_usage_error() {
        let filter = VersionFilter {
            sort: Some("newest".to_owned()),
            ..VersionFilter::default()
        };
        assert!(matches!(
            apply_version_filter(vec!["1.0".to_owned()], &filter),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn a_named_version_group_replaces_the_version_string() {
        let filter = VersionFilter {
            pattern: Some(r"^jdk-(?P<version>\d+\.\d+\.\d+)$".to_owned()),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "jdk-21.0.1".to_owned(),
                    "jdk-17.0.9".to_owned(),
                    "nightly".to_owned(),
                ],
                &filter
            )
            .expect("extraction"),
            ["21.0.1", "17.0.9"]
        );
    }

    /// The extracted string, not the raw one, is what every later stage sees.
    #[test]
    fn extraction_feeds_exclude_and_sorting() {
        let filter = VersionFilter {
            pattern: Some(r"^v(?P<version>.+)$".to_owned()),
            exclude: vec!["1.5.7".to_owned()],
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "v1.5.7".to_owned(),
                    "v1.4.0".to_owned(),
                    "v1.10.0".to_owned()
                ],
                &filter
            )
            .expect("extraction"),
            ["1.10.0", "1.4.0"]
        );
    }

    #[test]
    fn pattern_without_any_group_stays_a_filter() {
        let filter = VersionFilter {
            pattern: Some(r"^v\d+\.\d+$".to_owned()),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec!["v3.46".to_owned(), "3.45".to_owned(), "v3.44".to_owned()],
                &filter
            )
            .expect("filter only"),
            ["v3.46", "v3.44"]
        );
    }

    /// Ordinary groups are how authors write alternation. Extracting from them
    /// would rewrite versions behind the author's back, so only the named group
    /// opts in.
    #[test]
    fn a_plain_capture_group_does_not_extract() {
        let filter = VersionFilter {
            pattern: Some(r"^(rust-v)?\d+\.\d+\.\d+$".to_owned()),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "rust-v1.2.3".to_owned(),
                    "1.2.4".to_owned(),
                    "nightly".to_owned(),
                ],
                &filter
            )
            .expect("filter only"),
            ["1.2.4", "rust-v1.2.3"]
        );
    }

    /// A version has to be usable as `name:version`, and an empty extraction is
    /// the worst case: server-side one illegal string fails the whole snapshot.
    #[test]
    fn versions_that_are_not_legal_tags_are_dropped() {
        let filter = VersionFilter {
            pattern: Some(r"^release-(?P<version>.*)$".to_owned()),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "release-".to_owned(),
                    "release-1.2.3".to_owned(),
                    "release-a b".to_owned(),
                ],
                &filter
            )
            .expect("screened"),
            ["1.2.3"]
        );
        // Screening applies without a pattern too: any source can emit junk.
        assert_eq!(
            apply_version_filter(
                vec!["1.0.0".to_owned(), "not a tag".to_owned()],
                &VersionFilter::default()
            )
            .expect("screened"),
            ["1.0.0"]
        );
    }

    /// Distinct raw tags can normalize onto one version; only one may survive.
    #[test]
    fn versions_are_deduplicated_after_extraction() {
        assert_eq!(
            run_pipeline(
                vec![
                    RawVersion::release("1.2.3".to_owned()),
                    RawVersion::release("1.2.3".to_owned()),
                    RawVersion::release("1.2.4".to_owned()),
                ],
                &VersionFilter::default()
            )
            .expect("dedup"),
            ["1.2.4", "1.2.3"]
        );
    }

    #[test]
    fn latest_per_defaults_to_keeping_every_version() {
        let versions = vec![
            "0.12.0".to_owned(),
            "0.11.9".to_owned(),
            "0.11.8".to_owned(),
        ];
        assert_eq!(
            apply_version_filter(versions.clone(), &VersionFilter::default()).expect("default"),
            versions
        );
    }

    #[test]
    fn latest_per_minor_keeps_the_newest_of_each_line() {
        let filter = VersionFilter {
            latest_per: Some("minor".to_owned()),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "0.11.8".to_owned(),
                    "0.12.0".to_owned(),
                    "0.9.25".to_owned(),
                    "0.11.9".to_owned(),
                    "0.9.24".to_owned(),
                ],
                &filter
            )
            .expect("prune"),
            ["0.12.0", "0.11.9", "0.9.25"]
        );
    }

    #[test]
    fn latest_per_major_keeps_the_newest_of_each_major_line() {
        let filter = VersionFilter {
            latest_per: Some("major".to_owned()),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "1.5.7".to_owned(),
                    "2.0.1".to_owned(),
                    "1.9.0".to_owned(),
                    "2.1.0".to_owned(),
                ],
                &filter
            )
            .expect("prune"),
            ["2.1.0", "1.9.0"]
        );
    }

    /// Pruning groups only what it can parse; everything else survives untouched.
    #[test]
    fn latest_per_passes_unparseable_versions_through() {
        let filter = VersionFilter {
            latest_per: Some("minor".to_owned()),
            sort: Some("string".to_owned()),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "R2025a".to_owned(),
                    "R2025b".to_owned(),
                    "2024b".to_owned(),
                    "1.2.3".to_owned(),
                    "1.2.4".to_owned(),
                ],
                &filter
            )
            .expect("prune"),
            ["R2025b", "R2025a", "2024b", "1.2.4"]
        );
    }

    /// `limit` truncates what pruning left, not what sorting produced.
    #[test]
    fn latest_per_prunes_before_the_limit_applies() {
        let filter = VersionFilter {
            latest_per: Some("minor".to_owned()),
            limit: Some(2),
            ..VersionFilter::default()
        };
        assert_eq!(
            apply_version_filter(
                vec![
                    "1.2.0".to_owned(),
                    "1.2.1".to_owned(),
                    "1.1.0".to_owned(),
                    "1.0.0".to_owned(),
                ],
                &filter
            )
            .expect("prune"),
            ["1.2.1", "1.1.0"]
        );
    }

    #[test]
    fn invalid_latest_per_is_usage_error() {
        let filter = VersionFilter {
            latest_per: Some("patch".to_owned()),
            ..VersionFilter::default()
        };
        assert!(matches!(
            apply_version_filter(vec!["1.0.0".to_owned()], &filter),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn prerelease_marked_entries_are_dropped_unless_asked_for() {
        let entries = vec![
            RawVersion::release("1.2.0".to_owned()),
            RawVersion {
                value: "1.3.0-rc1".to_owned(),
                prerelease: true,
            },
        ];
        assert_eq!(
            run_pipeline(entries.clone(), &VersionFilter::default()).expect("default"),
            ["1.2.0"]
        );
        let including = VersionFilter {
            prerelease: Some(true),
            ..VersionFilter::default()
        };
        assert_eq!(
            run_pipeline(entries, &including).expect("including"),
            ["1.3.0-rc1", "1.2.0"]
        );
    }

    #[test]
    fn json_selects_an_array_of_strings() {
        let document = serde_json::json!({"versions": ["3.46", "3.45"]});
        let node = select_node(&document, Some("/versions"), "u").expect("pointer");
        assert_eq!(
            json_versions(node, None, "u").expect("strings"),
            [
                RawVersion::release("3.46".to_owned()),
                RawVersion::release("3.45".to_owned())
            ]
        );
    }

    #[test]
    fn json_reads_the_named_field_of_an_object_array() {
        let document = serde_json::json!([{"version": "v22.1.0"}, {"version": "v20.11.1"}]);
        let node = select_node(&document, None, "u").expect("root");
        assert_eq!(
            json_versions(node, Some("version"), "u").expect("objects"),
            [
                RawVersion::release("v22.1.0".to_owned()),
                RawVersion::release("v20.11.1".to_owned())
            ]
        );
    }

    #[test]
    fn json_reads_object_keys() {
        let document = serde_json::json!({"1.0.0": {}, "2.0.0": {}});
        let node = select_node(&document, None, "u").expect("root");
        assert_eq!(
            json_versions(node, None, "u").expect("keys"),
            [
                RawVersion::release("1.0.0".to_owned()),
                RawVersion::release("2.0.0".to_owned())
            ]
        );
    }

    #[test]
    fn json_rejects_shapes_it_cannot_read() {
        let scalar = serde_json::json!(42);
        assert!(json_versions(&scalar, None, "u").is_err());

        let objects = serde_json::json!([{"version": "1.0.0"}]);
        // An object array without `field` is a recipe error, not a guess.
        assert!(matches!(
            json_versions(&objects, None, "u"),
            Err(CliError::Usage(_))
        ));
        // A field no entry carries would silently discover nothing.
        assert!(json_versions(&objects, Some("tag"), "u").is_err());
        // One entry missing it would silently commit a partial list.
        let partial = serde_json::json!([{"version": "1.0.0"}, {"other": "2.0.0"}]);
        assert!(json_versions(&partial, Some("version"), "u").is_err());

        let mixed = serde_json::json!(["1.0.0", {"version": "2.0.0"}]);
        assert!(json_versions(&mixed, None, "u").is_err());

        let empty = serde_json::json!([]);
        assert!(json_versions(&empty, None, "u").expect("empty").is_empty());
    }

    #[test]
    fn json_select_must_be_a_pointer_and_must_resolve() {
        let document = serde_json::json!({"versions": []});
        assert!(matches!(
            select_node(&document, Some("versions"), "u"),
            Err(CliError::Usage(_))
        ));
        assert!(select_node(&document, Some("/missing"), "u").is_err());
        assert!(select_node(&document, Some(""), "u").is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn json_source_evaluates_end_to_end() {
        let source = MockSource::start(BTreeMap::from([(
            "/dist/index.json".to_owned(),
            MockRoute::json(&serde_json::json!({
                "releases": [
                    {"version": "v22.1.0"},
                    {"version": "v22.0.0"},
                    {"version": "v20.11.1"},
                    {"version": "nightly"}
                ]
            })),
        )]))
        .await;
        let discovery = VersionDiscovery {
            source: "json".to_owned(),
            url: format!("{}/dist/index.json", source.base),
            select: Some("/releases".to_owned()),
            field: Some("version".to_owned()),
            filter: VersionFilter {
                pattern: Some(r"^v(?P<version>\d+\.\d+\.\d+)$".to_owned()),
                latest_per: Some("major".to_owned()),
                ..VersionFilter::default()
            },
            ..VersionDiscovery::default()
        };

        let outcome = evaluate(&discovery, "acme/node", &limits()).await;
        assert_eq!(outcome.source_error, None);
        assert_eq!(outcome.versions, ["22.1.0", "20.11.1"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gitlab_releases_honor_the_upcoming_marking() {
        let source = MockSource::start(BTreeMap::from([(
            "/api/v4/projects/group%2Fsub%2Ftool/releases".to_owned(),
            MockRoute::json(&serde_json::json!([
                {"tag_name": "v2.1.0", "upcoming_release": true},
                {"tag_name": "v2.0.0", "upcoming_release": false},
                {"tag_name": "v1.9.0"}
            ])),
        )]))
        .await;
        let discovery = VersionDiscovery {
            source: "gitlab_releases".to_owned(),
            url: format!("{}/group/sub/tool", source.base),
            ..VersionDiscovery::default()
        };

        let outcome = evaluate(&discovery, "acme/tool", &limits()).await;
        assert_eq!(outcome.source_error, None);
        assert_eq!(outcome.versions, ["2.0.0", "1.9.0"]);

        let with_upcoming = VersionDiscovery {
            filter: VersionFilter {
                prerelease: Some(true),
                ..VersionFilter::default()
            },
            ..discovery
        };
        let outcome = evaluate(&with_upcoming, "acme/tool", &limits()).await;
        assert_eq!(outcome.versions, ["2.1.0", "2.0.0", "1.9.0"]);
        // The nested project path reaches the API percent-encoded.
        assert!(
            source
                .requests()
                .iter()
                .all(|(path, _)| path.starts_with("/api/v4/projects/group%2Fsub%2Ftool/releases"))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gitlab_tags_list_repository_tags() {
        let source = MockSource::start(BTreeMap::from([(
            "/api/v4/projects/acme%2Ftool/repository/tags".to_owned(),
            MockRoute::json(&serde_json::json!([
                {"name": "v3.2.0"},
                {"name": "v3.1.0"}
            ])),
        )]))
        .await;
        let discovery = VersionDiscovery {
            source: "gitlab_tags".to_owned(),
            url: format!("{}/acme/tool.git", source.base),
            ..VersionDiscovery::default()
        };

        let outcome = evaluate(&discovery, "acme/tool", &limits()).await;
        assert_eq!(outcome.source_error, None);
        assert_eq!(outcome.versions, ["3.2.0", "3.1.0"]);
    }

    #[test]
    fn gitlab_project_urls_carry_host_and_nested_path() {
        let project = GitlabProject::parse("https://gitlab.com/group/sub/tool/").expect("parsed");
        assert_eq!(project.origin, "https://gitlab.com");
        assert_eq!(project.path, "group/sub/tool");
        // The nested path is one path segment, so its separators are encoded.
        assert_eq!(
            project
                .endpoint(&["releases"], 100, 1)
                .expect("endpoint")
                .as_str(),
            "https://gitlab.com/api/v4/projects/group%2Fsub%2Ftool/releases?per_page=100"
        );
        assert_eq!(
            GitlabProject::parse("https://gitlab.example.com:8443/acme/tool")
                .expect("parsed")
                .origin,
            "https://gitlab.example.com:8443"
        );
        assert_eq!(
            GitlabProject::parse("https://gitlab.example.com/acme/tool/-/releases")
                .expect("parsed")
                .path,
            "acme/tool"
        );
        assert!(GitlabProject::parse("gitlab.com/acme/tool").is_err());
        assert!(GitlabProject::parse("https://gitlab.com").is_err());
    }

    /// A caller with no incremental context gets the whole page, as always.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_evaluation_reads_the_entire_page() {
        let (source, discovery) = releases_source().await;
        let outcome = evaluate(&discovery, "acme/tool", &limits()).await;
        assert_eq!(outcome.versions, ["2.1.0", "2.0.0", "1.9.0"]);
        assert_eq!(outcome.validator.as_deref(), Some("\"page-1\""));
        assert!(!outcome.not_modified);
        assert!(
            outcome.complete,
            "three entries against a hundred-entry page is the end of the listing"
        );
        assert_eq!(source.requests()[0].1, None);
    }

    /// Incremental mode cuts the newest-first page at the first version the
    /// caller already stored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn incremental_evaluation_stops_at_the_first_known_version() {
        let (_source, discovery) = releases_source().await;
        let known = BTreeSet::from(["2.0.0".to_owned(), "1.9.0".to_owned()]);
        let request = DiscoveryRequest {
            known_versions: Some(&known),
            validator: None,
            paginate: false,
        };
        let outcome = evaluate_with(&discovery, "acme/tool", &limits(), &request).await;
        assert_eq!(outcome.versions, ["2.1.0"]);
        assert!(!outcome.not_modified);
        assert!(!outcome.complete, "the cut left entries on the page unread");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stored_validator_short_circuits_the_fetch() {
        let (source, discovery) = releases_source().await;
        let known = BTreeSet::from(["2.1.0".to_owned()]);
        let request = DiscoveryRequest {
            known_versions: Some(&known),
            validator: Some("\"page-1\""),
            paginate: false,
        };
        let outcome = evaluate_with(&discovery, "acme/tool", &limits(), &request).await;
        assert!(outcome.not_modified);
        assert!(outcome.versions.is_empty());
        assert_eq!(outcome.source_error, None);
        assert!(!outcome.complete, "a 304 read nothing");
        assert_eq!(outcome.validator.as_deref(), Some("\"page-1\""));
        assert_eq!(
            source.requests()[0].1.as_deref(),
            Some("\"page-1\""),
            "the stored validator rides along as If-None-Match"
        );
    }

    /// The cut belongs to the fetched page. A recipe's own `list` sits in front of
    /// it and must not end the scan before it starts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_static_list_does_not_cut_the_fetched_page() {
        let (_source, discovery) = releases_source().await;
        let discovery = VersionDiscovery {
            list: vec!["1.9.0".to_owned()],
            ..discovery
        };
        let known = BTreeSet::from(["1.9.0".to_owned(), "2.0.0".to_owned()]);
        let outcome = evaluate_with(
            &discovery,
            "acme/tool",
            &limits(),
            &DiscoveryRequest {
                known_versions: Some(&known),
                validator: None,
                paginate: false,
            },
        )
        .await;
        assert_eq!(outcome.source_error, None);
        // 2.1.0 is the new one; 1.9.0 comes from the recipe, not the cut page.
        assert_eq!(outcome.versions, ["2.1.0", "1.9.0"]);
    }

    /// Tag listings are ordered by name or commit date, so a known tag partway
    /// down says nothing about the rest: read the whole page and let the merge
    /// dedupe.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tag_source_is_never_cut_at_a_known_version() {
        let source = MockSource::start(BTreeMap::from([(
            "/api/v4/projects/acme%2Ftool/repository/tags".to_owned(),
            MockRoute::json(&serde_json::json!([
                {"name": "v1.9.0"},
                {"name": "v2.1.0"},
                {"name": "v2.0.0"}
            ])),
        )]))
        .await;
        let discovery = VersionDiscovery {
            source: "gitlab_tags".to_owned(),
            url: format!("{}/acme/tool", source.base),
            ..VersionDiscovery::default()
        };
        let known = BTreeSet::from(["1.9.0".to_owned()]);
        let outcome = evaluate_with(
            &discovery,
            "acme/tool",
            &limits(),
            &DiscoveryRequest {
                known_versions: Some(&known),
                validator: None,
                paginate: false,
            },
        )
        .await;
        assert_eq!(outcome.source_error, None);
        assert_eq!(outcome.versions, ["2.1.0", "2.0.0", "1.9.0"]);
        assert!(
            outcome.complete,
            "an uncut page is complete whatever the request asked for"
        );
    }

    /// A source that can only be read whole has no cheap path to protect: an
    /// incremental request re-reads everything anyway, so the result is complete
    /// and its caller may reconcile against it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_whole_list_source_stays_complete_under_an_incremental_request() {
        let source = MockSource::start(BTreeMap::from([(
            "/versions.json".to_owned(),
            MockRoute::json(&serde_json::json!(["1.0.0", "1.1.0"])),
        )]))
        .await;
        let discovery = VersionDiscovery {
            source: "json".to_owned(),
            url: format!("{}/versions.json", source.base),
            ..VersionDiscovery::default()
        };
        let known = BTreeSet::from(["1.0.0".to_owned()]);
        let outcome = evaluate_with(
            &discovery,
            "acme/tool",
            &limits(),
            &DiscoveryRequest {
                known_versions: Some(&known),
                validator: None,
                paginate: false,
            },
        )
        .await;
        assert_eq!(outcome.source_error, None);
        assert!(outcome.complete);
        assert_eq!(outcome.versions, ["1.1.0", "1.0.0"]);
    }

    /// A full page is not the whole offering, however little of it survives the
    /// filters. A release train fills the page the recipe asked for, every entry
    /// is a prerelease the recipe drops, and the empty result must not read as
    /// "upstream publishes nothing" — reconciling against that would retire every
    /// version the picker offers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_page_is_incomplete_even_when_the_filters_empty_it() {
        let source = MockSource::start(BTreeMap::from([(
            "/api/v4/projects/acme%2Ftool/releases".to_owned(),
            MockRoute::json(&serde_json::json!([
                {"tag_name": "v3.0.0-rc3", "upcoming_release": true},
                {"tag_name": "v3.0.0-rc2", "upcoming_release": true},
                {"tag_name": "v3.0.0-rc1", "upcoming_release": true}
            ])),
        )]))
        .await;
        let discovery = VersionDiscovery {
            source: "gitlab_releases".to_owned(),
            url: format!("{}/acme/tool", source.base),
            // The recipe's limit is also the page size, so three entries fill it.
            filter: VersionFilter {
                limit: Some(3),
                ..VersionFilter::default()
            },
            ..VersionDiscovery::default()
        };
        let outcome = evaluate(&discovery, "acme/tool", &limits()).await;
        assert_eq!(outcome.source_error, None);
        assert!(outcome.versions.is_empty(), "every entry was a prerelease");
        assert!(
            !outcome.complete,
            "a full page proves nothing about what follows it"
        );
    }

    /// The cut is not what bounds a tag listing — tags are not newest-first, so
    /// they are never cut — but a full page of them is still only a page.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_page_of_tags_is_incomplete_though_it_was_never_cut() {
        let tags: Vec<serde_json::Value> = (0..100)
            .map(|n| serde_json::json!({"name": format!("v1.0.{n}")}))
            .collect();
        let source = MockSource::start(BTreeMap::from([(
            "/api/v4/projects/acme%2Ftool/repository/tags".to_owned(),
            MockRoute::json(&serde_json::json!(tags)),
        )]))
        .await;
        let discovery = VersionDiscovery {
            source: "gitlab_tags".to_owned(),
            url: format!("{}/acme/tool", source.base),
            ..VersionDiscovery::default()
        };
        let outcome = evaluate(&discovery, "acme/tool", &limits()).await;
        assert_eq!(outcome.source_error, None);
        assert_eq!(outcome.versions.len(), 100);
        assert!(
            !outcome.complete,
            "the page filled, so a next page may hold versions this fetch never saw"
        );
    }

    /// A GitLab releases source serving `pages` of tag names, each page keyed by the
    /// query a walk would send for it. A page shorter than 100 ends the listing.
    async fn paged_releases_source(pages: &[Vec<String>]) -> (MockSource, VersionDiscovery) {
        let path = "/api/v4/projects/acme%2Ftool/releases";
        let routes: BTreeMap<String, MockRoute> = pages
            .iter()
            .enumerate()
            .map(|(idx, names)| {
                let body: Vec<serde_json::Value> = names
                    .iter()
                    .map(|name| serde_json::json!({"tag_name": name}))
                    .collect();
                let key = if idx == 0 {
                    format!("{path}?per_page=100")
                } else {
                    format!("{path}?per_page=100&page={}", idx + 1)
                };
                (key, MockRoute::json(&serde_json::json!(body)))
            })
            .collect();
        let source = MockSource::start(routes).await;
        let discovery = VersionDiscovery {
            source: "gitlab_releases".to_owned(),
            url: format!("{}/acme/tool", source.base),
            ..VersionDiscovery::default()
        };
        (source, discovery)
    }

    /// A hundred versions on one line, newest last so the pages read like a real
    /// listing: `page` 1 holds the newest hundred.
    fn version_page(major: u32, count: usize) -> Vec<String> {
        (0..count)
            .map(|n| format!("{major}.0.{}", count - n))
            .collect()
    }

    /// A reconcile retires whatever its answer omits, so it has to hold the whole
    /// answer: it walks past the first page until the listing underfills. A
    /// version that only appears on page two is therefore in the result, and the
    /// fetch is complete — which is what lets the caller demote at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reconcile_walks_past_the_first_page() {
        let (source, discovery) =
            paged_releases_source(&[version_page(2, 100), vec!["1.9.0".to_owned()]]).await;
        let limits = DiscoveryLimits {
            // Above the two pages, so the walk ends at the listing rather than the cap.
            max_versions: 500,
            ..limits()
        };
        let outcome = evaluate_with(
            &discovery,
            "acme/tool",
            &limits,
            &DiscoveryRequest {
                known_versions: None,
                validator: None,
                paginate: true,
            },
        )
        .await;
        assert_eq!(outcome.source_error, None);
        assert_eq!(outcome.versions.len(), 101);
        assert!(
            outcome.versions.contains(&"1.9.0".to_owned()),
            "the version only page two knows about is in the answer"
        );
        assert!(outcome.complete, "the walk reached the end of the listing");
        let paths: Vec<String> = source.requests().into_iter().map(|(uri, _)| uri).collect();
        assert!(
            paths.iter().any(|uri| uri.contains("&page=2")),
            "page two must have been read: {paths:?}"
        );
    }

    /// The daily sweep does not pay for that walk. It reads its one conditional
    /// page, never asks for a second, and reports the fetch as incomplete — so what
    /// it commits merges rather than retiring anything it simply did not read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sweep_stays_on_the_first_page() {
        let (source, discovery) =
            paged_releases_source(&[version_page(2, 100), vec!["1.9.0".to_owned()]]).await;
        let known = BTreeSet::from(["0.0.1".to_owned()]);
        let outcome = evaluate_with(
            &discovery,
            "acme/tool",
            &limits(),
            &DiscoveryRequest {
                known_versions: Some(&known),
                validator: None,
                paginate: false,
            },
        )
        .await;
        assert_eq!(outcome.source_error, None);
        assert!(
            !outcome.versions.contains(&"1.9.0".to_owned()),
            "page two is not the sweep's business"
        );
        assert!(!outcome.complete, "one full page is not the whole offering");
        let paths: Vec<String> = source.requests().into_iter().map(|(uri, _)| uri).collect();
        assert_eq!(paths.len(), 1, "one page, one request: {paths:?}");
        assert!(!paths[0].contains("&page="), "{paths:?}");
    }

    /// The walk also stops once it holds as many versions as the caller could
    /// retain: everything past that is beyond the cap anyway. It still counts as
    /// complete, and the pages beyond it are never asked for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_walk_stops_at_the_retained_version_cap() {
        let (source, discovery) = paged_releases_source(&[
            version_page(3, 100),
            version_page(2, 100),
            vec!["1.9.0".to_owned()],
        ])
        .await;
        let limits = DiscoveryLimits {
            max_versions: 150,
            ..limits()
        };
        let outcome = evaluate_with(
            &discovery,
            "acme/tool",
            &limits,
            &DiscoveryRequest {
                known_versions: None,
                validator: None,
                paginate: true,
            },
        )
        .await;
        assert_eq!(outcome.source_error, None);
        assert_eq!(
            outcome.versions.len(),
            150,
            "capped at what may be retained"
        );
        assert!(outcome.complete);
        let paths: Vec<String> = source.requests().into_iter().map(|(uri, _)| uri).collect();
        assert!(paths.iter().any(|uri| uri.contains("&page=2")), "{paths:?}");
        assert!(
            !paths.iter().any(|uri| uri.contains("&page=3")),
            "the cap was reached on page two, so there was nothing to ask page three for: {paths:?}"
        );
    }

    /// A recipe carrying only a static `list` fetches nothing, so every evaluation
    /// of it is complete by construction.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_static_list_recipe_is_complete() {
        let discovery = VersionDiscovery {
            list: vec!["1.0.0".to_owned(), "1.1.0".to_owned()],
            ..VersionDiscovery::default()
        };
        let known = BTreeSet::from(["1.0.0".to_owned()]);
        let outcome = evaluate_with(
            &discovery,
            "acme/tool",
            &limits(),
            &DiscoveryRequest {
                known_versions: Some(&known),
                validator: None,
                paginate: false,
            },
        )
        .await;
        assert!(outcome.complete);
        assert_eq!(outcome.versions, ["1.1.0", "1.0.0"]);
    }

    /// A failed evaluation proves nothing about what upstream publishes, so it is
    /// never complete — the one guarantee that keeps a broken source from
    /// demoting a repository's versions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_evaluation_is_never_complete() {
        let discovery = VersionDiscovery {
            source: "not-a-source".to_owned(),
            ..VersionDiscovery::default()
        };
        let outcome = evaluate(&discovery, "acme/tool", &limits()).await;
        assert!(outcome.source_error.is_some());
        assert!(!outcome.complete);
    }

    async fn releases_source() -> (MockSource, VersionDiscovery) {
        let source = MockSource::start(BTreeMap::from([(
            "/api/v4/projects/acme%2Ftool/releases".to_owned(),
            MockRoute::tagged(
                &serde_json::json!([
                    {"tag_name": "v2.1.0"},
                    {"tag_name": "v2.0.0"},
                    {"tag_name": "v1.9.0"}
                ]),
                "\"page-1\"",
            ),
        )]))
        .await;
        let discovery = VersionDiscovery {
            source: "gitlab_releases".to_owned(),
            url: format!("{}/acme/tool", source.base),
            ..VersionDiscovery::default()
        };
        (source, discovery)
    }

    /// Sorts newest first the way every caller of the comparator does.
    fn newest_first(versions: &[&str]) -> Vec<String> {
        let mut sorted: Vec<String> = versions.iter().map(|value| (*value).to_owned()).collect();
        sorted.sort_by(|left, right| compare_semver_desc(left, right));
        sorted
    }

    #[test]
    fn a_leading_v_does_not_decide_which_version_is_newer() {
        // A repository that restyled its tags mid-life: bare, then v-prefixed.
        assert_eq!(
            newest_first(&["0.4.0-rc88", "v0.5.0-rc1"]),
            ["v0.5.0-rc1", "0.4.0-rc88"],
            "0.5.0 is newer than 0.4.0 whichever side wears the v"
        );
        assert_eq!(newest_first(&["v1.9.0", "v1.10.0"]), ["v1.10.0", "v1.9.0"]);
        assert_eq!(newest_first(&["v2.0.0", "3.0.0"]), ["3.0.0", "v2.0.0"]);
    }

    #[test]
    fn a_numbered_prerelease_counts_up_numerically() {
        // Plain text order puts rc9 above rc88, since '9' > '8'.
        assert_eq!(
            newest_first(&["0.4.0-rc9", "0.4.0-rc88"]),
            ["0.4.0-rc88", "0.4.0-rc9"],
            "the 88th candidate is later than the 9th"
        );
        assert_eq!(
            newest_first(&["1.0.0-rc.9", "1.0.0-rc.88"]),
            ["1.0.0-rc.88", "1.0.0-rc.9"],
            "a dotted candidate number reads the same way"
        );
        assert_eq!(
            newest_first(&["1.0.0-beta2", "1.0.0-alpha9"]),
            ["1.0.0-beta2", "1.0.0-alpha9"],
            "the word still decides before the number does"
        );
    }

    #[test]
    fn a_release_still_outranks_its_own_prereleases() {
        assert_eq!(
            newest_first(&["1.0.0-rc88", "1.0.0", "0.9.0"]),
            ["1.0.0", "1.0.0-rc88", "0.9.0"]
        );
    }

    #[test]
    fn a_version_line_ends_on_a_component_boundary() {
        assert!(version_line_matches("1.5", "1.5"));
        assert!(version_line_matches("1.5.7", "1.5"));
        assert!(!version_line_matches("1.55.0", "1.5"));
        assert!(!version_line_matches("1.4.0", "1.5"));
    }

    #[test]
    fn a_version_line_tolerates_a_trailing_dot_or_a_v_prefix() {
        assert!(version_line_matches("1.5.7", "1.5."));
        assert!(version_line_matches("1.5.7", "v1.5"));
        // A source that really publishes v-prefixed versions still matches raw.
        assert!(version_line_matches("v1.5.7", "v1.5"));
    }

    #[test]
    fn a_request_that_normalizes_away_names_no_line() {
        for request in ["", "v", "."] {
            assert!(
                !version_line_matches("1.5.7", request),
                "{request:?} must not match"
            );
        }
    }

    #[test]
    fn only_a_partial_numeric_request_reads_as_a_line() {
        for request in ["1", "1.5", "1.5.", "v1.5", "2026.08"] {
            assert!(is_version_line(request), "{request:?} names a line");
        }
        // A version of its own — including one nothing publishes yet, which is why the
        // distinction exists at all.
        for request in ["1.5.7", "1.5.7-rc1", "9.9.9", "stable", "1.x", "", "v"] {
            assert!(!is_version_line(request), "{request:?} names a version");
        }
    }

    /// "Newest" means whatever the caller's order says it means: the helper takes
    /// the first match it is handed rather than re-ranking, so a recipe's own
    /// `sort` survives resolution.
    #[test]
    fn the_callers_order_decides_which_match_is_newest() {
        let pipeline_order = ["2.0.0", "1.5.10", "1.5.9", "1.5.2", "1.4.0"];
        assert_eq!(
            newest_on_version_line(pipeline_order.iter().copied(), "1.5"),
            Some("1.5.10")
        );
        assert_eq!(
            newest_on_version_line(pipeline_order.iter().copied(), "3"),
            None,
            "an empty line has no newest version"
        );
        // A `sort: string` recipe ranks 1.9 above 1.10, and that is the recipe's
        // answer for the `1` line — semver ordering must not overrule it here.
        let string_order = ["1.9", "1.10", "1.1"];
        assert_eq!(
            newest_on_version_line(string_order.iter().copied(), "1"),
            Some("1.9")
        );
    }

    /// An exact version means itself, wherever it sits: a longer version on the
    /// same line does not shadow it, and neither does a stable one.
    #[test]
    fn an_exact_version_wins_over_the_line_it_sits_on() {
        let prereleases = ["1.5.8-rc1.2", "1.5.8-rc1"];
        assert_eq!(
            newest_on_version_line(prereleases.iter().copied(), "1.5.8-rc1"),
            Some("1.5.8-rc1")
        );
        let lines = ["2.1.0", "2"];
        assert_eq!(
            newest_on_version_line(lines.iter().copied(), "2"),
            Some("2"),
            "the version 2 is not the 2 line's newest member, it is 2 itself"
        );
    }

    /// A version line resolves to the newest release on it, not to the newest
    /// thing on it: a release candidate published against `1.5` does not become
    /// what `1.5` means.
    #[test]
    fn a_version_line_prefers_a_stable_release_over_a_prerelease() {
        let versions = ["1.5.8-rc1", "1.5.7", "1.5.6", "1.4.0"];
        assert_eq!(
            newest_on_version_line(versions.iter().copied(), "1.5"),
            Some("1.5.7")
        );
        // Naming the prerelease exactly still reaches it — it is on its own line.
        assert_eq!(
            newest_on_version_line(versions.iter().copied(), "1.5.8-rc1"),
            Some("1.5.8-rc1")
        );
    }

    /// Preference, not exclusion: a line that has only ever published prereleases
    /// resolves to the newest of them rather than to nothing at all.
    #[test]
    fn a_line_with_only_prereleases_resolves_to_the_newest_prerelease() {
        let versions = ["2.0.0-rc2", "2.0.0-rc1", "1.9.0"];
        assert_eq!(
            newest_on_version_line(versions.iter().copied(), "2"),
            Some("2.0.0-rc2")
        );
        assert_eq!(
            newest_on_version_line(versions.iter().copied(), "2.0"),
            Some("2.0.0-rc2")
        );
    }

    #[test]
    fn the_uncurated_filter_drops_curation_and_keeps_validity() {
        let filter = VersionFilter {
            prerelease: Some(true),
            pattern: Some(r"^\d".to_owned()),
            exclude: vec!["1.0.0".to_owned()],
            latest_per: Some("minor".to_owned()),
            limit: Some(5),
            sort: Some("numeric".to_owned()),
        };
        let uncurated = uncurated_filter(&filter);
        assert_eq!(uncurated.latest_per, None);
        assert_eq!(uncurated.limit, None);
        assert_eq!(uncurated.prerelease, Some(true));
        assert_eq!(uncurated.pattern, filter.pattern);
        assert_eq!(uncurated.exclude, filter.exclude);
        assert_eq!(uncurated.sort, filter.sort);
    }

    /// The caller's `max_versions` is curation too: an exact version below the
    /// newest hundred must still be reachable through `All`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_uncurated_scope_lifts_the_caller_cap() {
        let published = (0..150)
            .map(|patch| serde_json::json!({"tag_name": format!("v1.0.{patch}")}))
            .collect::<Vec<_>>();
        let source = MockSource::start(BTreeMap::from([(
            "/api/v4/projects/acme%2Ftool/releases".to_owned(),
            MockRoute::json(&serde_json::Value::Array(published)),
        )]))
        .await;
        let discovery = VersionDiscovery {
            source: "gitlab_releases".to_owned(),
            url: format!("{}/acme/tool", source.base),
            ..VersionDiscovery::default()
        };

        let curated = evaluate_scoped(
            &discovery,
            "acme/tool",
            &limits(),
            VersionScope::Curated,
            Reach::FirstPage,
        )
        .await;
        assert_eq!(curated.source_error, None);
        assert_eq!(curated.versions.len(), 100);
        assert!(!curated.versions.iter().any(|version| version == "1.0.0"));

        let all = evaluate_scoped(
            &discovery,
            "acme/tool",
            &limits(),
            VersionScope::All,
            Reach::FirstPage,
        )
        .await;
        assert_eq!(all.source_error, None);
        assert_eq!(all.versions.len(), 150);
        assert_eq!(all.versions.last().map(String::as_str), Some("1.0.0"));
    }

    /// `All` drops the recipe's curation stages while its pattern and exclusions
    /// still decide what counts as a version.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_uncurated_scope_keeps_the_recipe_validity_stages() {
        let (_source, discovery) = releases_source().await;
        let discovery = VersionDiscovery {
            filter: VersionFilter {
                latest_per: Some("major".to_owned()),
                limit: Some(1),
                exclude: vec!["1.9.0".to_owned()],
                ..VersionFilter::default()
            },
            ..discovery
        };

        let curated = evaluate_scoped(
            &discovery,
            "acme/tool",
            &limits(),
            VersionScope::Curated,
            Reach::FirstPage,
        )
        .await;
        assert_eq!(curated.versions, ["2.1.0"]);

        let all = evaluate_scoped(
            &discovery,
            "acme/tool",
            &limits(),
            VersionScope::All,
            Reach::FirstPage,
        )
        .await;
        assert_eq!(all.versions, ["2.1.0", "2.0.0"]);
    }

    #[test]
    fn merge_folds_candidates_into_the_stored_list() {
        let filter = VersionFilter {
            latest_per: Some("minor".to_owned()),
            ..VersionFilter::default()
        };
        let stored = vec!["1.2.0".to_owned(), "1.1.0".to_owned()];
        let merged = merge_versions(
            &stored,
            &["1.2.1".to_owned(), "1.1.0".to_owned()],
            &filter,
            &limits(),
        )
        .expect("merge");
        assert_eq!(merged, ["1.2.1", "1.1.0"]);
    }

    /// Merging must not re-extract: a capturing pattern no longer matches the
    /// versions it produced.
    #[test]
    fn merge_keeps_already_extracted_versions() {
        let filter = VersionFilter {
            pattern: Some(r"^v(?P<version>\d+\.\d+\.\d+)$".to_owned()),
            ..VersionFilter::default()
        };
        assert_eq!(
            merge_versions(
                &["1.5.7".to_owned()],
                &["1.6.0".to_owned()],
                &filter,
                &limits()
            )
            .expect("merge"),
            ["1.6.0", "1.5.7"]
        );
    }

    /// A typo must read as a broken recipe, not as an upstream with no releases.
    #[tokio::test]
    async fn an_unknown_source_is_reported_rather_than_read_as_empty() {
        let discovery = VersionDiscovery {
            source: "github_realeases".to_owned(),
            url: "https://github.com/acme/tool".to_owned(),
            list: vec!["1.0.0".to_owned()],
            ..VersionDiscovery::default()
        };
        let outcome = evaluate(&discovery, "acme/tool", &limits()).await;
        let error = outcome.source_error.expect("source error");
        assert!(error.contains("github_realeases"), "{error}");
        assert!(error.contains("github_releases"), "{error}");
        assert!(outcome.versions.is_empty());
    }

    /// Repository tags and a bare static `list` are both fetch-free and sound:
    /// the recipe's own versions come back with no error.
    #[tokio::test]
    async fn fetch_free_sources_still_yield_the_static_list() {
        for source in ["registry", ""] {
            let discovery = VersionDiscovery {
                source: source.to_owned(),
                list: vec!["3.46".to_owned(), "3.45".to_owned()],
                ..VersionDiscovery::default()
            };
            let outcome = evaluate(&discovery, "acme/tool", &limits()).await;
            assert_eq!(outcome.source_error, None, "source {source:?}");
            assert_eq!(outcome.versions, ["3.46", "3.45"], "source {source:?}");
        }
    }
}
