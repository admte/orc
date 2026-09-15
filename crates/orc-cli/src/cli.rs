use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use crate::app::has_chunked_suffix;
use crate::app::{
    AppConfig, DOWNLOAD_ARTIFACT_TYPE, ManifestDocument, OCI_IMAGE_INDEX, ParamSchema, Platform,
};
use crate::boot_hook;
use crate::cache::write_blob;
use crate::config::StoredConfig;
use crate::error::{CliError, Result};
use crate::github::GitHubPackageLister;
use crate::info::build_info_document;
use crate::lifecycle::{run_install_phase, run_uninstall_phase};
use crate::local_artifact_store::{
    CachedDescriptor, CachedMaterializedPackage, OCI_MANIFEST_MEDIA_TYPE,
    materialize_cached_package, read_manifest, read_ref, verify_cached_blob, write_manifest,
    write_ref,
};
use crate::output::{
    ListRow, OutputFormat, print_cached_refs, print_info, print_list, print_status, print_versions,
};
use crate::package::{PackageFormat, PackageOptions, PackagePlan, plan_push};
use crate::params::{ParsedParam, ParsedParamValue, durable_param_values, parse_app_params};
use crate::progress::{self, CliProgress};
use crate::pull::{
    FetchedManifest, MaterializedPackage, PullTarget, fetch_recipe, materialize_all_platforms,
    materialize_package, materialize_package_from, resolve_pull_target,
};
use crate::reference::{
    BUILTIN_DEFAULT_PREFIX, ResolvedPrefix, ResolvedReference, resolve_app_reference,
    resolve_prefix,
};
use crate::registry::{RegistryClient, digest_bytes};
use crate::resume;
use crate::state::{
    InstallRecord, list_install_records, materialized_app_dir, read_install_record,
    remove_install_record, write_install_record,
};
use crate::supervisor;
use crate::versions::{
    discover_versions, discovery_limits, github_token, read_manifest_summary, unique_platforms,
};
use orc_app::chunked::{DEFAULT_ZSTD_LEVEL, locate_and_verify_toc};
use orc_app::credential::StoredCredential;
use orc_app::discovery::{self, VersionScope};
use orc_app::lifecycle::{
    AppContext, AppEnv, ExitInfo, FORCED_STOPPED_TIMEOUT, StopHow, StopOutcome, StopReason,
    StopStatus, StoppedReason, managed_service_spec, run_stopped_phase, stop_sequence,
    write_app_env,
};
use orc_app::process::{AppProcess, LogLine, LogStream, spawn_piped_app};
use orc_app::progress::{ProgressEvent, ProgressKind, ProgressPhase, ProgressReporter};
use orc_app::reboot::{PhaseOutcome, PhaseReboot, RebootAction, RebootExecutor};
use orc_app::service::ServiceBackend;
use std::sync::Arc;
use tokio::io::AsyncBufReadExt as _;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "orc", version = env!("ORC_VERSION"), about = "Work with ORC app packages")]
pub struct Cli {
    #[arg(long, global = true)]
    insecure: bool,
    #[arg(long, global = true)]
    platform: Vec<String>,
    #[arg(long, global = true)]
    registry: Option<String>,
    #[arg(long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Login(LoginArgs),
    Logout(RegistryArg),
    #[command(alias = "ls")]
    List(ListArgs),
    Search(SearchArgs),
    #[command(alias = "vers")]
    Versions(VersionsArgs),
    Info(AppReadArgs),
    Install(InstallArgs),
    Start(StartArgs),
    Stop(AppArg),
    Uninstall(AppArg),
    Build(BuildArgs),
    Push(PushArgs),
    Pull(PullArgs),
    Clone(CloneArgs),
    Status(StatusArgs),
    Cache(CacheArgs),
    Config(ConfigArgs),
    /// Forward a local port to a service through the ORC access service.
    Forward(crate::forward::ForwardArgs),
    /// Serve a SOCKS5 proxy onto one project's services, resolving every name
    /// through the ORC access service instead of a local port per service.
    Proxy(crate::proxy::ProxyArgs),
    /// Internal plumbing: this binary, re-invoked by a service manager to become one
    /// app. Hidden, because nobody types it — a service definition does.
    #[command(name = "app-exec", hide = true)]
    AppExec(AppExecArgs),
    Version,
}

/// What the start shim needs to rebuild one app's environment. See
/// [`orc_app::lifecycle::exec_app`].
#[derive(Debug, Args)]
struct AppExecArgs {
    /// The app instance's work directory: where its config and persisted params live.
    #[arg(long, value_name = "PATH")]
    work_dir: PathBuf,
    /// The app's package name.
    #[arg(long, value_name = "NAME")]
    app: String,
    /// What the runtime calls this copy of the app.
    #[arg(long, value_name = "LABEL", default_value = "")]
    instance: String,
    /// The resolved upstream version, or `default`.
    #[arg(long, value_name = "VERSION", default_value = "default")]
    version: String,
}

#[derive(Debug, Args)]
struct LoginArgs {
    #[arg(short = 'u', long)]
    username: Option<String>,
    #[arg(long)]
    password_stdin: bool,
    /// Organization `orc forward` acts in by default against this server.
    #[arg(long, value_name = "CODE")]
    org: Option<String>,
    registry: Option<String>,
}

#[derive(Debug, Args)]
struct RegistryArg {
    registry: Option<String>,
}

#[derive(Debug, Args)]
struct ListArgs {
    filter: Option<String>,
    #[arg(short = 'q', long)]
    quiet: bool,
    #[arg(long = "format", value_enum, default_value_t)]
    output: OutputFormat,
}

#[derive(Debug, Args)]
struct SearchArgs {
    prefix: Option<String>,
    #[arg(short = 'q', long)]
    quiet: bool,
    #[arg(long = "format", value_enum, default_value_t)]
    output: OutputFormat,
}

#[derive(Debug, Args)]
struct AppReadArgs {
    app: String,
    #[arg(long = "format", value_enum, default_value_t)]
    output: OutputFormat,
}

#[derive(Debug, Args)]
struct VersionsArgs {
    app: String,
    #[arg(long = "format", value_enum, default_value_t)]
    output: OutputFormat,
    /// List the sources' own versions instead of the curated set: the recipe's line
    /// pruning and count limit are dropped (a forge source still answers one page
    /// at a time), while its other filters still apply.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct AppArg {
    app: String,
    /// End the app immediately: skip its stop command and the grace period, and cap the
    /// stopped hook. Applies to the stop an `uninstall` performs too. Always reported,
    /// because it is the destructive way to stop something.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct BuildArgs {
    path: Option<PathBuf>,
    /// Tag(s) to cache the build under. When omitted, the reference is derived from the
    /// `org.opencontainers.image.title`/`.version` annotations in artifact.yaml.
    #[arg(short = 't', long = "tag")]
    tags: Vec<String>,
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    /// Push the built artifact to the registry after caching (incompatible with --output).
    #[arg(long)]
    push: bool,
    /// Payload layer framing for files >= 8 MiB. `chunked-zstd` (the default, spec 146)
    /// caches single-blob chunked-zstd layers that dedup across versions against an
    /// `_orc`-capable registry; `plain` caches whole blobs that push to any registry.
    #[arg(long = "format", value_enum)]
    format: Option<PushFormat>,
    /// zstd level for compressed chunks (default 3).
    #[arg(long)]
    zstd_level: Option<i32>,
    /// Store every chunk as a raw (uncompressed) frame.
    #[arg(long)]
    no_compress: bool,
}

#[derive(Debug, Args)]
struct PushArgs {
    /// Legacy alias for `--format plain` (`--chunker none`). The removed `fastcdc`/`fixed`
    /// values are rejected by clap.
    #[arg(long, value_enum)]
    chunker: Option<PushChunker>,
    /// Payload layer framing for files >= 8 MiB. Default: `chunked-zstd` (spec 146) when
    /// the target registry advertises the `_orc` capability, else `plain`; download
    /// artifacts always default to `plain`, since their layers are served as the published
    /// files. `chunked-zstd` forces the chunked format; `plain` forces whole blobs (the only
    /// format external registries can dedup or non-orc clients can read).
    #[arg(long = "format", value_enum)]
    format: Option<PushFormat>,
    /// zstd level for compressed chunks (default 3).
    #[arg(long)]
    zstd_level: Option<i32>,
    /// Store every chunk as a raw (uncompressed) frame.
    #[arg(long)]
    no_compress: bool,
    reference: String,
    paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PushFormat {
    /// Single-blob chunked-zstd layers (spec 146) for files >= 8 MiB.
    #[value(name = "chunked-zstd")]
    ChunkedZstd,
    /// Whole-blob layers; registry-side CDC can deduplicate them. Works against any registry.
    Plain,
}

#[derive(Debug, Args)]
struct PullArgs {
    /// App reference, or a restore point:
    /// `<registry>/<org>/<project>/appdata-<pool>/<app>:<YYYYMMDD>T<HHMMSS>Z-s<slot>`.
    app: String,
    dir: Option<PathBuf>,
    /// Where to write. For an app this is the positional DIR by another name; for a
    /// restore point it is the directory the point's tree is materialized into
    /// (default: the point's own tag, in the current directory).
    #[arg(long, short = 'o', value_name = "DIR", conflicts_with = "archive")]
    output: Option<PathBuf>,
    /// Restore points only: write one `tar.zst` archive — byte for byte what the pool
    /// page's download link produces — instead of a directory tree.
    #[arg(long, value_name = "FILE")]
    archive: Option<PathBuf>,
    /// Recommended: file holding the key(s) for encrypted content, one 64-character hex
    /// key per line — every key a rotated pool holds, as the node page's Pull command
    /// lists them. Blank lines and `#` comments are ignored. Repeatable.
    #[arg(long = "key-file", value_name = "PATH")]
    key_file: Vec<PathBuf>,
    /// Key for encrypted content, as 64 hex characters — an App data key of the pool.
    /// An argument is visible in the process list to every user on this machine for as
    /// long as the pull runs, and lands in your shell history: prefer `--key-file`.
    /// Repeat it for every key a rotated pool holds. Also read from `ORC_ENCRYPTION_KEY`,
    /// which takes a comma-separated list; `--key-file` and `--key` win over it as a
    /// whole. Ignored for content that is not encrypted, and never printed.
    #[arg(long, value_name = "HEX")]
    key: Vec<String>,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct CloneArgs {
    app: String,
    dir: Option<PathBuf>,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct InstallArgs {
    #[arg(long)]
    force: bool,
    /// Continue an installation whose install phase asked for a reboot. The boot hook the
    /// CLI registers before restarting invokes exactly this; run by hand it finishes an
    /// install left pending by a machine that came back some other way.
    #[arg(long, conflicts_with_all = ["app", "force"])]
    resume: bool,
    #[arg(required_unless_present = "resume")]
    app: Option<String>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    params: Vec<String>,
}

#[derive(Debug, Args)]
struct StartArgs {
    #[arg(long)]
    detach: bool,
    app: String,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    params: Vec<String>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    app: Option<String>,
    #[arg(long = "format", value_enum, default_value_t)]
    output: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PushChunker {
    /// Whole-blob upload (the only supported mode); registry-side CDC can deduplicate it.
    None,
}

#[derive(Debug, Args)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Args)]
struct CacheArgs {
    #[command(subcommand)]
    command: CacheCommand,
}

#[derive(Debug, Subcommand)]
enum CacheCommand {
    Ls,
    Clean {
        #[arg(long)]
        unused: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Get { key: String },
    Set { key: String, value: String },
}

/// Runs the CLI with the supplied process arguments.
///
/// # Errors
///
/// Returns a [`CliError`] when argument parsing, configuration loading, registry access,
/// or command execution fails.
pub async fn run<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let raw: Vec<OsString> = args.into_iter().map(Into::into).collect();
    // Per-app dynamic help: `orc start|install <app> --help` lists the app's parameters,
    // which clap can't know statically. Intercept before clap parses the help flag.
    if let Some((command, app)) = app_help_request(&raw) {
        return print_app_help_for(&command, &app).await;
    }
    let cli = match Cli::try_parse_from(raw.iter()) {
        Ok(cli) => cli,
        Err(err) => {
            // clap reports --help / --version as "errors"; they are successful requests for
            // output. Print to stdout (err's Display already ends in a newline) and exit 0,
            // instead of routing them through stderr with a non-zero code and a doubled newline.
            use clap::error::ErrorKind;
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp
                    | ErrorKind::DisplayVersion
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) {
                print!("{err}");
                return Ok(());
            }
            return Err(CliError::Usage(err.to_string()));
        }
    };
    // Before the stored config is loaded: the start shim runs under a service manager,
    // where there is no operator, no home directory, and nothing to configure — only an
    // app to become.
    if let Command::AppExec(args) = &cli.command {
        return orc_app::lifecycle::exec_app(
            &args.work_dir,
            &args.app,
            &args.instance,
            &args.version,
        )
        .await;
    }
    let mut config = StoredConfig::load()?;
    let settings = CliSettings {
        insecure: cli.insecure,
        platform: cli.platform.clone(),
        registry: cli.registry.clone(),
        quiet: cli.quiet,
    };

    match cli.command {
        Command::Login(args) => login(args, &settings, &mut config).await,
        Command::Logout(args) => logout(&args, &mut config),
        Command::List(args) => list(&args, &settings),
        Command::Search(args) => search(args, &settings, &config).await,
        Command::Versions(args) => versions(args, &settings, &config).await,
        Command::Info(args) => info(args, &settings, &config).await,
        Command::Install(args) => install(args, &settings, &config).await,
        Command::Start(args) => start(args, &settings, &config).await,
        Command::Stop(args) => stop(&args, &settings, &config).await,
        Command::Uninstall(args) => uninstall(args, &settings, &config).await,
        Command::Build(args) => build(args, &settings, &config).await,
        Command::Push(args) => push(args, &settings, &config).await,
        Command::Pull(args) => pull(args, &settings, &config).await,
        Command::Clone(args) => clone(args, &settings, &config).await,
        Command::Status(args) => status(&args),
        Command::Cache(args) => cache_command(&args),
        Command::Config(args) => config_command(args, &mut config),
        Command::Forward(args) => crate::forward::forward(args, &config).await,
        Command::Proxy(args) => crate::proxy::proxy(args, &config).await,
        // Handled above, before the stored config is loaded.
        Command::AppExec(_) => Ok(()),
        Command::Version => {
            println!("{}", env!("ORC_VERSION"));
            Ok(())
        }
    }
}

struct CliSettings {
    insecure: bool,
    platform: Vec<String>,
    registry: Option<String>,
    quiet: bool,
}

/// Detects `orc start|install <app> ... --help`. Returns `(subcommand, app)` when the help
/// flag is present together with an app positional, so we can print per-app parameter help
/// instead of clap's static help. Returns `None` (clap handles it) otherwise.
fn app_help_request(raw: &[OsString]) -> Option<(String, String)> {
    let tokens: Vec<String> = raw
        .iter()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if !tokens.iter().any(|tok| tok == "-h" || tok == "--help") {
        return None;
    }
    let sub_index = tokens
        .iter()
        .position(|tok| tok == "start" || tok == "install")?;
    let command = tokens[sub_index].clone();
    let app = tokens[sub_index + 1..]
        .iter()
        .find(|tok| !tok.starts_with('-'))?
        .clone();
    Some((command, app))
}

/// Loads an app's parameter schema (local install first, else the registry) and prints
/// per-app `--help`.
async fn print_app_help_for(command: &str, app: &str) -> Result<()> {
    let config = StoredConfig::load()?;
    let resolved = resolve_app_reference(app, config.default_prefix(), None)?;
    let app_name = app_name_from_repository(&resolved.repository)?;
    let version = resolved.tag.clone();

    let mut app_config = None;
    if let Some(record) = read_install_record(&app_name, &version)? {
        let materialized = if record.materialized_dir.is_empty() {
            materialized_app_dir(&app_name, &version)?
        } else {
            PathBuf::from(&record.materialized_dir)
        };
        app_config = read_materialized_app_config(&materialized).ok();
    }
    if app_config.is_none()
        && let Ok(registry) = registry_client(&resolved.registry, &config, false)
        && let Ok(Some(summary)) =
            read_manifest_summary(&registry, &resolved.repository, &resolved.tag).await
    {
        app_config = summary.config;
    }

    if let Some(cfg) = app_config {
        crate::output::print_app_help(command, app, &crate::info::app_params(&cfg));
    } else {
        println!("Usage: orc {command} {app} [PARAMS]...");
        eprintln!(
            "Could not load parameters for {app} (not installed locally and registry fetch failed). Try `orc login` then `orc install {app}`."
        );
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImageIndexDocument<'a> {
    schema_version: u8,
    media_type: &'a str,
    manifests: Vec<IndexDescriptor>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IndexDescriptor {
    media_type: String,
    digest: String,
    size: u64,
    platform: Platform,
}

async fn login(args: LoginArgs, settings: &CliSettings, config: &mut StoredConfig) -> Result<()> {
    let prefix = resolve_prefix(args.registry.as_deref(), None)?;
    let org = args.org.clone();
    let registry = prefix.registry.clone();
    let (username, token) = if args.password_stdin {
        let mut token = String::new();
        std::io::stdin()
            .read_to_string(&mut token)
            .map_err(|err| CliError::Operational(format!("read password from stdin: {err}")))?;
        let username = args.username.unwrap_or_else(|| "token".to_owned());
        (username, token.trim_end_matches(['\r', '\n']).to_owned())
    } else if crate::terminal::stdin_is_terminal() {
        // docker-style interactive login. The username is plumbed to Basic
        // auth at registry token endpoints; ORC registries ignore it and take
        // the identity from the API key alone, so the `token` default works
        // there, while Docker-Hub-style registries need a real account name.
        let username = match args.username {
            Some(username) => username,
            None => crate::terminal::prompt_line("Username (token): ", "token")?,
        };
        let token = crate::terminal::prompt_password("Password: ")?;
        (username, token)
    } else {
        return Err(CliError::Usage(
            "login requires --password-stdin when stdin is not a terminal".to_owned(),
        ));
    };
    if token.is_empty() {
        return Err(CliError::Usage("password cannot be empty".to_owned()));
    }
    if username.is_empty() {
        return Err(CliError::Usage("username cannot be empty".to_owned()));
    }
    let credential = StoredCredential { username, token };
    // Verify before storing so a bad credential fails here, not on the first
    // real command.
    RegistryClient::new(&registry, Some(&credential), settings.insecure)?
        .ping()
        .await?;
    config.credentials.insert(registry.clone(), credential);
    if let Some(org) = org {
        config.default_org = Some(org);
    }
    if config.default_registry.is_none()
        && let Some(default_prefix) = login_default_prefix(&prefix)
    {
        config.default_registry = Some(default_prefix);
    }
    config.save()?;
    eprintln!("Login Succeeded ({})", prefix.value);
    Ok(())
}

/// Prefix to remember as the default after a successful login. A login that
/// targets the builtin default stores nothing, so the config stays empty
/// instead of pinning a value that is already in effect.
fn login_default_prefix(prefix: &ResolvedPrefix) -> Option<String> {
    (prefix.value != BUILTIN_DEFAULT_PREFIX).then(|| prefix.value.clone())
}

fn logout(args: &RegistryArg, config: &mut StoredConfig) -> Result<()> {
    let prefix = resolve_prefix(args.registry.as_deref(), config.default_registry.as_deref())?;
    let removed = config.credentials.remove(&prefix.registry).is_some();
    config.save()?;
    if removed {
        eprintln!("Removed credentials ({})", prefix.registry);
    } else {
        eprintln!("No credentials stored ({})", prefix.registry);
    }
    Ok(())
}

fn list(args: &ListArgs, settings: &CliSettings) -> Result<()> {
    let quiet = settings.quiet || args.quiet;
    let registry_filter = settings.registry.as_deref().map(str::trim);
    let mut rows = crate::local_artifact_store::list_refs()?;
    if let Some(filter) = args.filter.as_deref().map(str::trim)
        && !filter.is_empty()
    {
        rows.retain(|row| cached_ref_matches(row, filter));
    }
    if let Some(filter) = registry_filter
        && !filter.is_empty()
    {
        let filter = filter.trim_end_matches('/');
        rows.retain(|row| cached_ref_matches_registry(row, filter));
    }
    print_cached_refs(&rows, args.output, quiet)
}

fn cached_ref_matches(row: &crate::local_artifact_store::CachedRefSummary, filter: &str) -> bool {
    let app = row.repository.rsplit('/').next().unwrap_or_default();
    [
        row.reference.as_str(),
        row.repository.as_str(),
        app,
        row.tag.as_str(),
    ]
    .iter()
    .any(|value| value.contains(filter))
}

fn cached_ref_matches_registry(
    row: &crate::local_artifact_store::CachedRefSummary,
    filter: &str,
) -> bool {
    row.reference == filter
        || row.reference.starts_with(&format!("{filter}/"))
        || row.registry == filter
}

async fn search(args: SearchArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let quiet = settings.quiet || args.quiet;
    let prefix = resolve_prefix(
        args.prefix.as_deref(),
        settings
            .registry
            .as_deref()
            .or(config.default_registry.as_deref()),
    )?;
    if !quiet {
        eprintln!("Resolved prefix: {}", prefix.value);
    }
    let names = list_names(&prefix, config, settings.insecure).await?;
    if quiet {
        let rows = names
            .into_iter()
            .map(|name| ListRow {
                name,
                default_version: String::new(),
                description: String::new(),
                reference: String::new(),
            })
            .collect::<Vec<_>>();
        return print_list(&rows, args.output, true);
    }

    let registry = registry_client(&prefix.registry, config, settings.insecure)?;
    let mut rows = Vec::new();
    for name in names {
        let repository = join_repo(&prefix.namespace, &name);
        let Some(summary) = read_manifest_summary(&registry, &repository, "default").await? else {
            continue;
        };
        let config = summary.config.unwrap_or_default();
        rows.push(ListRow {
            name,
            default_version: config.default_version.unwrap_or_default(),
            description: summary.description,
            reference: format!("{}/{}:default", prefix.registry, repository),
        });
    }
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    print_list(&rows, args.output, false)
}

async fn list_names(
    prefix: &ResolvedPrefix,
    config: &StoredConfig,
    insecure: bool,
) -> Result<Vec<String>> {
    let mut names = if prefix.registry == "ghcr.io" {
        GitHubPackageLister::new(config.credential_for("ghcr.io"))?
            .list_container_packages(&prefix.namespace)
            .await?
    } else {
        registry_client(&prefix.registry, config, insecure)?
            .list_catalog(&prefix.namespace)
            .await?
    };
    names.sort();
    Ok(names)
}

async fn versions(args: VersionsArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let resolved = resolve_app_reference(
        &args.app,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    if !settings.quiet {
        eprintln!("Resolved reference: {}", resolved.full);
    }
    let registry = registry_client(&resolved.registry, config, settings.insecure)?;
    let scope = if args.all {
        VersionScope::All
    } else {
        VersionScope::Curated
    };
    let mut rows =
        discover_versions(&registry, github_token(config), &resolved.repository, scope).await?;
    for row in &mut rows {
        row.platforms = unique_platforms(std::mem::take(&mut row.platforms));
    }
    print_versions(&rows, args.output)
}

async fn info(args: AppReadArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let resolved = resolve_app_reference(
        &args.app,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    if !settings.quiet {
        eprintln!("Resolved reference: {}", resolved.full);
    }
    let registry = registry_client(&resolved.registry, config, settings.insecure)?;
    let Some(summary) =
        read_manifest_summary(&registry, &resolved.repository, &resolved.tag).await?
    else {
        return Err(CliError::NotFound(format!(
            "{} is not an ORC app artifact",
            resolved.full
        )));
    };
    let info = build_info_document(
        resolved.full,
        summary.digest,
        summary.description,
        unique_platforms(summary.platforms),
        summary.config.as_ref(),
    );
    print_info(&info, args.output)
}

/// `orc build` has no registry context, so it defaults to caching the chunked-zstd format
/// (spec 146 §CLI Surface). `--format plain` caches whole blobs that push anywhere; a
/// chunked-built artifact pushed to a non-`_orc` registry fails with a rebuild hint.
fn build_package_options(args: &BuildArgs) -> PackageOptions {
    let format = match args.format {
        Some(PushFormat::Plain) => PackageFormat::Plain,
        Some(PushFormat::ChunkedZstd) | None => PackageFormat::ChunkedZstd,
    };
    PackageOptions {
        format,
        explicit_format: args.format.is_some(),
        zstd_level: args.zstd_level.unwrap_or(DEFAULT_ZSTD_LEVEL),
        no_compress: args.no_compress,
    }
}

async fn build(args: BuildArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let options = build_package_options(&args);
    let root = args.path.unwrap_or_else(|| PathBuf::from("."));
    let platforms = settings
        .platform
        .iter()
        .map(String::as_str)
        .map(parse_platform_label)
        .collect::<Result<Vec<_>>>()?;
    if args.push && args.output.is_some() {
        return Err(CliError::Usage(
            "--push cannot be combined with --output".to_owned(),
        ));
    }
    let reporter = progress::make_reporter(settings.quiet);
    let artifact = crate::build_recipe::build_artifact(
        &root,
        &platforms,
        options,
        progress::as_dyn(reporter.as_ref()),
    )
    .await?;

    // Use explicit --tag values, or fall back to the reference derived from the
    // artifact.yaml annotations (org.opencontainers.image.title/.version).
    let tags: Vec<String> = if args.tags.is_empty() {
        artifact.default_reference.clone().into_iter().collect()
    } else {
        args.tags.clone()
    };
    if tags.is_empty() {
        return Err(CliError::Usage(
            "provide --tag or set org.opencontainers.image.title in artifact.yaml".to_owned(),
        ));
    }

    if let Some(output) = args.output {
        crate::oci_layout::write_layout(&output, &artifact, &tags)?;
        println!("{}", artifact.root.digest);
        if !settings.quiet {
            eprintln!("Wrote OCI layout to {}", output.display());
        }
        return Ok(());
    }

    for blob in &artifact.blobs {
        write_blob(&blob.digest, &blob.body)?;
    }
    for manifest in &artifact.manifests {
        write_manifest(&manifest.descriptor.media_type, &manifest.body)?;
    }
    // Cache the recipe referrer (blobs + manifest) and record it on every ref so
    // `orc push` re-publishes it and maintains the referrers index.
    let referrers: Vec<CachedDescriptor> = if let Some(recipe) = &artifact.recipe {
        for blob in &recipe.blobs {
            write_blob(&blob.digest, &blob.body)?;
        }
        write_manifest(
            &recipe.manifest.descriptor.media_type,
            &recipe.manifest.body,
        )?;
        vec![recipe.manifest.descriptor.clone()]
    } else {
        Vec::new()
    };
    let mut resolved_refs = Vec::new();
    let mut refs = 0usize;
    for tag in &tags {
        let resolved =
            resolve_push_reference(tag, config.default_prefix(), settings.registry.as_deref())?;
        for tag in &resolved.tags {
            let reference = format!("{}/{}:{tag}", resolved.registry, resolved.repository);
            write_ref(
                &reference,
                &resolved.registry,
                &resolved.repository,
                tag,
                artifact.root.clone(),
                referrers.clone(),
            )?;
            refs += 1;
        }
        resolved_refs.push(resolved);
    }
    println!("{}", artifact.root.digest);
    if !settings.quiet {
        eprintln!(
            "Cached {} blobs, {} manifests, {} refs",
            artifact.blobs.len(),
            artifact.manifests.len(),
            refs
        );
    }

    if args.push {
        for resolved in &resolved_refs {
            push_cached_ref(resolved, settings, config).await?;
        }
    }
    Ok(())
}

async fn push(args: PushArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    if args.paths.is_empty() {
        return push_cached(args, settings, config).await;
    }
    let platform = single_platform(settings)?
        .map(parse_platform_label)
        .transpose()?;
    let resolved = resolve_push_reference(
        &args.reference,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    if !settings.quiet {
        eprintln!("Resolved reference: {}", resolved.full);
    }
    let root = std::env::current_dir()
        .map_err(|err| CliError::Operational(format!("read current directory: {err}")))?;
    let reporter = progress::make_reporter(settings.quiet);
    let registry = with_progress(
        registry_client(&resolved.registry, config, settings.insecure)?,
        reporter.as_ref(),
    );

    // The target is known here, so pick the layer format directly: chunked-zstd when the
    // registry advertises the `_orc` capability (or the operator forces it), else plain.
    // The packager gets the last word on an unforced choice, so report after planning.
    let capable = registry.chunked_capability().await?.is_some();
    let plan = plan_push(&root, &args.paths, push_package_options(&args, capable))?;
    if !settings.quiet {
        report_chosen_format(&plan, capable);
    }

    let stats = upload_package_blobs(&registry, &resolved.repository, &plan).await?;
    let published_digest = publish_package(&registry, &resolved, &plan, platform).await?;
    println!("{published_digest}");
    if !settings.quiet {
        eprintln!(
            "Uploaded {} blobs, skipped {}, pushed {} tags",
            stats.uploaded,
            stats.skipped,
            resolved.tags.len()
        );
    }
    Ok(())
}

async fn push_cached(args: PushArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let resolved = resolve_push_reference(
        &args.reference,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    push_cached_ref(&resolved, settings, config).await
}

/// Packaging knobs for a direct `orc push <ref> <paths>` (which knows the target registry at
/// packaging time). An explicit `--format`/`--chunker none` wins and is passed through
/// untouched; otherwise the default is chunked-zstd against an `_orc`-capable registry and
/// plain against everything else (spec 146 §CLI Surface), and the packager may still drop
/// that default to plain once it knows the artifact type.
fn push_package_options(args: &PushArgs, capable: bool) -> PackageOptions {
    PackageOptions {
        format: resolve_push_format(args.format, args.chunker, capable),
        explicit_format: args.format.is_some() || args.chunker.is_some(),
        zstd_level: args.zstd_level.unwrap_or(DEFAULT_ZSTD_LEVEL),
        no_compress: args.no_compress,
    }
}

fn resolve_push_format(
    format: Option<PushFormat>,
    chunker: Option<PushChunker>,
    capable: bool,
) -> PackageFormat {
    match (format, chunker) {
        (Some(PushFormat::Plain), _) | (None, Some(PushChunker::None)) => PackageFormat::Plain,
        (Some(PushFormat::ChunkedZstd), _) => PackageFormat::ChunkedZstd,
        (None, None) => {
            if capable {
                PackageFormat::ChunkedZstd
            } else {
                PackageFormat::Plain
            }
        }
    }
}

fn report_chosen_format(plan: &PackagePlan, capable: bool) {
    match plan.format {
        PackageFormat::ChunkedZstd if capable => {
            eprintln!("Format: chunked-zstd (registry advertises the _orc capability)");
        }
        PackageFormat::ChunkedZstd => {
            eprintln!(
                "Format: chunked-zstd (forced; registry lacks the _orc capability, \
                 large layers upload monolithically without wire dedup)"
            );
        }
        PackageFormat::Plain if plan.artifact_type == DOWNLOAD_ARTIFACT_TYPE => {
            eprintln!("Format: plain (download layers are stored byte-identically)");
        }
        PackageFormat::Plain if capable => {
            eprintln!("Format: plain (forced whole blobs)");
        }
        PackageFormat::Plain => {
            eprintln!("Format: plain (registry is not _orc-capable)");
        }
    }
}

/// Uploads a locally-cached build to the registry for an already-resolved reference.
/// Shared by `orc push <ref>` and `orc build --push`.
async fn push_cached_ref(
    resolved: &ResolvedPushReference,
    settings: &CliSettings,
    config: &StoredConfig,
) -> Result<()> {
    if !settings.quiet {
        eprintln!("Resolved reference: {}", resolved.full);
    }
    let source_tag = resolved
        .tags
        .first()
        .ok_or_else(|| CliError::Usage("push reference must include a tag".to_owned()))?;
    let source_ref = format!("{}/{}:{source_tag}", resolved.registry, resolved.repository);
    let local_ref = read_ref(&source_ref)?;
    let reporter = progress::make_reporter(settings.quiet);
    let registry = with_progress(
        registry_client(&resolved.registry, config, settings.insecure)?,
        reporter.as_ref(),
    );
    let mut stats = UploadStats {
        uploaded: 0,
        skipped: 0,
    };
    // A cached artifact's format was fixed at build time. If it carries chunked-zstd layers
    // the target must be `_orc`-capable to negotiate them; otherwise the push fails with a
    // rebuild hint (see `upload_layer`).
    let capable = registry.chunked_capability().await?.is_some();
    upload_cached_graph(
        &registry,
        &resolved.repository,
        &local_ref.target,
        capable,
        &mut stats,
    )
    .await?;
    for tag in &resolved.tags {
        put_cached_manifest(&registry, &resolved.repository, tag, &local_ref.target).await?;
    }
    for referrer in &local_ref.referrers {
        push_referrer(
            &registry,
            &resolved.repository,
            &local_ref.target,
            referrer,
            &mut stats,
        )
        .await?;
    }
    println!("{}", local_ref.target.digest);
    if !settings.quiet {
        eprintln!(
            "Uploaded {} blobs, skipped {}, pushed {} tags",
            stats.uploaded,
            stats.skipped,
            resolved.tags.len()
        );
    }
    Ok(())
}

async fn upload_cached_graph(
    registry: &RegistryClient,
    repository: &str,
    descriptor: &CachedDescriptor,
    capable: bool,
    stats: &mut UploadStats,
) -> Result<()> {
    let body = read_manifest(&descriptor.digest)?;
    let document = ManifestDocument::parse(&body, &descriptor.media_type)
        .map_err(|err| CliError::Operational(format!("decode cached manifest: {err}")))?;
    match document {
        ManifestDocument::Manifest(manifest) => {
            upload_cached_blob(registry, repository, &manifest.config.digest, stats).await?;
            for layer in &manifest.layers {
                // A cached chunked-zstd layer needs an `_orc`-capable target: its format was
                // fixed at build time, so a non-capable registry (external, or non-orc
                // consumers) is a hard error with a rebuild hint rather than a silent
                // monolithic fallback that no non-orc client could read.
                if has_chunked_suffix(&layer.media_type) && !capable {
                    return Err(CliError::Usage(format!(
                        "cached layer {} is a chunked-zstd artifact but the target registry \
                         does not advertise the _orc chunked-upload capability; rebuild with \
                         `--format plain` to push whole blobs to this registry",
                        layer.digest
                    )));
                }
                let body = verify_cached_blob(&layer.digest)?;
                upload_layer(
                    registry,
                    repository,
                    &layer.media_type,
                    &layer.digest,
                    body,
                    &layer.annotations,
                    stats,
                )
                .await?;
            }
            put_cached_manifest(registry, repository, &descriptor.digest, descriptor).await?;
        }
        ManifestDocument::Index(index) => {
            for child in index.manifests {
                let child_descriptor = CachedDescriptor {
                    media_type: child.media_type,
                    digest: child.digest,
                    size: child.size.try_into().map_err(|_| {
                        CliError::Operational("cached manifest has invalid size".to_owned())
                    })?,
                };
                Box::pin(upload_cached_graph(
                    registry,
                    repository,
                    &child_descriptor,
                    capable,
                    stats,
                ))
                .await?;
            }
            put_cached_manifest(registry, repository, &descriptor.digest, descriptor).await?;
        }
    }
    Ok(())
}

async fn upload_cached_blob(
    registry: &RegistryClient,
    repository: &str,
    digest: &str,
    stats: &mut UploadStats,
) -> Result<()> {
    let body = verify_cached_blob(digest)?;
    ensure_planned_blob(registry, repository, digest, body, stats).await
}

/// Uploads one payload layer: a chunked-zstd layer (media type ends with `+zstd-chunked`)
/// via the negotiated `_orc` path, or a whole blob otherwise. The negotiated path falls back
/// to a monolithic PUT of the same stream bytes against a non-capable registry — an orc
/// consumer still reads it, just without wire dedup (the direct-push operator override). The
/// hard non-capable error lives on the cached-push path, where the format was fixed at build
/// time (see `upload_cached_graph`).
async fn upload_layer(
    registry: &RegistryClient,
    repository: &str,
    media_type: &str,
    digest: &str,
    body: Vec<u8>,
    annotations: &std::collections::BTreeMap<String, String>,
    stats: &mut UploadStats,
) -> Result<()> {
    if has_chunked_suffix(media_type) {
        let verified = locate_and_verify_toc(&body, annotations)?;
        registry
            .push_chunked_layer(repository, media_type, &body, &verified.toc)
            .await?;
        stats.uploaded += 1;
        return Ok(());
    }
    ensure_planned_blob(registry, repository, digest, body, stats).await
}

async fn put_cached_manifest(
    registry: &RegistryClient,
    repository: &str,
    reference: &str,
    descriptor: &CachedDescriptor,
) -> Result<String> {
    let body = read_manifest(&descriptor.digest)?;
    let digest = registry
        .put_manifest(repository, reference, &descriptor.media_type, body)
        .await?;
    verify_manifest_digest(&digest, &descriptor.digest, "cached manifest")?;
    Ok(digest)
}

/// Pushes a cached referrer manifest (e.g. the recipe): uploads its blobs, PUTs
/// the subject-bearing manifest, then maintains the referrers tag-schema fallback
/// when the registry does not natively index the subject (no `OCI-Subject`).
async fn push_referrer(
    registry: &RegistryClient,
    repository: &str,
    subject: &CachedDescriptor,
    referrer: &CachedDescriptor,
    stats: &mut UploadStats,
) -> Result<()> {
    let body = read_manifest(&referrer.digest)?;
    let document = ManifestDocument::parse(&body, &referrer.media_type)
        .map_err(|err| CliError::Operational(format!("decode cached referrer: {err}")))?;
    if let ManifestDocument::Manifest(manifest) = &document {
        upload_cached_blob(registry, repository, &manifest.config.digest, stats).await?;
        for layer in &manifest.layers {
            upload_cached_blob(registry, repository, &layer.digest, stats).await?;
        }
    }
    let response = registry
        .put_manifest_with_response(repository, &referrer.digest, &referrer.media_type, body)
        .await?;
    verify_manifest_digest(&response.digest, &referrer.digest, "cached referrer")?;
    if response.oci_subject.is_none() {
        registry
            .update_referrers_fallback(
                repository,
                &subject.digest,
                &crate::registry::ReferrerDescriptor {
                    media_type: referrer.media_type.clone(),
                    digest: referrer.digest.clone(),
                    size: i64::try_from(referrer.size).unwrap_or(i64::MAX),
                    artifact_type: Some(crate::app::RECIPE_ARTIFACT_TYPE.to_owned()),
                    annotations: std::collections::BTreeMap::new(),
                },
            )
            .await?;
    }
    Ok(())
}

struct UploadStats {
    uploaded: usize,
    skipped: usize,
}

async fn upload_package_blobs(
    registry: &RegistryClient,
    repository: &str,
    plan: &PackagePlan,
) -> Result<UploadStats> {
    let mut stats = UploadStats {
        uploaded: 0,
        skipped: 0,
    };
    let config_digest = digest_bytes(&plan.config_bytes);
    ensure_planned_blob(
        registry,
        repository,
        &config_digest,
        plan.config_bytes.clone(),
        &mut stats,
    )
    .await?;
    for payload in &plan.payloads {
        upload_layer(
            registry,
            repository,
            &payload.media_type,
            &payload.digest,
            payload.body.clone(),
            payload.descriptor_annotations(),
            &mut stats,
        )
        .await?;
    }
    Ok(stats)
}

async fn ensure_planned_blob(
    registry: &RegistryClient,
    repository: &str,
    digest: &str,
    body: Vec<u8>,
    stats: &mut UploadStats,
) -> Result<()> {
    if registry.ensure_blob(repository, digest, body).await? {
        stats.uploaded += 1;
    } else {
        stats.skipped += 1;
    }
    Ok(())
}

async fn publish_package(
    registry: &RegistryClient,
    resolved: &ResolvedPushReference,
    plan: &PackagePlan,
    platform: Option<Platform>,
) -> Result<String> {
    if let Some(platform) = platform {
        publish_child_manifest(registry, &resolved.repository, plan).await?;
        let mut published_digest = None;
        for tag in &resolved.tags {
            let digest =
                publish_platform_index(registry, &resolved.repository, tag, plan, platform.clone())
                    .await?;
            published_digest.get_or_insert(digest);
        }
        return Ok(published_digest.unwrap_or_else(|| plan.manifest_digest.clone()));
    }
    for tag in &resolved.tags {
        let digest = registry
            .put_manifest(
                &resolved.repository,
                tag,
                OCI_MANIFEST_MEDIA_TYPE,
                plan.manifest_bytes.clone(),
            )
            .await?;
        verify_manifest_digest(&digest, &plan.manifest_digest, "manifest")?;
    }
    Ok(plan.manifest_digest.clone())
}

async fn publish_child_manifest(
    registry: &RegistryClient,
    repository: &str,
    plan: &PackagePlan,
) -> Result<()> {
    let digest = registry
        .put_manifest(
            repository,
            &plan.manifest_digest,
            OCI_MANIFEST_MEDIA_TYPE,
            plan.manifest_bytes.clone(),
        )
        .await?;
    verify_manifest_digest(&digest, &plan.manifest_digest, "child manifest")
}

fn verify_manifest_digest(actual: &str, expected: &str, label: &str) -> Result<()> {
    if actual != expected {
        return Err(CliError::Operational(format!(
            "registry returned {label} digest {actual}, expected {expected}"
        )));
    }
    Ok(())
}

async fn publish_platform_index(
    registry: &RegistryClient,
    repository: &str,
    tag: &str,
    plan: &PackagePlan,
    platform: Platform,
) -> Result<String> {
    let mut manifests = match registry.get_manifest(repository, tag).await {
        Ok(response) => {
            let doc = ManifestDocument::parse(&response.body, &response.content_type)
                .map_err(|err| CliError::Operational(format!("decode existing index: {err}")))?;
            match doc {
                ManifestDocument::Index(index) => index
                    .manifests
                    .into_iter()
                    .filter_map(index_descriptor_from_existing)
                    .collect::<Vec<_>>(),
                ManifestDocument::Manifest(_) => {
                    return Err(CliError::Usage(format!(
                        "{repository}:{tag} already points to a non-platform manifest"
                    )));
                }
            }
        }
        Err(CliError::NotFound(_)) => Vec::new(),
        Err(err) => return Err(err),
    };
    let label = platform.label();
    manifests.retain(|descriptor| descriptor.platform.label() != label);
    manifests.push(IndexDescriptor {
        media_type: OCI_MANIFEST_MEDIA_TYPE.to_owned(),
        digest: plan.manifest_digest.clone(),
        size: plan
            .manifest_bytes
            .len()
            .try_into()
            .map_err(|_| CliError::Operational("manifest is too large".to_owned()))?,
        platform,
    });
    manifests.sort_by_key(|descriptor| descriptor.platform.label());
    let index = ImageIndexDocument {
        schema_version: 2,
        media_type: OCI_IMAGE_INDEX,
        manifests,
        annotations: plan.annotations.clone(),
    };
    let body = serde_json::to_vec(&index)
        .map_err(|err| CliError::Operational(format!("encode image index: {err}")))?;
    registry
        .put_manifest(repository, tag, OCI_IMAGE_INDEX, body)
        .await
}

fn index_descriptor_from_existing(descriptor: crate::app::Descriptor) -> Option<IndexDescriptor> {
    Some(IndexDescriptor {
        media_type: descriptor.media_type,
        digest: descriptor.digest,
        size: descriptor.size.try_into().ok()?,
        platform: descriptor.platform?,
    })
}

async fn pull(args: PullArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let resolved = resolve_app_reference(
        &args.app,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    if !settings.quiet {
        eprintln!("Resolved reference: {}", resolved.full);
    }
    let reporter = progress::make_reporter(settings.quiet);
    let registry = with_progress(
        registry_client(&resolved.registry, config, settings.insecure)?,
        reporter.as_ref(),
    );

    // One manifest fetch decides what this reference names, and the app path carries the
    // same document forward rather than asking for it again. A restore point is recognized
    // by its `artifactType`, never by how its tag is spelled; a reference that will not
    // fetch or parse fails right here, with the error the app path has always reported.
    let fetched = match resolve_pull_target(&registry, &resolved.repository, &resolved.tag).await? {
        PullTarget::RestorePoint(point) => {
            return pull_restore_point(&registry, &resolved, &point, &args, settings).await;
        }
        PullTarget::App(fetched) => *fetched,
    };
    if let Some(archive) = &args.archive {
        return Err(CliError::Usage(format!(
            "--archive {} applies to a restore point; {} is an app package",
            archive.display(),
            resolved.full
        )));
    }
    // For an app, `-o` is the positional DIR under another name.
    let mut args = args;
    match (args.dir.take(), args.output.take()) {
        (Some(dir), None) | (None, Some(dir)) => args.dir = Some(dir),
        (Some(dir), Some(output)) if dir == output => args.dir = Some(dir),
        (Some(dir), Some(output)) => {
            return Err(CliError::Usage(format!(
                "pull was given two output directories: {} and --output {}",
                dir.display(),
                output.display()
            )));
        }
        (None, None) => {}
    }

    if args.dir.is_none() {
        let result = cache_remote_package(
            &registry,
            &resolved,
            single_platform(settings)?,
            progress::as_dyn(reporter.as_ref()),
            fetched,
        )
        .await?;
        println!("{}@{}", resolved.full, result.digest);
        if !settings.quiet {
            eprintln!(
                "Cached {} blobs and {} manifests",
                result.blobs, result.manifests
            );
        }
        return Ok(());
    }
    let dest = args.dir.expect("dir checked");
    let result = materialize_package_from(
        &registry,
        &resolved.repository,
        &resolved.tag,
        single_platform(settings)?,
        &dest,
        args.force,
        fetched,
    )
    .await?;
    println!("{}@{}", resolved.full, result.digest);
    if !settings.quiet {
        eprintln!("Pulled {} files to {}", result.files, dest.display());
    }
    Ok(())
}

/// Downloads one App-data restore point: layers by digest through the registry with the
/// login this CLI already holds, decrypted here with the key the caller supplies.
///
/// This is the same decode the pool page's download link performs, moved to the machine
/// that asked for it — the server never sees the key, so it never sees the plaintext.
/// Nothing is fetched until the key has been checked against the id the point names: a
/// wrong key costs one manifest request, not a whole download.
async fn pull_restore_point(
    registry: &orc_app::registry::RegistryClient,
    resolved: &orc_app::reference::ResolvedReference,
    point: &orc_app::persist::point::ResolvedPoint,
    args: &PullArgs,
    settings: &CliSettings,
) -> Result<()> {
    let keys =
        orc_app::encryption::resolve_keys_from(&point.encryption, &args.key, &args.key_file)?;
    if keys.is_empty() {
        return Err(CliError::Operational(
            "this restore point declares no key to open it with".to_owned(),
        ));
    }
    let ring = orc_app::encryption::key_ring(&point.encryption, &keys)?;

    if !settings.quiet {
        let slot = point
            .slot
            .map_or_else(|| "?".to_owned(), |slot| slot.to_string());
        eprintln!(
            "Restore point {} — app {}, pool {}, slot {}{}",
            point.point.id,
            point.point.app,
            if point.pool.is_empty() {
                "?"
            } else {
                &point.pool
            },
            slot,
            if point.created.is_empty() {
                String::new()
            } else {
                format!(", taken {}", point.created)
            },
        );
        eprintln!(
            "{} files, {} of app data in {} layers ({} to transfer), sealed under key {}{}",
            point.point.files,
            byte_size(point.point.bytes),
            point.layers.len(),
            byte_size(point.transfer_bytes()),
            point.point.key_id,
            // A carried-forward layer keeps the key of the day it was written, so say how
            // many keys are on the ring that will be tried for one.
            if ring.len() > 1 {
                format!(" ({} keys given)", ring.len())
            } else {
                String::new()
            },
        );
    }

    let observer = LayerLines {
        quiet: settings.quiet,
    };
    let observer: Option<&dyn orc_app::persist::restore::LayerObserver> = Some(&observer);

    if let Some(archive) = &args.archive {
        let stats = orc_app::persist::point::write_archive(
            registry,
            &resolved.repository,
            &ring,
            &point.point,
            archive,
            args.force,
            observer,
        )
        .await?;
        println!("{}@{}", resolved.full, point.digest);
        if !settings.quiet {
            eprintln!(
                "Wrote {} — {} files, {} dirs, {} symlinks, {} of app data",
                archive.display(),
                stats.files,
                stats.dirs,
                stats.symlinks,
                byte_size(stats.bytes),
            );
        }
        return Ok(());
    }

    let dest = args
        .output
        .clone()
        .or_else(|| args.dir.clone())
        .unwrap_or_else(|| default_point_dir(point));
    let stats = orc_app::persist::point::materialize_into(
        registry,
        &resolved.repository,
        &ring,
        &point.point,
        &dest,
        args.force,
        observer,
    )
    .await?;
    println!("{}@{}", resolved.full, point.digest);
    if !settings.quiet {
        eprintln!(
            "Restored {} files, {} dirs, {} symlinks, {} of app data to {}",
            stats.files,
            stats.dirs,
            stats.symlinks,
            byte_size(stats.bytes),
            dest.display(),
        );
    }
    Ok(())
}

/// `./<tag>`: the point's own canonical tag, made safe to be one path segment.
fn default_point_dir(point: &orc_app::persist::point::ResolvedPoint) -> PathBuf {
    let name = point.output_name();
    PathBuf::from(if name.is_empty() {
        "restore-point".to_owned()
    } else {
        name
    })
}

/// One stderr line per layer as the point is read. A restore point can be a very long
/// silence otherwise: each layer is a whole blob, fetched and decoded before the next.
struct LayerLines {
    quiet: bool,
}

impl orc_app::persist::restore::LayerObserver for LayerLines {
    fn layer(&self, number: usize, total: usize, bytes: u64) {
        if !self.quiet {
            eprintln!(
                "Layer {number}/{total} ({} restored so far)",
                byte_size(bytes)
            );
        }
    }
}

/// Bytes as a person reads them. Binary units, because these are file sizes.
fn byte_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Author round-trip: reconstructs `artifact.yaml` (from the recipe referrer) plus
/// every platform's payload files into a directory, ready for `orc build`/`push`.
async fn clone(args: CloneArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let resolved = resolve_app_reference(
        &args.app,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    if !settings.quiet {
        eprintln!("Resolved reference: {}", resolved.full);
    }
    let dest = match args.dir {
        Some(dir) => dir,
        None => PathBuf::from(app_name_from_repository(&resolved.repository)?),
    };
    let reporter = progress::make_reporter(settings.quiet);
    let registry = with_progress(
        registry_client(&resolved.registry, config, settings.insecure)?,
        reporter.as_ref(),
    );

    // Resolve the package digest, then recover its embedded recipe.
    let response = registry
        .get_manifest(&resolved.repository, &resolved.tag)
        .await?;
    let Some(recipe) = fetch_recipe(&registry, &resolved.repository, &response.digest).await?
    else {
        return Err(CliError::NotFound(format!(
            "{} has no embedded recipe; use `orc pull` to extract one platform's files",
            resolved.full
        )));
    };

    // Write artifact.yaml verbatim, then materialize all-platform payloads.
    write_recipe_file(&dest, &recipe, args.force)?;
    let result = materialize_all_platforms(
        &registry,
        &resolved.repository,
        &resolved.tag,
        &dest,
        args.force,
    )
    .await?;

    println!("{}@{}", resolved.full, result.digest);
    if !settings.quiet {
        let platforms = if result.platforms.is_empty() {
            "any".to_owned()
        } else {
            result.platforms.join(", ")
        };
        eprintln!(
            "Cloned artifact.yaml + {} files ({platforms}) to {}",
            result.files,
            dest.display()
        );
    }
    Ok(())
}

fn write_recipe_file(dest: &Path, body: &[u8], force: bool) -> Result<()> {
    std::fs::create_dir_all(dest)
        .map_err(|err| CliError::Operational(format!("create {}: {err}", dest.display())))?;
    let path = dest.join("artifact.yaml");
    if path.exists() && !force {
        return Err(CliError::Conflict(format!(
            "{} already exists; use --force to overwrite",
            path.display()
        )));
    }
    std::fs::write(&path, body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))
}

struct CachedPull {
    digest: String,
    blobs: usize,
    manifests: usize,
}

async fn cache_remote_package(
    registry: &RegistryClient,
    resolved: &ResolvedReference,
    platform: Option<&str>,
    reporter: Option<&dyn ProgressReporter>,
    fetched: FetchedManifest,
) -> Result<CachedPull> {
    // The reference's own manifest was fetched to decide what it named; caching it writes
    // exactly those bytes, under exactly that digest.
    let repository = resolved.repository.as_str();
    let response = fetched.response;
    let mut manifests = 0usize;
    let target = match fetched.document {
        ManifestDocument::Manifest(manifest) => {
            validate_app_manifest(&manifest)?;
            let descriptor = write_manifest(OCI_MANIFEST_MEDIA_TYPE, &response.body)?;
            cache_manifest_blobs(registry, repository, &manifest, reporter).await?;
            manifests += 1;
            descriptor
        }
        ManifestDocument::Index(index) => {
            let _root = write_manifest(OCI_IMAGE_INDEX, &response.body)?;
            manifests += 1;
            let child = select_child_descriptor(&index.manifests, platform)?;
            let child_response = registry.get_manifest(repository, &child.digest).await?;
            if child_response.digest != child.digest {
                return Err(CliError::Operational(format!(
                    "manifest digest mismatch: expected {}, got {}",
                    child.digest, child_response.digest
                )));
            }
            let child_doc =
                ManifestDocument::parse(&child_response.body, &child_response.content_type)
                    .map_err(|err| {
                        CliError::Operational(format!("decode child manifest: {err}"))
                    })?;
            let ManifestDocument::Manifest(manifest) = child_doc else {
                return Err(CliError::Operational(
                    "image index child resolved to another index".to_owned(),
                ));
            };
            validate_app_manifest(&manifest)?;
            cache_manifest_blobs(registry, repository, &manifest, reporter).await?;
            manifests += 1;
            write_manifest(OCI_MANIFEST_MEDIA_TYPE, &child_response.body)?
        }
    };
    write_ref(
        &resolved.full,
        &resolved.registry,
        repository,
        &resolved.tag,
        target.clone(),
        Vec::new(),
    )?;
    let blobs = count_manifest_blobs(&target)?;
    Ok(CachedPull {
        digest: target.digest,
        blobs,
        manifests,
    })
}

async fn cache_manifest_blobs(
    registry: &RegistryClient,
    repository: &str,
    manifest: &crate::app::ImageManifest,
    reporter: Option<&dyn ProgressReporter>,
) -> Result<()> {
    cache_remote_blob(registry, repository, &manifest.config.digest, reporter).await?;
    for layer in &manifest.layers {
        cache_remote_blob(registry, repository, &layer.digest, reporter).await?;
    }
    Ok(())
}

async fn cache_remote_blob(
    registry: &RegistryClient,
    repository: &str,
    digest: &str,
    reporter: Option<&dyn ProgressReporter>,
) -> Result<()> {
    if crate::cache::read_blob(digest)?.is_some() {
        report_blob(reporter, digest, ProgressPhase::Verifying);
        verify_cached_blob(digest)?;
        // Terminal `Cached` so the line settles on "Cached", not "Done".
        report_blob(reporter, digest, ProgressPhase::Cached);
        return Ok(());
    }
    // `get_blob` emits the byte-level download events for this digest.
    let body = registry.get_blob(repository, digest).await?;
    report_blob(reporter, digest, ProgressPhase::Verifying);
    let actual = digest_bytes(&body);
    if actual != digest {
        report_blob(
            reporter,
            digest,
            ProgressPhase::Failed {
                message: format!("digest mismatch: got {actual}"),
            },
        );
        return Err(CliError::Operational(format!(
            "blob digest mismatch: expected {digest}, got {actual}"
        )));
    }
    report_blob(reporter, digest, ProgressPhase::Writing);
    write_blob(digest, &body)?;
    report_blob(reporter, digest, ProgressPhase::Done);
    Ok(())
}

fn count_manifest_blobs(descriptor: &CachedDescriptor) -> Result<usize> {
    let body = read_manifest(&descriptor.digest)?;
    let document = ManifestDocument::parse(&body, &descriptor.media_type)
        .map_err(|err| CliError::Operational(format!("decode cached manifest: {err}")))?;
    match document {
        ManifestDocument::Manifest(manifest) => Ok(1 + manifest.layers.len()),
        ManifestDocument::Index(_) => Ok(0),
    }
}

fn validate_app_manifest(manifest: &crate::app::ImageManifest) -> Result<()> {
    if manifest.schema_version != 2
        || manifest.artifact_type != crate::app::APP_ARTIFACT_TYPE
        || manifest.config.media_type != crate::app::APP_CONFIG_MEDIA_TYPE
    {
        return Err(CliError::NotFound(
            "manifest is not an ORC app artifact".to_owned(),
        ));
    }
    Ok(())
}

fn select_child_descriptor<'a>(
    children: &'a [crate::app::Descriptor],
    platform: Option<&str>,
) -> Result<&'a crate::app::Descriptor> {
    if let Some(platform) = platform {
        return children
            .iter()
            .find(|child| {
                child
                    .platform
                    .as_ref()
                    .is_some_and(|item| item.label() == platform)
            })
            .ok_or_else(|| no_matching_platform(children));
    }
    if children.len() == 1 {
        return children
            .first()
            .ok_or_else(|| no_matching_platform(children));
    }
    let host = host_platform_label();
    children
        .iter()
        .find(|child| {
            child
                .platform
                .as_ref()
                .is_some_and(|item| item.label() == host)
        })
        .ok_or_else(|| no_matching_platform(children))
}

fn no_matching_platform(children: &[crate::app::Descriptor]) -> CliError {
    let available = children
        .iter()
        .filter_map(|descriptor| descriptor.platform.as_ref())
        .map(Platform::label)
        .collect::<Vec<_>>()
        .join(", ");
    CliError::NotFound(format!("no matching platform; available: {available}"))
}

fn host_platform_label() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}/{architecture}")
}

async fn install(args: InstallArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    if args.resume {
        return resume_install(settings).await;
    }
    let app_ref = args
        .app
        .as_deref()
        .ok_or_else(|| CliError::Usage("install requires an app reference".to_owned()))?;
    let resolved = resolve_app_reference(
        app_ref,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    let app = app_name_from_repository(&resolved.repository)?;
    let version = resolved.tag.clone();
    if !settings.quiet {
        eprintln!("Resolved reference: {}", resolved.full);
    }
    let cwd = std::env::current_dir()
        .map_err(|err| CliError::Operational(format!("read current directory: {err}")))?;
    // No idempotency gating: (re)install with the given params every time and let the app's
    // install script decide what's a no-op. When already installed (and not --force), reuse the
    // materialized files and just re-run the install phase; --force re-pulls/re-materializes.
    let pass = match read_install_record(&app, &version)? {
        Some(record) if !args.force => {
            reinstall_existing(record, &app, &version, &args.params, &cwd).await?
        }
        _ => {
            let fresh = install_fresh_app(FreshInstall {
                resolved: &resolved,
                app: &app,
                version: &version,
                param_args: &args.params,
                force: args.force,
                settings,
                config,
                base_dir: &cwd,
            })
            .await?;
            match fresh {
                FreshOutcome::Pass(pass) => pass,
                // A version prefix that resolved onto an existing install takes the same
                // path a caller who typed the concrete version would have taken above.
                FreshOutcome::AlreadyInstalled(record) => {
                    let version = record.version.clone();
                    reinstall_existing(*record, &app, &version, &args.params, &cwd).await?
                }
            }
        }
    };
    let installed = match pass {
        InstallPass::Installed(installed) => *installed,
        // The phase asked for the machine: nothing is installed yet, and the run ends by
        // arranging its own return rather than by reporting a result.
        InstallPass::RebootPending(pending) => {
            return take_install_reboot(&pending, &args.params, &cwd);
        }
    };
    // A version prefix resolved to a concrete version: everything from here on names what
    // was actually installed, not what was typed. The reference still names the registry
    // this run pulled from, which is not always the one the record was first written with.
    let version = installed.record.version.clone();
    let reference = resolved.with_tag(&version);
    retire_resume_state(&app, &version)?;
    println!("{reference}@{}", installed.record.digest);
    if !settings.quiet {
        eprintln!(
            "Installed {} files to {}",
            installed.files,
            installed.materialized.display()
        );
    }
    Ok(())
}

/// Continues an installation its install phase interrupted with a reboot request.
///
/// Everything the run needs is on disk already: the app's files were materialized before
/// the restart (and whatever the phase wrote into them survived it), the parameters and
/// the pending install record are in the resume marker, and the reboot counter is in the
/// phase marker the primitive reopens. So the resume is the install phase and nothing
/// else — no registry, no re-pull, no second materialization.
async fn resume_install(settings: &CliSettings) -> Result<()> {
    let state_dir = cli_state_dir()?;
    let Some(marker) = resume::read(&state_dir)? else {
        eprintln!("Nothing to resume: no installation is waiting for a reboot.");
        return Ok(());
    };
    // Runs unattended out of a boot hook, so a marker that drifted from what the operator
    // asked for stops here rather than installing something nobody typed.
    marker.verify()?;

    let mut record = marker.record.clone();
    let app = record.app.clone();
    let version = record.version.clone();
    let materialized = if record.materialized_dir.is_empty() {
        materialized_app_dir(&app, &version)?
    } else {
        PathBuf::from(&record.materialized_dir)
    };
    let app_config = read_materialized_app_config(&materialized)?;
    let base_dir = marker.base_dir();
    let params = parse_app_params(app_config.params.as_ref(), &marker.params, &base_dir)?;
    if !settings.quiet {
        eprintln!(
            "Resuming the install of {app}:{version} after {} reboot(s)",
            marker.reboot_count
        );
    }

    let outcome =
        install_phase_under_reboot(&app, &version, &app_config, &params, &materialized).await;
    record.params = durable_param_values(&params);
    match outcome {
        // Another cycle: the marker and the hook are refreshed and the machine goes down
        // again, under the same counter.
        Ok(PhaseOutcome::RebootRequested { reboot_count }) => take_install_reboot(
            &RebootPending {
                record,
                reboot_count,
            },
            &marker.params,
            &base_dir,
        ),
        Ok(PhaseOutcome::Completed) => {
            "stopped".clone_into(&mut record.state);
            write_install_record(&record)?;
            retire_resume_state(&app, &version)?;
            println!("{}@{}", record.reference, record.digest);
            if !settings.quiet {
                eprintln!(
                    "Installed {app}:{version} to {} (continued across {} reboot(s))",
                    materialized.display(),
                    marker.reboot_count
                );
            }
            Ok(())
        }
        // A phase that failed on its own terms has nothing left to resume: the pass already
        // dropped its reboot state, and a hook that kept firing would only repeat the
        // failure unattended at every boot.
        Err(err) => {
            retire_resume_state(&app, &version)?;
            Err(err)
        }
    }
}

/// How an install pass ended.
enum InstallPass {
    /// The install phase converged; the record is on disk. Boxed: the installed app
    /// carries the whole app config, and every caller matches on the variant first.
    Installed(Box<InstalledApp>),
    /// The phase asked the CLI to restart the machine. No install record was written —
    /// an interrupted install is not an installed app.
    RebootPending(Box<RebootPending>),
}

/// What a fresh install produced.
///
/// The extra variant is [`install_fresh_app`]'s alone: only a run that resolves a
/// version can land on a version that is already installed, and only its callers know
/// what to do about it — `install` re-runs the install phase over the materialized
/// files, `start` just runs the app — exactly as each would have for a caller who
/// named the concrete version.
enum FreshOutcome {
    Pass(InstallPass),
    AlreadyInstalled(Box<InstallRecord>),
}

/// An install waiting for the machine to come back.
struct RebootPending {
    /// The record the converged install will write.
    record: InstallRecord,
    /// Reboots this install has now been charged, this one included.
    reboot_count: u32,
}

/// The CLI state directory for reboot-spanning installs. It holds the command shim, the
/// phase counter, and the resume marker.
fn cli_state_dir() -> Result<PathBuf> {
    let dir = orc_app::state::state_dir()?;
    std::fs::create_dir_all(&dir)
        .map_err(|err| CliError::Operational(format!("create {}: {err}", dir.display())))?;
    Ok(dir)
}

/// Runs an app's install phase under the reboot plumbing: the shim in front of the
/// phase's `PATH`, and the counter that survives the restarts it asks for.
async fn install_phase_under_reboot(
    app: &str,
    version: &str,
    app_config: &AppConfig,
    params: &std::collections::BTreeMap<String, ParsedParam>,
    work_dir: &Path,
) -> Result<PhaseOutcome> {
    let state_dir = cli_state_dir()?;
    let reboot = PhaseReboot::enter(&state_dir, app, version, "install")?;
    if !orc_app::reboot::may_reboot(reboot.reboot_count()) {
        // Loud, because the phase is about to have its `shutdown` refused and an operator
        // reading back a half-finished install needs to see why.
        eprintln!(
            "{app}:{version} install has spent its reboot budget ({}/{}); \
             further reboot requests are refused",
            reboot.reboot_count(),
            orc_app::reboot::MAX_PHASE_REBOOTS
        );
    }
    // The CLI has no secret resolver; `sec:` tokens stay unresolved here.
    run_install_phase(
        app,
        // Standalone: one copy of the app on this machine, so the instance is the app.
        app,
        version,
        app_config,
        params,
        work_dir,
        None,
        terminal_log_line(),
        Some(&reboot),
        None,
    )
    .await
}

/// Arranges the CLI's own return, then hands the machine to the reboot executor.
///
/// The order is the whole safety property: the boot hook is registered *first*, and a
/// registration that fails aborts the restart. Rebooting a machine with nothing to
/// re-invoke the CLI would strand the installation halfway with no way back.
fn take_install_reboot(
    pending: &RebootPending,
    param_args: &[String],
    base_dir: &Path,
) -> Result<()> {
    let state_dir = cli_state_dir()?;
    let label = format!("{}:{}", pending.record.app, pending.record.version);
    let spec = boot_hook::HookSpec::from_env()?;
    if let Err(err) = boot_hook::register(&spec) {
        // Nothing was restarted, so nothing is charged: the next attempt starts on a full
        // budget and a clean slate.
        orc_app::reboot::clear(&state_dir);
        let _ = resume::remove(&state_dir);
        return Err(CliError::Operational(format!(
            "{label} install asked for a reboot, but the boot hook that would continue it \
             afterwards could not be registered: {err}. Nothing was restarted; re-run \
             `orc install` with the privileges to write that path."
        )));
    }
    let reboot_count = pending.reboot_count;
    let marker = resume::ResumeMarker::new(
        pending.record.clone(),
        param_args.to_vec(),
        base_dir,
        reboot_count,
        boot_hook::describe(),
    );
    if let Err(err) = resume::write(&state_dir, &marker) {
        let _ = boot_hook::unregister();
        orc_app::reboot::clear(&state_dir);
        return Err(err);
    }
    eprintln!(
        "{label}: the install phase requested a reboot ({reboot_count}/{}).",
        orc_app::reboot::MAX_PHASE_REBOOTS
    );
    eprintln!(
        "Rebooting now — this installation continues automatically after the restart (via {}).",
        marker.hook
    );
    match RebootExecutor::from_env().execute(&format!("{label} install")) {
        // The restart is enqueued and proceeds on its own; exiting at once beats sitting
        // in a terminal the machine is about to take away.
        RebootAction::Rebooting => std::process::exit(orc_app::ExitCode::Success as i32),
        RebootAction::Recorded => Ok(()),
        RebootAction::Failed => Err(CliError::Operational(format!(
            "{label} install asked for a reboot but this machine would not restart; the \
             installation stays pending — restart it by hand, or run `orc install --resume`"
        ))),
    }
}

/// Drops the pending-install state once a pass ends without asking for the machine.
///
/// Only for the install the marker actually names: a marker left by another app is
/// another app's business, and unregistering its hook would strand it.
fn retire_resume_state(app: &str, version: &str) -> Result<()> {
    let state_dir = cli_state_dir()?;
    match resume::read(&state_dir) {
        Ok(Some(marker)) if marker.record.app == app && marker.record.version == version => {}
        Ok(Some(_) | None) => return Ok(()),
        // A marker nothing can read describes no installation; it and its hook go.
        Err(_) => {}
    }
    boot_hook::unregister()?;
    resume::remove(&state_dir)
}

struct InstalledApp {
    record: InstallRecord,
    app_config: AppConfig,
    materialized: PathBuf,
    files: usize,
}

/// Forwards a lifecycle phase's child output straight to the operator's terminal,
/// preserving the live install/uninstall/start output the CLI showed under
/// inherited stdio (stderr→stderr, stdout→stdout).
fn terminal_log_line() -> LogLine {
    Arc::new(|stream: LogStream, line: &str| match stream {
        LogStream::Stderr => eprintln!("{line}"),
        LogStream::Stdout => println!("{line}"),
    })
}

/// Re-installs an already-materialized app: reuses the on-disk files and re-runs the install
/// phase with the given params (no re-pull). Updates the record's params/state.
async fn reinstall_existing(
    mut record: InstallRecord,
    app: &str,
    version: &str,
    param_args: &[String],
    base_dir: &Path,
) -> Result<InstallPass> {
    let materialized = if record.materialized_dir.is_empty() {
        materialized_app_dir(app, version)?
    } else {
        PathBuf::from(&record.materialized_dir)
    };
    let app_config = read_materialized_app_config(&materialized)?;
    let params = parse_app_params(app_config.params.as_ref(), param_args, base_dir)?;
    let outcome =
        install_phase_under_reboot(app, version, &app_config, &params, &materialized).await?;
    record.params = durable_param_values(&params);
    if let PhaseOutcome::RebootRequested { reboot_count } = outcome {
        // The record on disk keeps saying what it said before the phase ran: this
        // re-install has not finished, and the resume marker carries the update.
        return Ok(InstallPass::RebootPending(Box::new(RebootPending {
            record,
            reboot_count,
        })));
    }
    "stopped".clone_into(&mut record.state);
    write_install_record(&record)?;
    Ok(InstallPass::Installed(Box::new(InstalledApp {
        record,
        app_config,
        materialized,
        files: 0,
    })))
}

struct InstallMaterializedPackage {
    digest: String,
    files: usize,
    platform: String,
    config_bytes: Vec<u8>,
    blob_digests: Vec<String>,
}

impl From<CachedMaterializedPackage> for InstallMaterializedPackage {
    fn from(value: CachedMaterializedPackage) -> Self {
        Self {
            digest: value.digest,
            files: value.files,
            platform: value.platform,
            config_bytes: value.config_bytes,
            blob_digests: value.blob_digests,
        }
    }
}

impl From<MaterializedPackage> for InstallMaterializedPackage {
    fn from(value: MaterializedPackage) -> Self {
        Self {
            digest: value.digest,
            files: value.files,
            platform: value.platform,
            config_bytes: value.config_bytes,
            blob_digests: value.blob_digests,
        }
    }
}

struct FreshInstall<'a> {
    resolved: &'a ResolvedReference,
    app: &'a str,
    version: &'a str,
    param_args: &'a [String],
    force: bool,
    settings: &'a CliSettings,
    config: &'a StoredConfig,
    base_dir: &'a std::path::Path,
}

async fn install_fresh_app(request: FreshInstall<'_>) -> Result<FreshOutcome> {
    let named_dest = materialized_app_dir(request.app, request.version)?;
    let platform = single_platform(request.settings)?;
    let reporter = progress::make_reporter(request.settings.quiet);
    // A reference the local store already holds installs as the version it names, so
    // this install is concrete before it starts and a forced run may replace its work
    // directory right away.
    let cached = if cached_reference_exists(&request.resolved.full)? {
        clear_materialized_dir(&named_dest, request.force)?;
        materialize_cached_package(
            &request.resolved.full,
            platform,
            &named_dest,
            request.force,
            progress::as_dyn(reporter.as_ref()),
        )?
    } else {
        None
    };
    let materialized = if let Some(package) = cached {
        Materialization {
            package: InstallMaterializedPackage::from(package),
            version: request.version.to_owned(),
            dest: named_dest,
            reference: request.resolved.full.clone(),
        }
    } else {
        let registry = with_progress(
            registry_client(
                &request.resolved.registry,
                request.config,
                request.settings.insecure,
            )?,
            reporter.as_ref(),
        );
        match materialize_from_registry(&request, &registry, platform, &named_dest).await? {
            // The requested version resolved onto an install that already exists; the
            // caller decides what to do with it.
            RegistryMaterialization::AlreadyInstalled(record) => {
                return Ok(FreshOutcome::AlreadyInstalled(record));
            }
            RegistryMaterialization::Materialized(materialized) => materialized,
        }
    };
    let Materialization {
        package: result,
        version,
        dest,
        reference,
    } = materialized;
    let app_config = serde_json::from_slice::<AppConfig>(&result.config_bytes)
        .map_err(|err| CliError::Operational(format!("decode app config: {err}")))?;
    let params = parse_app_params(
        app_config.params.as_ref(),
        request.param_args,
        request.base_dir,
    )?;
    // The record is assembled before the phase runs but written only once it converges:
    // an install interrupted by a reboot hands this to the resume marker instead, so
    // nothing on disk ever claims a half-finished app is installed.
    let (mode, pid_service) = install_record_mode(request.app, &version, &app_config, &params);
    let record = InstallRecord {
        app: request.app.to_owned(),
        version: version.clone(),
        reference,
        digest: result.digest,
        platform: result.platform,
        mode,
        state: "stopped".to_owned(),
        pid_service,
        params: durable_param_values(&params),
        blob_digests: result.blob_digests,
        materialized_dir: dest.display().to_string(),
    };
    let outcome =
        install_phase_under_reboot(request.app, &version, &app_config, &params, &dest).await?;
    if let PhaseOutcome::RebootRequested { reboot_count } = outcome {
        return Ok(FreshOutcome::Pass(InstallPass::RebootPending(Box::new(
            RebootPending {
                record,
                reboot_count,
            },
        ))));
    }
    write_install_record(&record)?;
    Ok(FreshOutcome::Pass(InstallPass::Installed(Box::new(
        InstalledApp {
            record,
            app_config,
            materialized: dest,
            files: result.files,
        },
    ))))
}

/// A package on disk, under the concrete version it installs as.
struct Materialization {
    package: InstallMaterializedPackage,
    version: String,
    dest: PathBuf,
    reference: String,
}

/// What the registry pass produced for a fresh install.
enum RegistryMaterialization {
    Materialized(Materialization),
    /// The requested version resolved to one that is already installed; nothing was
    /// materialized.
    AlreadyInstalled(Box<InstallRecord>),
}

/// Resolves the requested reference against the registry and puts its package on disk.
///
/// A resolved version prefix installs under the version it resolved to, so the work
/// directory, the install record, and `APP_VERSION` all name the same thing — and whatever
/// is already installed under that version is reused as if it had been named outright,
/// which is what keeps a repeated prefix install or start from refusing to overwrite its
/// own materialized files.
async fn materialize_from_registry(
    request: &FreshInstall<'_>,
    registry: &RegistryClient,
    platform: Option<&str>,
    named_dest: &Path,
) -> Result<RegistryMaterialization> {
    clear_named_dest(request, registry, named_dest).await?;
    let pinned = match resolve_install_target(registry, request, platform, named_dest).await? {
        InstallTarget::Materialized(package) => {
            return Ok(RegistryMaterialization::Materialized(Materialization {
                package: InstallMaterializedPackage::from(package),
                version: request.version.to_owned(),
                dest: named_dest.to_path_buf(),
                reference: request.resolved.full.clone(),
            }));
        }
        InstallTarget::Pinned(pinned) => pinned,
    };
    if !request.force
        && let Some(record) = read_install_record(request.app, &pinned)?
    {
        if !request.settings.quiet {
            eprintln!(
                "Resolved {}:{} to {} via version discovery (already installed)",
                request.app, request.version, pinned
            );
        }
        return Ok(RegistryMaterialization::AlreadyInstalled(Box::new(record)));
    }
    let dest = materialized_app_dir(request.app, &pinned)?;
    clear_materialized_dir(&dest, request.force)?;
    let package = materialize_pinned_package(request, registry, &pinned, platform, &dest).await?;
    Ok(RegistryMaterialization::Materialized(Materialization {
        package: InstallMaterializedPackage::from(package),
        reference: request.resolved.with_tag(&pinned),
        version: pinned,
        dest,
    }))
}

/// Puts the package of a version discovery resolved to on disk.
///
/// A version the recipe publishes may also have been pushed as a tag of its own, and that
/// is the package to install: a caller who types `app:1.5.7` and a caller whose `app:1.5`
/// resolves to 1.5.7 record the same reference, so they must not end up with different
/// bits. `default` stands in only where no such tag exists, which is the ordinary case for
/// a recipe that publishes versions the registry never sees.
async fn materialize_pinned_package(
    request: &FreshInstall<'_>,
    registry: &RegistryClient,
    pinned: &str,
    platform: Option<&str>,
    dest: &Path,
) -> Result<MaterializedPackage> {
    let repository = &request.resolved.repository;
    // The requested tag was just looked for and is not there, so a version that resolved
    // to itself has no package of its own to try.
    if pinned != request.version {
        match materialize_package(registry, repository, pinned, platform, dest, request.force).await
        {
            Ok(package) => {
                if !request.settings.quiet {
                    eprintln!(
                        "Resolved {}:{} to {pinned} via version discovery",
                        request.app, request.version
                    );
                }
                return Ok(package);
            }
            Err(CliError::NotFound(_)) => {}
            Err(err) => return Err(err),
        }
    }
    if !request.settings.quiet {
        eprintln!(
            "Resolved {}:{} via version discovery (installing default package pinned to {pinned})",
            request.app, request.version
        );
    }
    materialize_package(
        registry,
        repository,
        "default",
        platform,
        dest,
        request.force,
    )
    .await
}

/// What the requested reference turned out to name.
enum InstallTarget {
    /// The requested tag exists; its package is materialized.
    Materialized(MaterializedPackage),
    /// The tag is missing, but discovery names a concrete version to install instead.
    /// Nothing is materialized yet — the caller owns that decision.
    Pinned(String),
}

/// Clears the work directory the request names — but only once the registry has confirmed
/// that the tag it named is really there.
///
/// A forced install replaces the directory it installs into. The requested version may yet
/// turn out to be a version line that resolves onto another version, and onto another
/// directory, so clearing up front would take a sibling install's files with it and leave
/// that install's record pointing at nothing. The extra look-up is paid for only when
/// there is something to delete.
async fn clear_named_dest(
    request: &FreshInstall<'_>,
    registry: &RegistryClient,
    named_dest: &Path,
) -> Result<()> {
    if !request.force || !named_dest.exists() {
        return Ok(());
    }
    match registry
        .get_manifest(&request.resolved.repository, request.version)
        .await
    {
        Ok(_) => clear_materialized_dir(named_dest, true),
        Err(CliError::NotFound(_)) => Ok(()),
        Err(err) => Err(err),
    }
}

/// Removes a stale materialized directory before a forced re-materialization.
fn clear_materialized_dir(dest: &Path, force: bool) -> Result<()> {
    if force && dest.exists() {
        std::fs::remove_dir_all(dest)
            .map_err(|err| CliError::Operational(format!("remove {}: {err}", dest.display())))?;
    }
    Ok(())
}

/// Whether the local artifact store can serve `reference` without a registry.
fn cached_reference_exists(reference: &str) -> Result<bool> {
    match read_ref(reference) {
        Ok(_) => Ok(true),
        Err(CliError::NotFound(_)) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Materializes the requested package, or — when the tag is missing but the requested
/// version is discoverable from the package recipe — reports the concrete version whose package is
/// `default`'s. The install then keys on that version, so the lifecycle exports
/// `APP_VERSION=<version>` and the install script fetches that version.
///
/// The requested version resolves in two steps: an exact discovered version resolves to
/// itself, and anything else is read as a version prefix and resolves to the newest
/// discovered version on that line. A version that matches neither keeps today's
/// `NotFound`, so the run still exits with the not-found code.
async fn resolve_install_target(
    registry: &RegistryClient,
    request: &FreshInstall<'_>,
    platform: Option<&str>,
    dest: &Path,
) -> Result<InstallTarget> {
    let repository = &request.resolved.repository;
    match materialize_package(
        registry,
        repository,
        &request.resolved.tag,
        platform,
        dest,
        request.force,
    )
    .await
    {
        Ok(package) => Ok(InstallTarget::Materialized(package)),
        // Only a genuine tag-miss for a non-`default` version is a fallback candidate; any
        // other NotFound (e.g. a platform mismatch) is a real failure and passes through.
        Err(CliError::NotFound(original)) if request.version != "default" => {
            let matched = match_discovered_version(
                registry,
                repository,
                request.version,
                github_token(request.config),
            )
            .await?;
            match matched {
                DiscoveredMatch::Version(version) => Ok(InstallTarget::Pinned(version)),
                DiscoveredMatch::NoMatch => Err(CliError::NotFound(format!(
                    "{original}; no discovered version matches {:?}",
                    request.version
                ))),
                DiscoveredMatch::Unavailable => Err(CliError::NotFound(original)),
            }
        }
        Err(err) => Err(err),
    }
}

/// What a requested version matched in a repository's discovery recipe.
enum DiscoveredMatch {
    /// The concrete version to install.
    Version(String),
    /// The recipe was evaluated and nothing it publishes matches the request.
    NoMatch,
    /// There was nothing to match against: no `default` tag, no `versions:` block, or
    /// the source could not be reached.
    Unavailable,
}

/// Matches `version` against `repository`'s declared version-discovery recipe, evaluated
/// locally against `default`'s config.
///
/// The curated evaluation runs first. It is the one the recipe is tuned for, and on a busy
/// release feed it is the only one that fits the fetch budget, because the recipe's own
/// `limit` is what keeps the fetched page small enough to read. Only when nothing curated
/// matches does the uncurated evaluation run, which is what makes a version the recipe
/// prunes out of `orc versions` installable by name: curation shapes the listing, not what
/// may be installed.
///
/// Within an evaluation an exact version wins over a version line, and the sources come
/// back newest-first, so the first version on the requested line wins and no request is
/// ever ambiguous.
async fn match_discovered_version(
    registry: &RegistryClient,
    repository: &str,
    version: &str,
    github_token: Option<&str>,
) -> Result<DiscoveredMatch> {
    let Some(summary) = read_manifest_summary(registry, repository, "default").await? else {
        return Ok(DiscoveredMatch::Unavailable);
    };
    let Some(recipe) = summary.config.and_then(|config| config.versions) else {
        return Ok(DiscoveredMatch::Unavailable);
    };
    let limits = discovery_limits(github_token);
    // What the recipe curates is what the picker offers, and it is bounded by the
    // recipe's own limit — one page answers it, and answers most installs.
    let curated = discovery::evaluate_scoped(
        &recipe,
        repository,
        &limits,
        VersionScope::Curated,
        discovery::Reach::FirstPage,
    )
    .await;
    if curated.source_error.is_some() {
        return Ok(DiscoveredMatch::Unavailable);
    }
    if let Some(matched) = first_match(&curated.versions, version) {
        return Ok(DiscoveredMatch::Version(matched));
    }
    // Nothing curated matches, so this is the uncurated question: does the source
    // publish this version at all? Answer against the complete source listing so a
    // version sitting past the first page remains installable.
    let all = discovery::evaluate_scoped(
        &recipe,
        repository,
        &limits,
        VersionScope::All,
        discovery::Reach::WholeListing,
    )
    .await;
    if let Some(matched) = first_match(&all.versions, version) {
        return Ok(DiscoveredMatch::Version(matched));
    }
    // The wider list is the one that would have held a version the curated pass drops, so
    // failing to read it means the answer is unknown rather than "no such version".
    if all.source_error.is_some() {
        return Ok(DiscoveredMatch::Unavailable);
    }
    Ok(DiscoveredMatch::NoMatch)
}

/// What `request` names in an evaluated list, under the shared version-line rule:
/// itself when it is on the list, otherwise the newest version on the line it names,
/// preferring a stable release. The list arrives in the recipe's own pipeline order,
/// which is the order the rule reads "newest" in.
fn first_match(versions: &[String], request: &str) -> Option<String> {
    discovery::newest_on_version_line(versions.iter().map(String::as_str), request)
        .map(str::to_owned)
}

/// Rebuilds params from an install record's stored string values, restoring each param's
/// `file_backed` flag from the schema so content/sensitive params materialize as `<NAME>_FILE`
/// (the flag is not persisted in the record).
fn parsed_from_record(
    params: &std::collections::BTreeMap<String, String>,
    schema: Option<&ParamSchema>,
) -> std::collections::BTreeMap<String, ParsedParam> {
    params
        .iter()
        .map(|(name, value)| {
            let property = schema.and_then(|schema| schema.properties.get(name));
            let file_backed = property.is_some_and(|property| {
                property.sensitive || property.content_media_type.is_some()
            });
            // Record values are durable strings, never resolved secrets, so the
            // default lifetime is the whole app run unless the schema says otherwise.
            let lifetime = property
                .and_then(|property| property.lifetime)
                .unwrap_or(orc_app::app::ParamLifetime::Runtime);
            (
                name.clone(),
                ParsedParam {
                    name: name.clone(),
                    value: ParsedParamValue::String(value.clone()),
                    file_backed,
                    lifetime,
                },
            )
        })
        .collect()
}

async fn start(args: StartArgs, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let resolved = resolve_app_reference(
        &args.app,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    let app = app_name_from_repository(&resolved.repository)?;
    let version = resolved.tag.clone();
    let installed = match load_or_install_for_start(
        &args, &resolved, &app, &version, settings, config,
    )
    .await?
    {
        InstallPass::Installed(installed) => *installed,
        // The implied install asked for the machine. It is arranged exactly as a
        // standalone `orc install` arranges it — hook, marker, restart — and the app
        // is not started: its installation has not finished.
        InstallPass::RebootPending(pending) => {
            let cwd = std::env::current_dir()
                .map_err(|err| CliError::Operational(format!("read current directory: {err}")))?;
            // The pending record names the version that is actually being installed,
            // which is not the requested one when a version line resolved.
            let pending_version = pending.record.version.clone();
            take_install_reboot(&pending, &args.params, &cwd)?;
            return Err(CliError::Operational(format!(
                "{app}:{pending_version} was not started: its install phase requested a \
                     reboot and the installation is still pending"
            )));
        }
    };
    let record = installed.record.clone();
    // A version prefix resolved to a concrete version: the app runs, and records its run,
    // under what was installed rather than what was typed.
    let version = record.version.clone();

    // Param model (app decides idempotency, no gating): if the caller passes any params, that
    // is the full set for this run (required ones enforced); if none, reuse the params stored
    // at install time. Either way we keep each param's file_backed flag from the schema, so
    // content-typed params like shell `cmd` materialize as <NAME>_FILE.
    let schema = installed.app_config.params.as_ref();
    let params = if args.params.is_empty() {
        parsed_from_record(&record.params, schema)
    } else {
        let cwd = std::env::current_dir()
            .map_err(|err| CliError::Operational(format!("read current directory: {err}")))?;
        parse_app_params(schema, &args.params, &cwd)?
    };

    let mode = resolve_run_mode(
        &app,
        &version,
        &installed.app_config,
        &installed.materialized,
        &params,
    )?;
    match mode {
        RunMode::Subprocess => {
            if args.detach {
                return Err(CliError::Usage(
                    "orc start --detach is not implemented yet for an app that runs as a \
                     subprocess"
                        .to_owned(),
                ));
            }
            start_subprocess(&app, &version, &installed, &params, record, settings).await
        }
        // A service start is already the detached run `--detach` asks for: the manager
        // holds the app and this process returns. Saying so is kinder than refusing.
        mode => {
            if args.detach && !settings.quiet {
                eprintln!(
                    "{app}:{version} runs as a service, which is already detached; \
                     --detach changes nothing here"
                );
            }
            let backend = service_backend(&app, &version)?;
            let running =
                start_service(&app, &mode, &installed, &params, settings, backend.as_ref()).await?;
            write_install_record(&running)
        }
    }
}

/// Runs the app in the foreground and stays with it until it ends.
///
/// This process is the app's runtime for as long as the app runs, which is what makes the
/// operator's first interrupt — a Ctrl-C here, an `orc stop` in another shell — the start
/// of the termination sequence rather than a hang-up: the sequence can only run where the
/// child is held. A second interrupt stops waiting and jumps to the kill.
async fn start_subprocess(
    app: &str,
    version: &str,
    installed: &InstalledApp,
    params: &std::collections::BTreeMap<String, ParsedParam>,
    mut record: InstallRecord,
    settings: &CliSettings,
) -> Result<()> {
    let work_dir = installed.materialized.as_path();
    let config = &installed.app_config;
    let state_dir = orc_app::state::state_dir()?;
    // Installed before the child exists: an interrupt arriving while the app is starting
    // is the operator's, and it must not fall through to this process's default action.
    let mut interrupts = Interrupts::install()?;

    let start = orc_app::lifecycle::start_command(
        app, app, config, version, params, work_dir, None, None, None,
    )
    .await?;
    let mut child = spawn_piped_app(start.command)?;
    let started = Instant::now();
    let drains = drain_to_terminal(&mut child)?;
    // Startup-lifetime secrets are withdrawn as soon as the app is running.
    for path in start.startup_files {
        let _ = std::fs::remove_file(path);
    }

    // The marker first, then the record: a reader that sees a pid in the record can
    // always ask the marker whether it still means anything.
    let supervisor = supervisor::record(work_dir)?;
    "running".clone_into(&mut record.state);
    "process".clone_into(&mut record.mode);
    record.pid_service = Some(supervisor.pid.to_string());
    record.params = durable_param_values(params);
    write_install_record(&record)?;
    if !settings.quiet {
        eprintln!(
            "Started {app}:{version} in the foreground (supervisor pid {}); \
             interrupt it here, or run `orc stop {app}:{version}` elsewhere",
            supervisor.pid
        );
    }

    let ctx = AppContext {
        app,
        instance: app,
        version,
        config,
        params,
        work_dir,
        state_dir: &state_dir,
        secrets: None,
        log_line: terminal_log_line(),
    };
    let mut process = AppProcess::subprocess(&mut child, started);
    let (state, result) =
        supervise_foreground(&ctx, &mut process, &mut interrupts, drains, settings).await;

    orc_app::lifecycle::remove_param_files(work_dir);
    supervisor::clear(work_dir);
    state.clone_into(&mut record.state);
    record.pid_service = None;
    write_install_record(&record)?;
    result
}

/// Waits out one foreground run and runs the stopped hook after it, whichever way it
/// ended: the app's own exit, the operator's first interrupt, or their second.
///
/// Returns the state to record and what the run itself is worth as an exit code — an app
/// the operator stopped is not a failed start.
async fn supervise_foreground(
    ctx: &AppContext<'_>,
    process: &mut AppProcess<'_>,
    interrupts: &mut Interrupts,
    drains: TerminalDrains,
    settings: &CliSettings,
) -> (&'static str, Result<()>) {
    let (app, version) = (ctx.app, ctx.version);
    let started = process.started();
    let app_pid = process.pid();
    let interrupted = {
        let running = process.wait();
        tokio::pin!(running);
        tokio::select! {
            result = &mut running => Ending::Ended(result),
            interrupt = interrupts.next() => Ending::Interrupted(interrupt),
        }
    };

    match interrupted {
        // Nobody asked: the app ended on its own, and the stopped hook is told so.
        Ending::Ended(result) => {
            drains.flush().await;
            let run_duration = started.elapsed();
            let (exit, state, result) = match result {
                Ok(status) if status.success() => (
                    ExitInfo::from_status(status, app_pid, run_duration),
                    "completed",
                    Ok(()),
                ),
                Ok(status) => (
                    ExitInfo::from_status(status, app_pid, run_duration),
                    "failed",
                    Err(CliError::Operational(format!(
                        "start phase exited with {status}"
                    ))),
                ),
                Err(err) => (
                    ExitInfo::unknown(app_pid, run_duration),
                    "failed",
                    Err(CliError::Operational(format!("run start phase: {err}"))),
                ),
            };
            run_stopped_phase(ctx, StoppedReason::Exit, StopStatus::Skipped, &exit, None).await;
            (state, result)
        }
        Ending::Interrupted(interrupt) => {
            let force = CancellationToken::new();
            if interrupt == Interrupt::Force {
                force.cancel();
            }
            if !settings.quiet {
                if force.is_cancelled() {
                    eprintln!(
                        "Stopping {app}:{version} now: the stop command and the grace \
                         period are skipped"
                    );
                } else {
                    eprintln!(
                        "Stopping {app}:{version}; interrupt again to stop waiting and \
                         end it immediately"
                    );
                }
            }
            let outcome = {
                let stopping = stop_sequence(ctx, process, StopReason::Stop, &force);
                tokio::pin!(stopping);
                loop {
                    tokio::select! {
                        outcome = &mut stopping => break outcome,
                        _ = interrupts.next(), if !force.is_cancelled() => {
                            force.cancel();
                            if !settings.quiet {
                                eprintln!("Ending {app}:{version} immediately, as asked");
                            }
                        }
                    }
                }
            };
            drains.flush().await;
            report_stop(app, version, &outcome, settings);
            let cap = force.is_cancelled().then_some(FORCED_STOPPED_TIMEOUT);
            run_stopped_phase(
                ctx,
                StoppedReason::Stopped(StopReason::Stop),
                outcome.stop_status,
                &outcome.exit,
                cap,
            )
            .await;
            ("stopped", Ok(()))
        }
    }
}

/// Hands the app to the platform's service manager and returns: the manager holds it from
/// here, which is the whole point of service mode — the app outlives this process.
async fn start_service(
    app: &str,
    mode: &RunMode,
    installed: &InstalledApp,
    params: &std::collections::BTreeMap<String, ParsedParam>,
    settings: &CliSettings,
    backend: &dyn ServiceBackend,
) -> Result<InstallRecord> {
    let mut record = installed.record.clone();
    let version = record.version.clone();
    let version = version.as_str();
    let Some(name) = mode.service_name() else {
        return Err(CliError::Operational(format!(
            "{app}:{version} does not name a service to start"
        )));
    };
    if matches!(mode, RunMode::ManagedService(_)) {
        // The definition names this binary, not the app: the manager restarts the app
        // while nobody is watching, and the environment has to be rebuilt at every start.
        let resolved = orc_app::lifecycle::resolved_params(params, None).await?;
        write_app_env(
            &installed.materialized,
            &AppEnv {
                app: app.to_owned(),
                instance: app.to_owned(),
                version: version.to_owned(),
                params: resolved,
                persist_state: None,
            },
        )?;
        let runtime_exe = std::env::current_exe()
            .map_err(|err| CliError::Operational(format!("locate the orc binary: {err}")))?;
        let spec = managed_service_spec(
            app,
            app,
            version,
            &installed.app_config,
            &installed.materialized,
            name,
            &runtime_exe,
        );
        backend.define(&spec).await?;
    }
    backend.start(name).await?;

    "running".clone_into(&mut record.state);
    "service".clone_into(&mut record.mode);
    record.pid_service = Some(name.to_owned());
    record.params = durable_param_values(params);
    if !settings.quiet {
        eprintln!("Started {app}:{version} as the service {name}");
    }
    Ok(record)
}

/// The interrupts a foreground start answers, held open for the whole run.
///
/// The streams are installed once and reused: a second interrupt arriving while the
/// termination sequence runs is the operator saying "now", and a handler registered
/// after the first one would be a window where that second interrupt kills this process
/// instead — leaving the app running with nothing supervising it.
struct Interrupts {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    force: tokio::signal::unix::Signal,
}

/// What an interrupt asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Interrupt {
    /// Run the termination sequence: the stop command, the signal, the grace period.
    Graceful,
    /// Do not wait: `orc stop --force` from another shell.
    Force,
}

/// How a foreground run came to an end.
enum Ending {
    /// The app ended by itself.
    Ended(std::io::Result<std::process::ExitStatus>),
    /// The operator asked for it to end.
    Interrupted(Interrupt),
}

impl Interrupts {
    fn install() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let install = |kind: SignalKind, name: &str| {
                signal(kind)
                    .map_err(|err| CliError::Operational(format!("listen for {name}: {err}")))
            };
            Ok(Self {
                interrupt: install(SignalKind::interrupt(), "interrupts")?,
                terminate: install(SignalKind::terminate(), "termination requests")?,
                force: install(SignalKind::user_defined1(), "forced stop requests")?,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    /// The next interrupt. Cancel-safe, so it can be raced against the app's own exit and
    /// then raced again against the termination sequence without losing a signal.
    async fn next(&mut self) -> Interrupt {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => Interrupt::Graceful,
                _ = self.terminate.recv() => Interrupt::Graceful,
                _ = self.force.recv() => Interrupt::Force,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            Interrupt::Graceful
        }
    }
}

/// Both of a foreground app's pipes, draining to this terminal.
struct TerminalDrains {
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
}

impl TerminalDrains {
    /// Lets the drains finish what the closed pipes still hold, so the app's last lines
    /// are printed before the stop hooks start printing theirs. Bounded, because a
    /// grandchild that inherited the pipe can hold it open long after the app is gone.
    async fn flush(self) {
        let _ = tokio::time::timeout(DRAIN_FLUSH, async {
            let _ = self.stdout.await;
            let _ = self.stderr.await;
        })
        .await;
    }
}

/// How long the app's output is given to finish arriving after the app ends.
const DRAIN_FLUSH: Duration = Duration::from_secs(2);

/// Prints a foreground app's output as it is produced.
fn drain_to_terminal(child: &mut tokio::process::Child) -> Result<TerminalDrains> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Operational("app stdout not piped".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CliError::Operational("app stderr not piped".to_owned()))?;
    Ok(TerminalDrains {
        stdout: tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                println!("{line}");
            }
        }),
        stderr: tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("{line}");
            }
        }),
    })
}

/// The one report an operator reads when a termination sequence has run: what the app's
/// own stop command decided, and how the app ended.
fn report_stop(app: &str, version: &str, outcome: &StopOutcome, settings: &CliSettings) {
    if settings.quiet {
        return;
    }
    match outcome.stop_status {
        StopStatus::Ok => eprintln!("The stop command finished; {app}:{version} was safe to end"),
        StopStatus::Failed => {
            eprintln!("The stop command did not finish cleanly; the stop carried on");
        }
        StopStatus::Timeout => eprintln!("The stop command ran out of time; the stop carried on"),
        StopStatus::Skipped => {}
    }
    match outcome.how {
        StopHow::Graceful => eprintln!("Stopped {app}:{version}"),
        StopHow::Killed => {
            eprintln!("{app}:{version} did not end within its grace period and was killed");
        }
        StopHow::Forced => eprintln!("Ended {app}:{version} immediately, as asked"),
    }
}

async fn load_or_install_for_start(
    args: &StartArgs,
    resolved: &ResolvedReference,
    app: &str,
    version: &str,
    settings: &CliSettings,
    config: &StoredConfig,
) -> Result<InstallPass> {
    // Local records first, and a version line reads against them too: an app that is
    // installed starts even with the registry unreachable or its upstream source down,
    // which is not something a run that installs nothing should depend on. `orc install`
    // stays network-first — it is the command whose job is to go and look.
    if let Some(record) = installed_record_for(app, version, LineAmbiguity::Resolve)? {
        let version = record.version.clone();
        return load_existing_for_start(app, &version, record)
            .map(|installed| InstallPass::Installed(Box::new(installed)));
    }
    let cwd = std::env::current_dir()
        .map_err(|err| CliError::Operational(format!("read current directory: {err}")))?;
    let fresh = install_fresh_app(FreshInstall {
        resolved,
        app,
        version,
        param_args: &args.params,
        force: false,
        settings,
        config,
        base_dir: &cwd,
    })
    .await?;
    match fresh {
        FreshOutcome::Pass(pass) => Ok(pass),
        // The version line resolved onto a version that is already installed: run that,
        // exactly as a caller who named the concrete version would have.
        FreshOutcome::AlreadyInstalled(record) => {
            let version = record.version.clone();
            load_existing_for_start(app, &version, *record)
                .map(|installed| InstallPass::Installed(Box::new(installed)))
        }
    }
}

/// What a command does when a version line names more than one installed version.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LineAmbiguity {
    /// `start` resolves the line the way a registry line resolves: newest, stable
    /// preferred. Starting the wrong one of two installs is recoverable.
    Resolve,
    /// `stop` and `uninstall` refuse and name the candidates. They act on what this
    /// machine already has, one of them destroys it, and picking between two
    /// installs the operator has kept side by side is not theirs to guess.
    Refuse,
}

/// The installed version a request names: that exact version when a record for it exists,
/// otherwise the installed version on the line it names.
///
/// Local records only. `stop` and `uninstall` operate on what this machine has installed
/// and never reach for a registry to read a version line, and `start` consults this before
/// it considers installing anything.
fn installed_record_for(
    app: &str,
    request: &str,
    ambiguity: LineAmbiguity,
) -> Result<Option<InstallRecord>> {
    if let Some(record) = read_install_record(app, request)? {
        return Ok(Some(record));
    }
    let mut records = list_install_records(Some(app))?;
    // Records come off the filesystem in whatever order it listed them, and the shared
    // matcher reads "newest" in the order it is handed. No recipe order exists here, so
    // impose the only one that applies to a machine's own installs.
    records.sort_by(|left, right| discovery::compare_semver_desc(&left.version, &right.version));
    if ambiguity == LineAmbiguity::Refuse {
        let on_line: Vec<&str> = records
            .iter()
            .map(|record| record.version.as_str())
            .filter(|version| discovery::version_line_matches(version, request))
            .collect();
        if on_line.len() > 1 {
            return Err(CliError::Usage(format!(
                "{app}:{request} names {} installed versions ({}); name one exactly",
                on_line.len(),
                on_line.join(", ")
            )));
        }
    }
    let newest = discovery::newest_on_version_line(
        records.iter().map(|record| record.version.as_str()),
        request,
    );
    Ok(newest
        .map(str::to_owned)
        .and_then(|version| records.into_iter().find(|record| record.version == version)))
}

fn load_existing_for_start(
    app: &str,
    version: &str,
    record: InstallRecord,
) -> Result<InstalledApp> {
    let materialized = if record.materialized_dir.is_empty() {
        materialized_app_dir(app, version)?
    } else {
        PathBuf::from(&record.materialized_dir)
    };
    let app_config = read_materialized_app_config(&materialized)?;
    Ok(InstalledApp {
        record,
        app_config,
        materialized,
        files: 0,
    })
}

/// How an installed app runs (spec 142 run modes), resolved from its config and the
/// files it materialized.
///
/// The distinction that matters to every command below is who owns what. In
/// [`RunMode::Subprocess`] the foreground `orc start` owns the process, so no other
/// invocation can end it. In [`RunMode::ManagedService`] this CLI owns the definition and
/// the platform manager owns the process. In [`RunMode::ByoService`] the app's own install
/// phase owns the definition and the CLI only starts and stops what it named.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RunMode {
    /// `command` alone: a foreground child of the `orc start` that ran it.
    Subprocess,
    /// `command` + `service`: the CLI writes the definition and removes it at uninstall.
    ManagedService(String),
    /// `service` alone: the definition belongs to the app's install phase.
    ByoService(String),
}

impl RunMode {
    /// The platform service name, in the two modes that have one.
    fn service_name(&self) -> Option<&str> {
        match self {
            Self::Subprocess => None,
            Self::ManagedService(name) | Self::ByoService(name) => Some(name),
        }
    }
}

/// How this app runs, or `None` when it declares no start at all — an install-only app
/// whose install *is* the whole job.
///
/// The service name is the **platform** name, expanded against this instance's version
/// and params, which is what the manager, `APP_SERVICE`, and `orc status` all speak in.
fn run_mode(
    app: &str,
    version: &str,
    config: &AppConfig,
    work_dir: &Path,
    params: &std::collections::BTreeMap<String, ParsedParam>,
) -> Result<Option<RunMode>> {
    // A packaged `start-{app}` script stands in for an explicit start command, so a
    // package that ships one alongside `service` is asking the CLI to own the definition.
    let command = orc_app::lifecycle::resolve_start_command(app, config, work_dir);
    let Some(name) = orc_app::lifecycle::instance_service_name(config, app, version, params)?
    else {
        return Ok(command.map(|_| RunMode::Subprocess));
    };
    Ok(Some(match command {
        Some(_) => RunMode::ManagedService(name),
        None => RunMode::ByoService(name),
    }))
}

/// The run mode a start may use, with the two shapes the CLI cannot run refused by name.
fn resolve_run_mode(
    app: &str,
    version: &str,
    config: &AppConfig,
    work_dir: &Path,
    params: &std::collections::BTreeMap<String, ParsedParam>,
) -> Result<RunMode> {
    if config.start.as_ref().is_some_and(|start| start.gui) {
        return Err(CliError::Usage(
            "GUI app start is not implemented yet".to_owned(),
        ));
    }
    run_mode(app, version, config, work_dir, params)?.ok_or_else(|| {
        CliError::Operational(format!("{app}:{version} does not define a start command"))
    })
}

/// The platform's service manager, or a refusal naming what is missing.
///
/// A package that declares `start.service` on a platform with no manager is a package
/// that cannot run here, and saying so is the whole of the answer.
fn service_backend(app: &str, version: &str) -> Result<Arc<dyn ServiceBackend>> {
    orc_app::service::backend().map(Arc::from).ok_or_else(|| {
        CliError::Usage(format!(
            "{app}:{version} runs as a service, and no service manager is available on \
             this platform"
        ))
    })
}

/// Where an install's files live: what the record says, or the derived location for a
/// record written before the path was stored.
fn record_work_dir(app: &str, version: &str, record: &InstallRecord) -> Result<PathBuf> {
    if record.materialized_dir.is_empty() {
        materialized_app_dir(app, version)
    } else {
        Ok(PathBuf::from(&record.materialized_dir))
    }
}

/// Everything a stop-side command needs to read off an install record before it acts.
struct StopTarget {
    app: String,
    version: String,
    record: InstallRecord,
    config: AppConfig,
    work_dir: PathBuf,
    params: std::collections::BTreeMap<String, ParsedParam>,
    mode: Option<RunMode>,
}

/// Loads the one install a stop-side reference names, or `None` when it names none.
///
/// Local records only, and a version line that matches several refuses rather than
/// guessing: `stop` and `uninstall` act on what this machine has, and one of them
/// destroys it.
fn stop_target(app: &str, request: &str) -> Result<Option<StopTarget>> {
    let Some(record) = installed_record_for(app, request, LineAmbiguity::Refuse)? else {
        return Ok(None);
    };
    let version = record.version.clone();
    let work_dir = record_work_dir(app, &version, &record)?;
    let config = read_materialized_app_config(&work_dir)?;
    let params = parsed_from_record(&record.params, config.params.as_ref());
    let mode = run_mode(app, &version, &config, &work_dir, &params)?;
    Ok(Some(StopTarget {
        app: app.to_owned(),
        version,
        record,
        config,
        work_dir,
        params,
        mode,
    }))
}

async fn stop(args: &AppArg, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let resolved = resolve_app_reference(
        &args.app,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    let app = app_name_from_repository(&resolved.repository)?;
    // Idempotent for scripting: an app this machine never installed, and an app that is
    // not running, are both a notice and a success, not a failure to act on.
    let Some(target) = stop_target(&app, &resolved.tag)? else {
        if !settings.quiet {
            eprintln!("{app}:{} is not installed", resolved.tag);
        }
        return Ok(());
    };
    let version = target.version.clone();
    if is_not_running_state(&target.record.state) {
        if !settings.quiet {
            eprintln!("{app}:{version} is not running");
        }
        return Ok(());
    }
    match target.mode.as_ref().and_then(RunMode::service_name) {
        Some(name) => {
            let name = name.to_owned();
            let backend = service_backend(&app, &version)?;
            let state_dir = orc_app::state::state_dir()?;
            let stopped = stop_service(
                &target,
                &name,
                StopReason::Stop,
                args.force,
                settings,
                &backend,
                &state_dir,
            )
            .await?;
            write_install_record(&stopped)
        }
        None => stop_subprocess(&app, target, args.force, settings).await,
    }
}

/// Ends a service app here, in this process: the manager holds the app, so the whole
/// termination sequence — the stop command, the manager's stop, the grace period, the
/// kill, the stopped hook — can run wherever the operator typed the command.
///
/// Returns the record as it now stands, recorded stopped.
async fn stop_service(
    target: &StopTarget,
    name: &str,
    reason: StopReason,
    force: bool,
    settings: &CliSettings,
    backend: &Arc<dyn ServiceBackend>,
    state_dir: &Path,
) -> Result<InstallRecord> {
    let (app, version) = (target.app.as_str(), target.version.as_str());
    let mut record = target.record.clone();
    let status = backend.status(name).await?;
    if status.state.is_terminal() {
        if !settings.quiet {
            eprintln!("The service {name} is already {}", status.state);
        }
        mark_stopped(&mut record);
        return Ok(record);
    }

    let ctx = AppContext {
        app,
        instance: app,
        version,
        config: &target.config,
        params: &target.params,
        work_dir: &target.work_dir,
        state_dir,
        secrets: None,
        log_line: terminal_log_line(),
    };
    let mut process = AppProcess::service(
        Arc::clone(backend),
        name.to_owned(),
        Instant::now(),
        status.main_pid,
    );
    // A forced stop starts with the token already spent: the sequence reads that as "do
    // not wait" and goes straight to the kill.
    let token = CancellationToken::new();
    if force {
        token.cancel();
    }
    if !settings.quiet {
        eprintln!("Stopping {app}:{version} (service {name})");
        if force {
            eprintln!("Ending it now: the stop command and the grace period are skipped");
        } else if target
            .config
            .stop
            .as_ref()
            .is_some_and(|stop| stop.command.is_some())
        {
            eprintln!("Running the stop command while the app is still up");
        }
    }
    let outcome = stop_sequence(&ctx, &mut process, reason, &token).await;
    report_stop(app, version, &outcome, settings);
    run_stopped_phase(
        &ctx,
        StoppedReason::Stopped(reason),
        outcome.stop_status,
        &outcome.exit,
        force.then_some(FORCED_STOPPED_TIMEOUT),
    )
    .await;
    mark_stopped(&mut record);
    Ok(record)
}

/// Asks the foreground `orc start` supervising this app to stop it.
///
/// The sequence itself belongs to that process — it is the one holding the child — so
/// this is a request and then a wait, never a kill of its own. A recorded pid that is no
/// longer that supervisor is reported and reconciled rather than signalled: the number
/// may since have been handed to somebody else's process.
async fn stop_subprocess(
    app: &str,
    target: StopTarget,
    force: bool,
    settings: &CliSettings,
) -> Result<()> {
    let version = target.version.clone();
    let mut record = target.record;
    let recorded = record
        .pid_service
        .as_deref()
        .and_then(|pid| pid.parse::<u32>().ok());
    if supervisor::supervision(&target.work_dir, recorded) == supervisor::Supervision::Gone {
        supervisor::clear(&target.work_dir);
        record_stopped(&mut record)?;
        if !settings.quiet {
            match recorded {
                Some(pid) => eprintln!(
                    "{app}:{version} is recorded as running, but the process that was \
                     supervising it (pid {pid}) is gone; nothing was signalled and it is \
                     now recorded as stopped"
                ),
                None => eprintln!(
                    "{app}:{version} is recorded as running, but no supervising process was \
                     recorded; nothing was signalled and it is now recorded as stopped"
                ),
            }
        }
        return Ok(());
    }
    ask_supervisor(
        app,
        &version,
        &target.config,
        &target.work_dir,
        record,
        force,
        settings,
    )
    .await
}

/// Signals the verified supervisor and waits for it to finish the sequence it owns.
#[cfg(unix)]
async fn ask_supervisor(
    app: &str,
    version: &str,
    config: &AppConfig,
    work_dir: &Path,
    mut record: InstallRecord,
    force: bool,
    settings: &CliSettings,
) -> Result<()> {
    let supervisor::Supervision::Live(pid) = supervisor::supervision(
        work_dir,
        record
            .pid_service
            .as_deref()
            .and_then(|pid| pid.parse::<u32>().ok()),
    ) else {
        return Err(CliError::Operational(format!(
            "{app}:{version} lost its supervisor while it was being stopped"
        )));
    };
    supervisor::ask_to_stop(pid, force)?;
    if !settings.quiet {
        if force {
            eprintln!(
                "Asked the supervisor of {app}:{version} (pid {pid}) to end it now, \
                 skipping the stop command and the grace period"
            );
        } else {
            eprintln!("Asked the supervisor of {app}:{version} (pid {pid}) to stop it");
        }
    }
    // The supervisor prints the sequence on its own terminal; what is left here is to
    // wait for it, bounded by exactly the time that sequence is allowed to take.
    let budget = orc_app::lifecycle::stop_budget(app, config, work_dir) + SUPERVISOR_MARGIN;
    let deadline = Instant::now() + budget;
    while supervisor::alive(pid) {
        if Instant::now() >= deadline {
            return Err(CliError::Operational(format!(
                "{app}:{version} has not stopped within {}s; its supervisor (pid {pid}) is \
                 still running",
                budget.as_secs()
            )));
        }
        tokio::time::sleep(SUPERVISOR_POLL).await;
    }
    supervisor::clear(work_dir);
    // The supervisor records the stop itself as it leaves; this reconciles the record
    // only where it could not — a supervisor that was killed rather than asked.
    if let Ok(Some(current)) = read_install_record(app, version) {
        record = current;
    }
    if !is_not_running_state(&record.state) {
        record_stopped(&mut record)?;
    }
    if !settings.quiet {
        eprintln!("Stopped {app}:{version}");
    }
    Ok(())
}

/// Windows has no signal a second process can send a supervisor, so a foreground app is
/// stopped where it runs.
#[cfg(not(unix))]
#[allow(
    clippy::unused_async,
    reason = "the Unix path awaits the supervisor; the call reads the same on both"
)]
async fn ask_supervisor(
    app: &str,
    version: &str,
    _config: &AppConfig,
    _work_dir: &Path,
    _record: InstallRecord,
    _force: bool,
    _settings: &CliSettings,
) -> Result<()> {
    Err(CliError::Conflict(format!(
        "{app}:{version} runs in the foreground and this platform has no way to ask its \
         supervisor to stop; interrupt it where it runs"
    )))
}

/// How long past an app's own stop budget the supervisor is given to finish and record it.
#[cfg(unix)]
const SUPERVISOR_MARGIN: Duration = Duration::from_secs(5);

/// How often a waiting stop looks at whether the supervisor has finished. There is no
/// event to wait on: the supervisor belongs to another session, not to this process.
#[cfg(unix)]
const SUPERVISOR_POLL: Duration = Duration::from_millis(100);

/// Reads an install as stopped, with nothing left running to name. Pure: the commands
/// that end an app decide for themselves when that becomes what is on disk.
fn mark_stopped(record: &mut InstallRecord) {
    "stopped".clone_into(&mut record.state);
    record.pid_service = None;
}

/// The same, persisted.
fn record_stopped(record: &mut InstallRecord) -> Result<()> {
    mark_stopped(record);
    write_install_record(record)
}

/// Removes a service definition this CLI wrote, and the environment it persisted for it.
///
/// Always, on every uninstall of a runtime-managed app: a definition left behind after
/// its app is gone is a unit naming a work directory that no longer exists.
async fn remove_managed_definition(
    name: &str,
    work_dir: &Path,
    backend: &dyn ServiceBackend,
    settings: &CliSettings,
) -> Result<()> {
    backend.undefine(name).await?;
    orc_app::lifecycle::remove_app_env(work_dir);
    if !settings.quiet {
        eprintln!("Removed the service definition {name}");
    }
    Ok(())
}

async fn uninstall(args: AppArg, settings: &CliSettings, config: &StoredConfig) -> Result<()> {
    let resolved = resolve_app_reference(
        &args.app,
        config.default_prefix(),
        settings.registry.as_deref(),
    )?;
    let app = app_name_from_repository(&resolved.repository)?;
    let Some(mut target) = stop_target(&app, &resolved.tag)? else {
        if !settings.quiet {
            eprintln!("{app}:{} is not installed", resolved.tag);
        }
        return Ok(());
    };
    // What a version line uninstalls is the install it resolved to, all of it: the files,
    // the record, and the app's own uninstall phase in between.
    let version = target.version.clone();
    if !is_not_running_state(&target.record.state) {
        match target.mode.as_ref().and_then(RunMode::service_name) {
            // The manager holds the app, so this process can end it and carry on.
            Some(name) => {
                let name = name.to_owned();
                let backend = service_backend(&app, &version)?;
                let state_dir = orc_app::state::state_dir()?;
                target.record = stop_service(
                    &target,
                    &name,
                    StopReason::Terminate,
                    args.force,
                    settings,
                    &backend,
                    &state_dir,
                )
                .await?;
                // Persisted before the uninstall phase runs: an uninstall that fails
                // half way leaves a record a retry can read, and the app is stopped.
                write_install_record(&target.record)?;
            }
            // A foreground app belongs to the process supervising it, and that is not
            // this one: removing the files under a running app is not an uninstall.
            None => {
                return Err(CliError::Conflict(format!(
                    "{app}:{version} is {}; stop it before uninstall",
                    target.record.state
                )));
            }
        }
    }
    // A definition this CLI wrote is this CLI's to remove, whether or not the app was
    // running when the uninstall arrived. A bring-your-own definition is removed by the
    // app's own uninstall phase, below.
    if let Some(RunMode::ManagedService(name)) = &target.mode {
        match orc_app::service::backend() {
            Some(backend) => {
                remove_managed_definition(name, &target.work_dir, backend.as_ref(), settings)
                    .await?;
            }
            // No manager here means no definition was ever written here either, so the
            // uninstall carries on rather than stranding the app it can still remove.
            None => orc_app::lifecycle::remove_app_env(&target.work_dir),
        }
    }

    let _ = run_uninstall_phase(
        &app,
        &app,
        &version,
        &target.config,
        &target.record.params,
        &target.work_dir,
        terminal_log_line(),
        None,
    )
    .await?;
    if target.work_dir.exists() {
        std::fs::remove_dir_all(&target.work_dir).map_err(|err| {
            CliError::Operational(format!("remove {}: {err}", target.work_dir.display()))
        })?;
    }
    remove_install_record(&app, &version)?;
    if !settings.quiet {
        eprintln!("Uninstalled {app}:{version}");
    }
    Ok(())
}

fn is_not_running_state(state: &str) -> bool {
    matches!(state, "stopped" | "completed" | "failed")
}

fn read_materialized_app_config(materialized: &std::path::Path) -> Result<AppConfig> {
    let path = materialized.join("app.config.v1.json");
    let bytes = std::fs::read(&path)
        .map_err(|err| CliError::Operational(format!("read {}: {err}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| CliError::Operational(format!("decode {}: {err}", path.display())))
}

fn status(args: &StatusArgs) -> Result<()> {
    let records = list_install_records(args.app.as_deref())?;
    print_status(&records, args.output)?;
    report_pending_install(args.app.as_deref());
    Ok(())
}

/// Names an installation that is waiting for a reboot, which no install record can show:
/// it is deliberately not recorded until its phase converges. A note on stderr, so the
/// table (and `--format json`) stays exactly the list of installed apps.
fn report_pending_install(app_filter: Option<&str>) {
    // Reads the state dir rather than creating it: reporting must not be the thing that
    // brings a directory into existence.
    let Ok(Some(marker)) = orc_app::state::state_dir().and_then(|dir| resume::read(&dir)) else {
        return;
    };
    if app_filter.is_some_and(|filter| filter != marker.record.app) {
        return;
    }
    eprintln!(
        "note: {}:{} is {} — it continues automatically at the next boot, \
         or run `orc install --resume`",
        marker.record.app,
        marker.record.version,
        resume::PENDING_STATE
    );
}

fn app_name_from_repository(repository: &str) -> Result<String> {
    repository
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| CliError::Usage(format!("invalid app repository {repository:?}")))
}

/// How an app will run, and what its run will be called, as the install record says it.
///
/// The recorded name is the **platform** service name — what an operator types at their
/// service manager — not the OS-agnostic identifier the package declared. A name the
/// runtime cannot derive yet (an identifier naming a param this install did not set)
/// falls back to the declared one: the record is a report, and it is better slightly
/// less precise than absent.
fn install_record_mode(
    app: &str,
    version: &str,
    config: &AppConfig,
    params: &std::collections::BTreeMap<String, ParsedParam>,
) -> (String, Option<String>) {
    let Some(declared) = config
        .start
        .as_ref()
        .and_then(|start| start.service.as_ref())
    else {
        return ("process".to_owned(), None);
    };
    let derived = orc_app::lifecycle::instance_service_name(config, app, version, params)
        .ok()
        .flatten()
        .unwrap_or_else(|| declared.clone());
    ("service".to_owned(), Some(derived))
}

fn config_command(args: ConfigArgs, config: &mut StoredConfig) -> Result<()> {
    match args.command {
        ConfigCommand::Get { key } => match config.config_value(&key) {
            Some(value) => {
                println!("{value}");
                Ok(())
            }
            None => Err(CliError::Usage(format!("unknown config key {key:?}"))),
        },
        ConfigCommand::Set { key, value } => {
            config.set_config_value(&key, value)?;
            config.save()
        }
    }
}

fn cache_command(args: &CacheArgs) -> Result<()> {
    match args.command {
        CacheCommand::Ls => {
            let stats = crate::local_artifact_store::stats()?;
            crate::local_artifact_store::print_stats(&stats);
            Ok(())
        }
        CacheCommand::Clean { unused } => {
            let stats = if unused {
                crate::local_artifact_store::clean_unused(&installed_blob_digests()?)?
            } else {
                crate::local_artifact_store::clean_all()?
            };
            crate::local_artifact_store::print_cleaned(&stats);
            Ok(())
        }
    }
}

fn installed_blob_digests() -> Result<BTreeSet<String>> {
    Ok(list_install_records(None)?
        .into_iter()
        .flat_map(|record| record.blob_digests)
        .collect())
}

fn registry_client(
    registry: &str,
    config: &StoredConfig,
    insecure: bool,
) -> Result<RegistryClient> {
    RegistryClient::new(registry, config.credential_for(registry), insecure)
}

/// Attaches the progress reporter to a registry client when one is active, so
/// every blob transfer reports automatically. A no-op when progress is off.
fn with_progress(client: RegistryClient, reporter: Option<&Arc<CliProgress>>) -> RegistryClient {
    match reporter {
        Some(reporter) => client.with_progress(reporter.clone()),
        None => client,
    }
}

/// Emits a blob-keyed progress event for the CLI-local cache paths (which do
/// not flow through the SDK's `pull` orchestration).
fn report_blob(reporter: Option<&dyn ProgressReporter>, digest: &str, phase: ProgressPhase) {
    if let Some(reporter) = reporter {
        reporter.report(ProgressEvent::new(digest, ProgressKind::Blob, phase));
    }
}

fn single_platform(settings: &CliSettings) -> Result<Option<&str>> {
    match settings.platform.as_slice() {
        [] => Ok(None),
        [platform] => Ok(Some(platform.as_str())),
        _ => Err(CliError::Usage(
            "only `orc build` accepts multiple --platform values".to_owned(),
        )),
    }
}

fn join_repo(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_owned()
    } else {
        format!("{namespace}/{name}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPushReference {
    registry: String,
    repository: String,
    tags: Vec<String>,
    full: String,
}

fn resolve_push_reference(
    input: &str,
    default_prefix: &str,
    override_prefix: Option<&str>,
) -> Result<ResolvedPushReference> {
    let input = input.trim();
    if input.is_empty() {
        return Err(CliError::Usage("push reference cannot be empty".to_owned()));
    }
    let (path, tag_list) = split_tag_list(input);
    let app = resolve_app_reference(path, default_prefix, override_prefix)?;
    let mut tags = Vec::new();
    for tag in tag_list.unwrap_or("default").split(',') {
        if !valid_tag(tag) {
            return Err(CliError::Usage(format!("invalid tag {tag:?}")));
        }
        if !tags.iter().any(|known| known == tag) {
            tags.push(tag.to_owned());
        }
    }
    let full = format!("{}/{}:{}", app.registry, app.repository, tags.join(","));
    Ok(ResolvedPushReference {
        registry: app.registry,
        repository: app.repository,
        tags,
        full,
    })
}

fn split_tag_list(input: &str) -> (&str, Option<&str>) {
    let last_slash = input.rfind('/');
    let last_colon = input.rfind(':');
    match (last_slash, last_colon) {
        (_, Some(colon)) if last_slash.is_none_or(|slash| colon > slash) => {
            (&input[..colon], Some(&input[colon + 1..]))
        }
        _ => (input, None),
    }
}

fn valid_tag(tag: &str) -> bool {
    crate::reference::is_valid_tag(tag)
}

fn parse_platform_label(label: &str) -> Result<Platform> {
    let parts = label.split('/').collect::<Vec<_>>();
    let ([os, architecture] | [os, architecture, _]) = parts.as_slice() else {
        return Err(CliError::Usage(format!(
            "platform {label:?} must be os/arch or os/arch/variant"
        )));
    };
    if parts
        .iter()
        .any(|part| part.is_empty() || part.contains(' '))
    {
        return Err(CliError::Usage(format!("invalid platform {label:?}")));
    }
    Ok(Platform {
        os: (*os).to_owned(),
        architecture: (*architecture).to_owned(),
        variant: parts.get(2).copied().unwrap_or_default().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_repo_keeps_empty_namespace_clean() {
        assert_eq!(join_repo("", "app"), "app");
        assert_eq!(join_repo("admte", "app"), "admte/app");
    }

    #[test]
    fn login_default_prefix_skips_the_builtin_default() {
        let builtin = resolve_prefix(Some(BUILTIN_DEFAULT_PREFIX), None).expect("prefix");
        assert_eq!(login_default_prefix(&builtin), None);

        let namespaced = resolve_prefix(Some("orc8r.com/admte"), None).expect("prefix");
        assert_eq!(
            login_default_prefix(&namespaced).as_deref(),
            Some("orc8r.com/admte")
        );

        let custom_host = resolve_prefix(Some("localhost:5000"), None).expect("prefix");
        assert_eq!(
            login_default_prefix(&custom_host).as_deref(),
            Some("localhost:5000")
        );
    }

    #[test]
    fn push_reference_resolves_and_deduplicates_tags() {
        let resolved =
            resolve_push_reference("runner:1.0,latest,1.0", "ghcr.io/acme", None).expect("ref");
        assert_eq!(resolved.registry, "ghcr.io");
        assert_eq!(resolved.repository, "acme/runner");
        assert_eq!(resolved.tags, ["1.0", "latest"]);
        assert_eq!(resolved.full, "ghcr.io/acme/runner:1.0,latest");
    }

    #[test]
    fn push_reference_defaults_missing_tag_to_default() {
        let resolved = resolve_push_reference("runner", "localhost:5000/dev", None).expect("ref");
        assert_eq!(resolved.full, "localhost:5000/dev/runner:default");
        assert_eq!(resolved.tags, ["default"]);
    }

    #[test]
    fn push_reference_rejects_empty_or_invalid_tags() {
        assert!(resolve_push_reference("runner:1.0,", "ghcr.io/acme", None).is_err());
        assert!(resolve_push_reference("runner:-bad", "ghcr.io/acme", None).is_err());
    }

    #[test]
    fn platform_labels_parse_os_arch_and_variant() {
        assert_eq!(
            parse_platform_label("linux/amd64").expect("platform"),
            Platform {
                os: "linux".to_owned(),
                architecture: "amd64".to_owned(),
                variant: String::new(),
            }
        );
        assert_eq!(
            parse_platform_label("linux/arm/v7")
                .expect("platform")
                .label(),
            "linux/arm/v7"
        );
        assert!(parse_platform_label("linux").is_err());
        assert!(parse_platform_label("linux//amd64").is_err());
        assert!(parse_platform_label("linux/amd64/too/many").is_err());
    }

    #[test]
    fn push_format_is_explicit_only_when_the_operator_names_one() {
        let args = |format, chunker| PushArgs {
            chunker,
            format,
            zstd_level: None,
            no_compress: false,
            reference: "runner".to_owned(),
            paths: vec![PathBuf::from("app.config.v1.json")],
        };

        let capable_default = push_package_options(&args(None, None), true);
        assert_eq!(capable_default.format, PackageFormat::ChunkedZstd);
        assert!(!capable_default.explicit_format);

        let plain_default = push_package_options(&args(None, None), false);
        assert_eq!(plain_default.format, PackageFormat::Plain);
        assert!(!plain_default.explicit_format);

        let forced = push_package_options(&args(Some(PushFormat::ChunkedZstd), None), true);
        assert_eq!(forced.format, PackageFormat::ChunkedZstd);
        assert!(forced.explicit_format);

        let legacy = push_package_options(&args(None, Some(PushChunker::None)), true);
        assert_eq!(legacy.format, PackageFormat::Plain);
        assert!(legacy.explicit_format);
    }

    #[test]
    fn terminal_install_states_are_not_running() {
        assert!(is_not_running_state("stopped"));
        assert!(is_not_running_state("completed"));
        assert!(is_not_running_state("failed"));
        assert!(!is_not_running_state("running"));
    }

    // ─── run modes and the service manager ──────────────────────────────────────

    use orc_app::service::{ServiceSpec, ServiceState, ServiceStatus};

    /// A service manager that records what it was asked to do and answers the way a real
    /// one would, without a machine having to have one.
    struct FakeManager {
        calls: std::sync::Mutex<Vec<String>>,
        states: tokio::sync::watch::Sender<ServiceStatus>,
    }

    impl FakeManager {
        fn running() -> Arc<Self> {
            let (states, _) = tokio::sync::watch::channel(ServiceStatus {
                state: ServiceState::Active,
                main_pid: Some(4242),
                ..ServiceStatus::default()
            });
            Arc::new(Self {
                calls: std::sync::Mutex::new(Vec::new()),
                states,
            })
        }

        fn record(&self, call: &str) {
            self.calls.lock().expect("calls").push(call.to_owned());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls").clone()
        }

        /// What a manager does once it has been asked to stop: the app ends, and the
        /// watch is how the runtime is told.
        fn report_stopped(&self) {
            let _ = self.states.send(ServiceStatus {
                state: ServiceState::Inactive,
                main_pid: None,
                exit_code: Some(0),
                ..ServiceStatus::default()
            });
        }
    }

    #[async_trait::async_trait]
    impl ServiceBackend for FakeManager {
        fn platform_name(&self, name: &str) -> String {
            orc_app::service::platform_name(name)
        }

        async fn define(&self, spec: &ServiceSpec) -> Result<()> {
            self.record(&format!("define:{}", spec.name));
            Ok(())
        }

        async fn undefine(&self, name: &str) -> Result<()> {
            self.record(&format!("undefine:{name}"));
            Ok(())
        }

        async fn start(&self, name: &str) -> Result<()> {
            self.record(&format!("start:{name}"));
            Ok(())
        }

        async fn stop(&self, name: &str) -> Result<()> {
            self.record(&format!("stop:{name}"));
            self.report_stopped();
            Ok(())
        }

        async fn kill(&self, name: &str) -> Result<()> {
            self.record(&format!("kill:{name}"));
            self.report_stopped();
            Ok(())
        }

        async fn status(&self, name: &str) -> Result<ServiceStatus> {
            self.record(&format!("status:{name}"));
            Ok(*self.states.borrow())
        }

        fn watch(&self, name: &str) -> futures_util::stream::BoxStream<'static, ServiceStatus> {
            self.record(&format!("watch:{name}"));
            let receiver = self.states.subscribe();
            Box::pin(futures_util::stream::unfold(
                receiver,
                |mut receiver| async move {
                    receiver.changed().await.ok()?;
                    let status = *receiver.borrow_and_update();
                    Some((status, receiver))
                },
            ))
        }
    }

    fn quiet_settings() -> CliSettings {
        CliSettings {
            insecure: false,
            platform: Vec::new(),
            registry: None,
            quiet: true,
        }
    }

    fn app_config(value: serde_json::Value) -> AppConfig {
        serde_json::from_value(value).expect("app config")
    }

    fn seeded_record(app: &str, version: &str, work_dir: &Path) -> InstallRecord {
        InstallRecord {
            app: app.to_owned(),
            version: version.to_owned(),
            reference: format!("ghcr.io/acme/{app}:{version}"),
            digest: "sha256:abc".to_owned(),
            platform: "linux/amd64".to_owned(),
            mode: "service".to_owned(),
            state: "stopped".to_owned(),
            pid_service: None,
            params: std::collections::BTreeMap::new(),
            blob_digests: Vec::new(),
            materialized_dir: work_dir.display().to_string(),
        }
    }

    /// The three shapes `start` can take, read off one config each. The service name is
    /// the platform's, expanded against this instance — two versions of one app can be
    /// installed side by side, and each has to name its own service.
    #[test]
    fn run_mode_reads_the_three_start_shapes() {
        let work = tempfile::tempdir().expect("work dir");
        let params = std::collections::BTreeMap::new();

        let subprocess = app_config(serde_json::json!({"start": {"command": "./run.sh"}}));
        assert_eq!(
            run_mode("demo", "1.0", &subprocess, work.path(), &params).expect("mode"),
            Some(RunMode::Subprocess)
        );

        let managed = app_config(
            serde_json::json!({"start": {"command": "./run.sh", "service": "demo-${APP_VERSION}"}}),
        );
        assert_eq!(
            run_mode("demo", "1.0", &managed, work.path(), &params).expect("mode"),
            Some(RunMode::ManagedService(orc_app::service::platform_name(
                "demo-1.0"
            )))
        );

        let bring_your_own = app_config(serde_json::json!({"start": {"service": "demo"}}));
        assert_eq!(
            run_mode("demo", "1.0", &bring_your_own, work.path(), &params).expect("mode"),
            Some(RunMode::ByoService(orc_app::service::platform_name("demo")))
        );

        let install_only = app_config(serde_json::json!({"install": {"command": "./setup.sh"}}));
        assert_eq!(
            run_mode("demo", "1.0", &install_only, work.path(), &params).expect("mode"),
            None
        );
    }

    /// A managed service start writes the definition and the environment behind it, asks
    /// the manager to start it, and returns — the app outlives this process, which is the
    /// whole point of service mode.
    #[tokio::test]
    async fn starting_a_managed_service_defines_it_and_returns() {
        let work = tempfile::tempdir().expect("work dir");
        let config = app_config(
            serde_json::json!({"start": {"command": "./run.sh", "service": "demo"}, "stop": {}}),
        );
        let installed = InstalledApp {
            record: seeded_record("demo", "1.0", work.path()),
            app_config: config,
            materialized: work.path().to_path_buf(),
            files: 0,
        };
        let params = std::collections::BTreeMap::new();
        let mode = run_mode("demo", "1.0", &installed.app_config, work.path(), &params)
            .expect("mode")
            .expect("a start mode");
        let manager = FakeManager::running();

        let record = start_service(
            "demo",
            &mode,
            &installed,
            &params,
            &quiet_settings(),
            manager.as_ref(),
        )
        .await
        .expect("start the service");

        let name = orc_app::service::platform_name("demo");
        assert_eq!(
            manager.calls(),
            vec![format!("define:{name}"), format!("start:{name}")]
        );
        assert_eq!(record.state, "running");
        assert_eq!(record.mode, "service");
        assert_eq!(record.pid_service.as_deref(), Some(name.as_str()));
        assert!(
            orc_app::lifecycle::app_env_path(work.path()).exists(),
            "the shim's environment is persisted at start"
        );
    }

    /// A bring-your-own definition belongs to the app's own install phase: the CLI starts
    /// what the app registered and writes nothing of its own.
    #[tokio::test]
    async fn starting_a_bring_your_own_service_only_starts_it() {
        let work = tempfile::tempdir().expect("work dir");
        let installed = InstalledApp {
            record: seeded_record("demo", "1.0", work.path()),
            app_config: app_config(serde_json::json!({"start": {"service": "demo"}})),
            materialized: work.path().to_path_buf(),
            files: 0,
        };
        let params = std::collections::BTreeMap::new();
        let mode = run_mode("demo", "1.0", &installed.app_config, work.path(), &params)
            .expect("mode")
            .expect("a start mode");
        let manager = FakeManager::running();

        start_service(
            "demo",
            &mode,
            &installed,
            &params,
            &quiet_settings(),
            manager.as_ref(),
        )
        .await
        .expect("start the service");

        assert_eq!(
            manager.calls(),
            vec![format!("start:{}", orc_app::service::platform_name("demo"))]
        );
        assert!(
            !orc_app::lifecycle::app_env_path(work.path()).exists(),
            "nothing is persisted for a definition this CLI does not own"
        );
    }

    /// The stop of a service app runs here, in the process the operator typed it in: the
    /// app's stop command while it is still up, the manager's stop, then the stopped hook
    /// told how it went.
    #[tokio::test]
    async fn stopping_a_service_runs_the_sequence_where_the_operator_asked() {
        let (target, name) = stop_fixture();
        let manager = FakeManager::running();
        let backend: Arc<dyn ServiceBackend> = Arc::clone(&manager) as Arc<dyn ServiceBackend>;
        let state = tempfile::tempdir().expect("state dir");

        let record = stop_service(
            &target,
            &name,
            StopReason::Stop,
            false,
            &quiet_settings(),
            &backend,
            state.path(),
        )
        .await
        .expect("stop the service");

        assert!(
            manager.calls().contains(&format!("stop:{name}")),
            "{:?}",
            manager.calls()
        );
        assert!(
            !manager.calls().contains(&format!("kill:{name}")),
            "a graceful stop never reaches the kill"
        );
        assert_eq!(steps(&target.work_dir), "stop\nstopped:ok\n");
        assert_eq!(record.state, "stopped");
        assert_eq!(record.pid_service, None);
    }

    /// `--force` skips the ask entirely: no stop command, no manager stop, and the
    /// stopped hook is told the stop command decided nothing.
    #[tokio::test]
    async fn forcing_a_service_stop_goes_straight_to_the_kill() {
        let (target, name) = stop_fixture();
        let manager = FakeManager::running();
        let backend: Arc<dyn ServiceBackend> = Arc::clone(&manager) as Arc<dyn ServiceBackend>;
        let state = tempfile::tempdir().expect("state dir");

        stop_service(
            &target,
            &name,
            StopReason::Stop,
            true,
            &quiet_settings(),
            &backend,
            state.path(),
        )
        .await
        .expect("stop the service");

        assert!(
            manager.calls().contains(&format!("kill:{name}")),
            "{:?}",
            manager.calls()
        );
        assert!(
            !manager.calls().contains(&format!("stop:{name}")),
            "a forced stop does not ask first"
        );
        assert_eq!(steps(&target.work_dir), "stopped:skipped\n");
    }

    /// A definition this CLI wrote is this CLI's to remove, and the environment it
    /// persisted for the shim goes with it.
    #[tokio::test]
    async fn uninstalling_a_managed_service_removes_the_definition() {
        let work = tempfile::tempdir().expect("work dir");
        orc_app::lifecycle::write_app_env(
            work.path(),
            &AppEnv {
                app: "demo".to_owned(),
                instance: "demo".to_owned(),
                version: "1.0".to_owned(),
                params: std::collections::BTreeMap::new(),
                persist_state: None,
            },
        )
        .expect("write the app environment");
        let manager = FakeManager::running();
        let name = orc_app::service::platform_name("demo");

        remove_managed_definition(&name, work.path(), manager.as_ref(), &quiet_settings())
            .await
            .expect("remove the definition");

        assert_eq!(manager.calls(), vec![format!("undefine:{name}")]);
        assert!(!orc_app::lifecycle::app_env_path(work.path()).exists());
    }

    /// One running managed-service install, with hooks that write down what ran.
    fn stop_fixture() -> (StopTarget, String) {
        let work = tempfile::tempdir().expect("work dir");
        // The directory outlives the test through the target it is handed to; the
        // fixture keeps its own copy of the path rather than the handle.
        let work_dir = work.keep();
        let (stop, stopped) = if cfg!(windows) {
            (
                "[IO.File]::AppendAllText((Join-Path $PWD 'steps.txt'), \"stop`n\")",
                "[IO.File]::AppendAllText((Join-Path $PWD 'steps.txt'), \"stopped:$env:APP_STOP_STATUS`n\")",
            )
        } else {
            (
                "printf 'stop\\n' >> steps.txt",
                "printf \"stopped:$APP_STOP_STATUS\\n\" >> steps.txt",
            )
        };
        let config = app_config(serde_json::json!({
            "start": {"command": "./run.sh", "service": "demo"},
            "stop": {"command": stop, "timeout": "10s", "grace": "5s"},
            "stopped": {"command": stopped}
        }));
        let params = std::collections::BTreeMap::new();
        let mode = run_mode("demo", "1.0", &config, &work_dir, &params)
            .expect("mode")
            .expect("a start mode");
        let name = mode.service_name().expect("a service name").to_owned();
        let mut record = seeded_record("demo", "1.0", &work_dir);
        "running".clone_into(&mut record.state);
        record.pid_service = Some(name.clone());
        (
            StopTarget {
                app: "demo".to_owned(),
                version: "1.0".to_owned(),
                record,
                config,
                work_dir,
                params,
                mode: Some(mode),
            },
            name,
        )
    }

    fn steps(work_dir: &Path) -> String {
        std::fs::read_to_string(work_dir.join("steps.txt")).unwrap_or_default()
    }
}
