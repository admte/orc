use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::any;
use serde_json::json;
use sha2::{Digest as _, Sha256};

/// Every request's `Authorization` header, keyed by path.
type Authorizations = Arc<Mutex<Vec<(String, Option<String>)>>>;

const APP_ARTIFACT_TYPE: &str = "application/vnd.orc8r.app.v1";
const APP_CONFIG_MEDIA_TYPE: &str = "application/vnd.orc8r.app.config.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_filters_catalog_to_orc_apps_and_enriches_metadata() {
    let config = app_config(&json!({"default_version": "3.46"}));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "Jenkins Swarm agent");
    let non_orc = non_orc_manifest();

    let server = MockServer::start(BTreeMap::from([
        (
            "/v2/_catalog".to_owned(),
            MockResponse::json(&json!({
                "repositories": ["admte/jenkins-agent", "admte/plain-container"]
            })),
        ),
        (
            "/v2/admte/jenkins-agent/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/admte/jenkins-agent/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        (
            "/v2/admte/plain-container/manifests/default".to_owned(),
            MockResponse::manifest(non_orc),
        ),
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/admte", server.registry()),
            "search",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc search");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows.as_array().expect("array").len(), 1);
    assert_eq!(rows[0]["name"], "jenkins-agent");
    assert_eq!(rows[0]["default"], "3.46");
    assert_eq!(rows[0]["description"], "Jenkins Swarm agent");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains(&format!("Resolved prefix: {}/admte", server.registry()))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_skips_repos_without_default_tag() {
    let config = app_config(&json!({"default_version": "3.46"}));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "Jenkins Swarm agent");

    // ubuntu is in the catalog but has no default tag — mock returns 404 for its manifest
    let server = MockServer::start(BTreeMap::from([
        (
            "/v2/_catalog".to_owned(),
            MockResponse::json(&json!({
                "repositories": ["admte/jenkins-agent", "admte/ubuntu"]
            })),
        ),
        (
            "/v2/admte/jenkins-agent/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/admte/jenkins-agent/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        // no route for /v2/admte/ubuntu/manifests/default → mock returns 404
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/admte", server.registry()),
            "search",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc search");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows.as_array().expect("array").len(), 1);
    assert_eq!(rows[0]["name"], "jenkins-agent");
    server.assert_requested("/v2/admte/ubuntu/manifests/default");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_token_exchange_for_public_repo() {
    let config_dir = tempfile::tempdir().expect("config dir");
    let config = app_config(&json!({"default_version": "1.0"}));
    let config_digest = digest_bytes(&config);
    let server = MockServer::start_with_token_auth(
        BTreeMap::from([
            (
                "/v2/_catalog".to_owned(),
                MockResponse::json(&json!({"repositories": ["acme/public-app"]})),
            ),
            (
                "/v2/acme/public-app/manifests/default".to_owned(),
                MockResponse::manifest(app_manifest(&config, "Public app")),
            ),
            (
                format!("/v2/acme/public-app/blobs/{config_digest}"),
                MockResponse::bytes(config, "application/json"),
            ),
        ]),
        TokenAuth {
            credentials: None,
            issued: "anon-token".to_owned(),
        },
    )
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "search",
            "--format",
            "json",
        ])
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run orc search");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows[0]["name"], "public-app");
    server.assert_requested("/token");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_fallback_for_registry_without_token_service() {
    let config = app_config(&json!({"default_version": "1.0"}));
    let config_digest = digest_bytes(&config);
    let server = MockServer::start(BTreeMap::from([
        (
            "/v2/_catalog".to_owned(),
            MockResponse::json(&json!({"repositories": ["acme/htpasswd-app"]}))
                .require_basic("user", "pass"),
        ),
        (
            "/v2/acme/htpasswd-app/manifests/default".to_owned(),
            MockResponse::manifest(app_manifest(&config, "Htpasswd app"))
                .require_basic("user", "pass"),
        ),
        (
            format!("/v2/acme/htpasswd-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json").require_basic("user", "pass"),
        ),
    ]))
    .await;

    let config_dir = tempfile::tempdir().expect("config dir");
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({
            "credentials": {
                server.registry(): {"username": "user", "token": "pass"}
            }
        })
        .to_string(),
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "search",
            "--format",
            "json",
        ])
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run orc search");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows[0]["name"], "htpasswd-app");
    server.assert_not_requested("/token");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_denied_after_failed_token_retry_exits_3() {
    let config_dir = tempfile::tempdir().expect("config dir");
    // The token endpoint issues a token, but the route demands a different
    // one, so the authenticated retry also gets a 401 — terminal.
    let server = MockServer::start_with_token_auth(
        BTreeMap::from([(
            "/v2/_catalog".to_owned(),
            MockResponse::json(&json!({"repositories": []})).require_bearer("other-token"),
        )]),
        TokenAuth {
            credentials: None,
            issued: "issued-token".to_owned(),
        },
    )
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "search",
        ])
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run orc search");

    assert_eq!(output.status.code(), Some(3), "expected auth exit code");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("registry access denied"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_with_registry_flag_stays_local_and_does_not_query_registry() {
    let cache_dir = tempfile::tempdir().expect("cache dir");
    let server = MockServer::start(BTreeMap::from([(
        "/v2/_catalog".to_owned(),
        MockResponse::json(&json!({"repositories": ["acme/remote-app"]})),
    )]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "list",
            "--format",
            "json",
        ])
        .env("ORC_CACHE_DIR", cache_dir.path())
        .output()
        .expect("run orc list");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows.as_array().expect("array").len(), 0);
    server.assert_not_requested("/v2/_catalog");
    server.assert_not_requested("/token");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_validates_credentials_before_storing() {
    let config_dir = tempfile::tempdir().expect("config dir");
    let server = MockServer::start_with_token_auth(
        BTreeMap::from([("/v2/".to_owned(), MockResponse::json(&json!({})))]),
        TokenAuth {
            credentials: Some(("token".to_owned(), "s3cret".to_owned())),
            issued: "ping-token".to_owned(),
        },
    )
    .await;

    let output = run_login(&server.registry(), config_dir.path(), "s3cret");
    assert_success(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Login Succeeded"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stored =
        std::fs::read_to_string(config_dir.path().join("config.json")).expect("config saved");
    assert!(stored.contains("s3cret"));
    server.assert_requested("/token");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_rejects_bad_credentials_and_stores_nothing() {
    let config_dir = tempfile::tempdir().expect("config dir");
    let server = MockServer::start_with_token_auth(
        BTreeMap::from([("/v2/".to_owned(), MockResponse::json(&json!({})))]),
        TokenAuth {
            credentials: Some(("token".to_owned(), "right".to_owned())),
            issued: "ping-token".to_owned(),
        },
    )
    .await;

    let output = run_login(&server.registry(), config_dir.path(), "wrong");
    assert_eq!(output.status.code(), Some(3), "expected auth exit code");
    assert!(
        !config_dir.path().join("config.json").exists(),
        "config must not be saved on failed login"
    );
}

fn run_login(registry: &str, config_dir: &std::path::Path, password: &str) -> std::process::Output {
    use std::io::Write as _;
    let mut child = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["login", "--password-stdin", registry])
        .env("ORC_CONFIG_DIR", config_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn orc login");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(password.as_bytes())
        .expect("write password");
    child.wait_with_output().expect("run orc login")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ghcr_search_uses_github_packages_api_and_stored_token() {
    let token = "package-token";
    let config_dir = tempfile::tempdir().expect("config dir");
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({
            "credentials": {
                "ghcr.io": {"username": "alice", "token": token}
            }
        })
        .to_string(),
    )
    .expect("write config");

    let github = MockServer::start(BTreeMap::from([(
        "/orgs/acme/packages".to_owned(),
        MockResponse::json(&json!([
            {"name": "runner", "package_type": "container"},
            {"name": "library", "package_type": "maven"}
        ]))
        .require_bearer(token),
    )]))
    .await;

    let config = app_config(&json!({"default_version": "2.320.1"}));
    let config_digest = digest_bytes(&config);
    let registry = MockServer::start_with_token_auth(
        BTreeMap::from([
            (
                "/v2/acme/runner/manifests/default".to_owned(),
                MockResponse::manifest(app_manifest(&config, "GitHub Actions runner")),
            ),
            (
                format!("/v2/acme/runner/blobs/{config_digest}"),
                MockResponse::bytes(config, "application/json"),
            ),
        ]),
        TokenAuth {
            credentials: Some(("alice".to_owned(), token.to_owned())),
            issued: "scoped-token".to_owned(),
        },
    )
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["search", "ghcr.io/acme", "--format", "json"])
        .env("ORC_CONFIG_DIR", config_dir.path())
        .env("ORC_GITHUB_API_BASE_URL", github.base_url())
        .env("ORC_GHCR_REGISTRY_BASE_URL", registry.base_url())
        .output()
        .expect("run orc search");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows.as_array().expect("array").len(), 1);
    assert_eq!(rows[0]["name"], "runner");
    assert_eq!(rows[0]["default"], "2.320.1");
    github.assert_requested("/orgs/acme/packages");
    registry.assert_requested("/token");
    registry.assert_token_query_contains("service=mock-registry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn versions_marks_digest_matched_default_and_merges_github_releases() {
    let token = "release-token";
    let config_dir = tempfile::tempdir().expect("config dir");
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({
            "credentials": {
                "ghcr.io": {"username": "alice", "token": token}
            }
        })
        .to_string(),
    )
    .expect("write config");

    let default_config = app_config(&json!({
        "default_version": "3.45",
        "versions": {
            "source": "github_releases",
            "url": "https://github.com/jenkinsci/swarm-plugin",
            "filter": {"prerelease": false}
        }
    }));
    let old_config = app_config(&json!({"default_version": "3.45"}));
    let default_digest = digest_bytes(&default_config);
    let old_digest = digest_bytes(&old_config);
    let default_manifest = app_manifest(&default_config, "Jenkins Swarm agent");
    let old_manifest = app_manifest(&old_config, "Jenkins Swarm agent");

    let github = MockServer::start(BTreeMap::from([(
        "/repos/jenkinsci/swarm-plugin/releases".to_owned(),
        MockResponse::json(&json!([
            {"tag_name": "v3.47", "prerelease": false},
            {"tag_name": "v4.0.0-beta", "prerelease": true}
        ]))
        .require_bearer(token),
    )]))
    .await;
    let registry = MockServer::start_with_token_auth(
        BTreeMap::from([
            (
                "/v2/acme/jenkins-agent/manifests/default".to_owned(),
                MockResponse::manifest(default_manifest.clone()),
            ),
            (
                "/v2/acme/jenkins-agent/manifests/3.46".to_owned(),
                MockResponse::manifest(default_manifest),
            ),
            (
                "/v2/acme/jenkins-agent/manifests/3.45".to_owned(),
                MockResponse::manifest(old_manifest),
            ),
            (
                format!("/v2/acme/jenkins-agent/blobs/{default_digest}"),
                MockResponse::bytes(default_config, "application/json"),
            ),
            (
                format!("/v2/acme/jenkins-agent/blobs/{old_digest}"),
                MockResponse::bytes(old_config, "application/json"),
            ),
            (
                "/v2/acme/jenkins-agent/tags/list".to_owned(),
                MockResponse::json(
                    &json!({"name": "acme/jenkins-agent", "tags": ["default", "3.45", "3.46"]}),
                ),
            ),
        ]),
        TokenAuth {
            credentials: Some(("alice".to_owned(), token.to_owned())),
            issued: "scoped-token".to_owned(),
        },
    )
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            "ghcr.io/acme",
            "versions",
            "jenkins-agent",
            "--format",
            "json",
        ])
        .env("ORC_CONFIG_DIR", config_dir.path())
        .env("ORC_GITHUB_API_BASE_URL", github.base_url())
        .env("ORC_GHCR_REGISTRY_BASE_URL", registry.base_url())
        .output()
        .expect("run orc versions");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    let versions = rows
        .as_array()
        .expect("array")
        .iter()
        .map(|row| {
            (
                row["version"].as_str().expect("version"),
                row["default"].as_bool().expect("default"),
                row["platforms"][0].as_str().expect("platform"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        versions,
        vec![
            ("3.47", false, "any"),
            ("3.46", true, "any"),
            ("3.45", false, "any")
        ]
    );
    // All registry requests target the same repository with read-only verbs,
    // so the scoped token from the first exchange is reused for every call.
    registry.assert_requested_count("/token", 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_merges_static_configured_list() {
    let config = app_config(&json!({
        "default_version": "3.45",
        "versions": {
            "list": ["4.0", "3.47", "3.46", "3.45"],
            "filter": {"pattern": "^3\\.", "exclude": ["3.47"], "limit": 2}
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "Static versions");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/static-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/static-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        (
            "/v2/acme/static-app/tags/list".to_owned(),
            MockResponse::json(&json!({"name": "acme/static-app", "tags": ["default"]})),
        ),
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "versions",
            "static-app",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc versions");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows[0]["version"], "3.46");
    assert_eq!(rows[0]["default"], false);
    assert_eq!(rows[0]["platforms"], json!(["any"]));
    assert_eq!(rows[1]["version"], "3.45");
    assert_eq!(rows[1]["default"], true);
    assert_eq!(rows[1]["platforms"], json!(["any"]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_filters_static_list_with_configured_sort() {
    let config = app_config(&json!({
        "default_version": "item-2",
        "versions": {
            "list": ["item-9", "item-10", "item-2"],
            "filter": {"sort": "string", "limit": 2}
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "Sorted static versions");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/sorted-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/sorted-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        (
            "/v2/acme/sorted-app/tags/list".to_owned(),
            MockResponse::json(&json!({"name": "acme/sorted-app", "tags": ["default"]})),
        ),
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "versions",
            "sorted-app",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc versions");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    let versions = rows
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["version"].as_str().expect("version"))
        .collect::<Vec<_>>();
    assert_eq!(versions, vec!["item-9", "item-2"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_merges_http_plain_text_list() {
    let versions = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"# comment\n3.46\n\n3.45\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = app_config(&json!({
        "default_version": "3.45",
        "versions": {
            "source": "http",
            "url": format!("{}/versions.txt", versions.base_url())
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "HTTP versions");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/http-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/http-app/blobs/{config_digest}"),
            MockResponse::bytes(config.clone(), "application/json"),
        ),
        (
            "/v2/acme/http-app/tags/list".to_owned(),
            MockResponse::json(&json!({"name": "acme/http-app", "tags": ["default"]})),
        ),
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "versions",
            "http-app",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc versions");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows[0]["version"], "3.46");
    assert_eq!(rows[0]["default"], false);
    assert_eq!(rows[1]["version"], "3.45");
    assert_eq!(rows[1]["default"], true);
    versions.assert_requested("/versions.txt");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_merges_json_source_versions() {
    let versions = MockServer::start(BTreeMap::from([(
        "/dist/index.json".to_owned(),
        MockResponse::json(&json!({
            "releases": [
                {"version": "v22.1.0"},
                {"version": "v22.0.0"},
                {"version": "nightly"}
            ]
        })),
    )]))
    .await;
    let config = app_config(&json!({
        "versions": {
            "source": "json",
            "url": format!("{}/dist/index.json", versions.base_url()),
            "select": "/releases",
            "field": "version",
            "filter": {"pattern": "^v(?P<version>\\d+\\.\\d+\\.\\d+)$"}
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "JSON versions");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/json-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/json-app/blobs/{config_digest}"),
            MockResponse::bytes(config.clone(), "application/json"),
        ),
        (
            "/v2/acme/json-app/tags/list".to_owned(),
            MockResponse::json(&json!({"name": "acme/json-app", "tags": ["default"]})),
        ),
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "versions",
            "json-app",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc versions");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    // The `nightly` entry doesn't match the pattern and is dropped; the surviving
    // entries have the capture group's text as their version.
    assert_eq!(rows.as_array().expect("rows").len(), 2);
    assert_eq!(rows[0]["version"], "22.1.0");
    assert_eq!(rows[1]["version"], "22.0.0");
    versions.assert_requested("/dist/index.json");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_merges_gitlab_release_tags() {
    let gitlab = MockServer::start(BTreeMap::from([(
        "/projects/acme%2Ftool/releases".to_owned(),
        MockResponse::json(&json!([
            {"tag_name": "v2.1.0", "upcoming_release": true},
            {"tag_name": "v2.0.0"},
            {"tag_name": "v1.9.0"}
        ])),
    )]))
    .await;
    let config = app_config(&json!({
        "versions": {
            "source": "gitlab_releases",
            "url": "https://gitlab.com/acme/tool"
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "GitLab release tags");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/gitlab-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/gitlab-app/blobs/{config_digest}"),
            MockResponse::bytes(config.clone(), "application/json"),
        ),
        (
            "/v2/acme/gitlab-app/tags/list".to_owned(),
            MockResponse::json(&json!({"name": "acme/gitlab-app", "tags": ["default"]})),
        ),
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "versions",
            "gitlab-app",
            "--format",
            "json",
        ])
        .env("ORC_GITLAB_API_BASE_URL", gitlab.base_url())
        .output()
        .expect("run orc versions");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    // The upcoming (prerelease) tag is dropped by default; the leading `v` is
    // stripped from the surviving tags.
    assert_eq!(rows.as_array().expect("rows").len(), 2);
    assert_eq!(rows[0]["version"], "2.0.0");
    assert_eq!(rows[1]["version"], "1.9.0");
    gitlab.assert_requested("/projects/acme%2Ftool/releases");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_merges_nuget_registration_versions() {
    let feed = MockServer::start(BTreeMap::from([(
        "/registration/nuget-app/index.json".to_owned(),
        MockResponse::json(&json!({
            "items": [{
                "items": [
                    {"catalogEntry": {"version": "1.0.0", "listed": true}},
                    {"catalogEntry": {"version": "1.1.0", "listed": false}},
                    {"catalogEntry": {"version": "1.2.0"}}
                ]
            }]
        })),
    )]))
    .await;
    let config = app_config(&json!({
        "default_version": "1.0.0",
        "versions": {
            "source": "nuget",
            "url": format!("{}/registration", feed.base_url())
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "NuGet versions");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/nuget-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/nuget-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        (
            "/v2/acme/nuget-app/tags/list".to_owned(),
            MockResponse::json(&json!({"name": "acme/nuget-app", "tags": ["default"]})),
        ),
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "versions",
            "nuget-app",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc versions");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows[0]["version"], "1.2.0");
    assert_eq!(rows[0]["default"], false);
    assert_eq!(rows[1]["version"], "1.0.0");
    assert_eq!(rows[1]["default"], true);
    feed.assert_requested("/registration/nuget-app/index.json");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_merges_winget_rest_versions() {
    let feed = MockServer::start(BTreeMap::from([(
        "/packages/winget-app/versions".to_owned(),
        MockResponse::json(&json!({
            "Data": [
                {"PackageVersion": "2.0.0"},
                {"PackageVersion": "1.0.0"}
            ]
        })),
    )]))
    .await;
    let config = app_config(&json!({
        "default_version": "1.0.0",
        "versions": {
            "source": "winget",
            "url": feed.base_url()
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "WinGet versions");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/winget-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/winget-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        (
            "/v2/acme/winget-app/tags/list".to_owned(),
            MockResponse::json(&json!({"name": "acme/winget-app", "tags": ["default"]})),
        ),
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "versions",
            "winget-app",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc versions");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(rows[0]["version"], "2.0.0");
    assert_eq!(rows[0]["default"], false);
    assert_eq!(rows[1]["version"], "1.0.0");
    assert_eq!(rows[1]["default"], true);
    feed.assert_requested("/packages/winget-app/versions");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_renders_config_without_downloading_payloads() {
    let config = app_config(&json!({
        "params": {
            "type": "object",
            "required": ["github_url", "github_token"],
            "properties": {
                "github_url": {"type": "string", "description": "Repository URL"},
                "github_token": {"type": "string", "description": "Runner token", "sensitive": true}
            }
        },
        "start": {"service": "github-runner"},
        "stop": {"signal": "SIGINT", "timeout": "30s"}
    }));
    let config_digest = digest_bytes(&config);
    let payload_digest = digest_bytes(b"payload");
    let manifest = app_manifest_with_layer(&config, &payload_digest, "Self-hosted runner");
    let server = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/github-runner/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/github-runner/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        (
            format!("/v2/acme/github-runner/blobs/{payload_digest}"),
            MockResponse::bytes(b"payload".to_vec(), "application/octet-stream"),
        ),
    ]))
    .await;

    // Its own cache: an app config is a cached blob like any other, so a warm shared
    // cache would let the second run of this test serve it without asking the registry.
    let cache = tempfile::tempdir().expect("cache dir");
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", server.registry()),
            "info",
            "github-runner",
            "--format",
            "json",
        ])
        .env("ORC_CACHE_DIR", cache.path())
        .output()
        .expect("run orc info");

    assert_success(&output);
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(
        info["reference"],
        format!("{}/acme/github-runner:default", server.registry())
    );
    assert_eq!(info["description"], "Self-hosted runner");
    // A `service` with no `command` is a bring-your-own definition, named by the
    // platform name the runtime derives from the package's OS-agnostic identifier.
    assert_eq!(
        info["mode"],
        format!(
            "service {} (bring-your-own)",
            orc_cli::service::platform_name("github-runner")
        )
    );
    assert_eq!(
        info["phases"],
        json!(["start", "stop (SIGINT, 30s, grace 10s)"])
    );
    assert_eq!(info["params"][0]["flag"], "--github-token");
    assert_eq!(info["params"][0]["sensitive"], true);
    assert_eq!(info["params"][1]["flag"], "--github-url");
    server.assert_requested(&format!("/v2/acme/github-runner/blobs/{config_digest}"));
    server.assert_not_requested(&format!("/v2/acme/github-runner/blobs/{payload_digest}"));
}

/// spec 205 CLI parity: `orc install app:X` on a tag-404 falls back to the `default`
/// package when `X` is server-discoverable, recording the install under version `X` so
/// the install script runs with `APP_VERSION=X`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_falls_back_to_default_for_discovered_version() {
    // The install script proves APP_VERSION reached it: it writes the value to a file in
    // the materialized (work) directory, which is keyed by the requested version.
    let install_script = b"printf '%s' \"$APP_VERSION\" > version.txt\n".to_vec();
    let script_digest = digest_bytes(&install_script);

    // The version list lives on a separate mock so its URL is known before the config
    // (and thus the config digest and manifest) is built.
    let versions = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.2.3\n1.2.0\n".to_vec(), "text/plain"),
    )]))
    .await;

    let config = app_config(&json!({
        "install": {"command": "sh install.sh"},
        "versions": {"source": "http", "url": format!("{}/versions.txt", versions.base_url())}
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest_layers(
        &config,
        "Fallback app",
        &[json!({
            "mediaType": "application/octet-stream",
            "digest": script_digest,
            "size": install_script.len(),
            "annotations": {"org.opencontainers.image.title": "install.sh"}
        })],
    );
    // No route for `.../manifests/1.2.3` → the tag fetch 404s, engaging the fallback.
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/fallback-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/fallback-app/blobs/{config_digest}"),
            MockResponse::bytes(config.clone(), "application/json"),
        ),
        (
            format!("/v2/acme/fallback-app/blobs/{script_digest}"),
            MockResponse::bytes(install_script.clone(), "application/octet-stream"),
        ),
    ]))
    .await;

    let cache = tempfile::tempdir().expect("cache dir");
    let state = tempfile::tempdir().expect("state dir");
    let config_dir = tempfile::tempdir().expect("config dir");
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "install",
            "fallback-app:1.2.3",
        ])
        .env("ORC_CACHE_DIR", cache.path())
        .env("ORC_STATE_DIR", state.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run orc install");

    assert_success(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "Resolved fallback-app:1.2.3 via version discovery (installing default package pinned to 1.2.3)"
        ),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The install script ran with APP_VERSION=1.2.3 in the version-keyed work dir.
    let version_file = state.path().join("apps/fallback-app/1.2.3/version.txt");
    assert_eq!(
        std::fs::read_to_string(&version_file).expect("version.txt written by install"),
        "1.2.3"
    );
}

/// A version that is neither a real tag nor discovered keeps the original tag-miss error;
/// the fallback never fires and no default package is installed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_keeps_not_found_for_undiscovered_version() {
    let versions = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.2.3\n1.2.0\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = app_config(&json!({
        "install": {"command": "sh install.sh"},
        "versions": {"source": "http", "url": format!("{}/versions.txt", versions.base_url())}
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "Fallback app");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/fallback-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/fallback-app/blobs/{config_digest}"),
            MockResponse::bytes(config.clone(), "application/json"),
        ),
    ]))
    .await;

    let cache = tempfile::tempdir().expect("cache dir");
    let state = tempfile::tempdir().expect("state dir");
    let config_dir = tempfile::tempdir().expect("config dir");
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "install",
            "fallback-app:9.9.9",
        ])
        .env("ORC_CACHE_DIR", cache.path())
        .env("ORC_STATE_DIR", state.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run orc install");

    assert!(
        !output.status.success(),
        "install must fail for an undiscovered version: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("via version discovery"),
        "no fallback note expected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !state.path().join("apps/fallback-app/9.9.9").exists(),
        "no default package should have been materialized"
    );
}

/// Being logged into the target registry must not break install-by-line: the registry's
/// credential is not a GitHub credential, and handing it to the GitHub API would 401 the
/// version source, which reads as unreachable and drops the install back to the tag-miss.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_by_line_keeps_registry_credential_off_github() {
    let install_script = b"printf '%s' \"$APP_VERSION\" > version.txt\n".to_vec();
    let script_digest = digest_bytes(&install_script);

    // The releases route demands nothing, and records what it was sent: a request
    // carrying the registry key would be a leak even where the mock tolerates it.
    let github = MockServer::start(BTreeMap::from([(
        "/repos/acme/line-app/releases".to_owned(),
        MockResponse::json(&json!([
            {"tag_name": "1.2.3", "prerelease": false},
            {"tag_name": "1.1.0", "prerelease": false}
        ])),
    )]))
    .await;

    let config = app_config(&json!({
        "install": {"command": "sh install.sh"},
        "versions": {
            "source": "github_releases",
            "url": "https://github.com/acme/line-app",
            "filter": {"prerelease": false}
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest_layers(
        &config,
        "Line app",
        &[json!({
            "mediaType": "application/octet-stream",
            "digest": script_digest,
            "size": install_script.len(),
            "annotations": {"org.opencontainers.image.title": "install.sh"}
        })],
    );
    // Every registry route demands the stored credential, so the run only gets this far
    // while the login is real; no route for the `1.2` line or the `1.2.3` tag, so both
    // tag fetches 404 and the discovery fallback carries the install.
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/line-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest).require_basic("operator", "registry-key"),
        ),
        (
            format!("/v2/acme/line-app/blobs/{config_digest}"),
            MockResponse::bytes(config.clone(), "application/json")
                .require_basic("operator", "registry-key"),
        ),
        (
            format!("/v2/acme/line-app/blobs/{script_digest}"),
            MockResponse::bytes(install_script.clone(), "application/octet-stream")
                .require_basic("operator", "registry-key"),
        ),
    ]))
    .await;

    let config_dir = tempfile::tempdir().expect("config dir");
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({
            "credentials": {
                registry.registry(): {"username": "operator", "token": "registry-key"}
            }
        })
        .to_string(),
    )
    .expect("write config");

    let cache = tempfile::tempdir().expect("cache dir");
    let state = tempfile::tempdir().expect("state dir");
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "install",
            "line-app:1.2",
        ])
        .env("ORC_CACHE_DIR", cache.path())
        .env("ORC_STATE_DIR", state.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .env("ORC_GITHUB_API_BASE_URL", github.base_url())
        .output()
        .expect("run orc install");

    assert_success(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "Resolved line-app:1.2 via version discovery (installing default package pinned to 1.2.3)"
        ),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(state.path().join("apps/line-app/1.2.3/version.txt"))
            .expect("version.txt written by install"),
        "1.2.3"
    );
    github.assert_authorization("/repos/acme/line-app/releases", None);
}

/// The GitHub-side credential is the `ghcr.io` one, and it does ride along: a private
/// release feed stays readable during install resolution even when a second, unrelated
/// registry credential is also stored.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_by_line_sends_ghcr_credential_to_github() {
    let install_script = b"printf '%s' \"$APP_VERSION\" > version.txt\n".to_vec();
    let script_digest = digest_bytes(&install_script);

    // The feed is private: without the `ghcr.io` token this 401s, discovery reports an
    // unreachable source, and the install fails with the tag-miss.
    let github = MockServer::start(BTreeMap::from([(
        "/repos/acme/private-app/releases".to_owned(),
        MockResponse::json(&json!([{"tag_name": "2.4.1", "prerelease": false}]))
            .require_bearer("ghcr-token"),
    )]))
    .await;

    let config = app_config(&json!({
        "install": {"command": "sh install.sh"},
        "versions": {
            "source": "github_releases",
            "url": "https://github.com/acme/private-app",
            "filter": {"prerelease": false}
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest_layers(
        &config,
        "Private app",
        &[json!({
            "mediaType": "application/octet-stream",
            "digest": script_digest,
            "size": install_script.len(),
            "annotations": {"org.opencontainers.image.title": "install.sh"}
        })],
    );
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/private-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest).require_basic("operator", "registry-key"),
        ),
        (
            format!("/v2/acme/private-app/blobs/{config_digest}"),
            MockResponse::bytes(config.clone(), "application/json")
                .require_basic("operator", "registry-key"),
        ),
        (
            format!("/v2/acme/private-app/blobs/{script_digest}"),
            MockResponse::bytes(install_script.clone(), "application/octet-stream")
                .require_basic("operator", "registry-key"),
        ),
    ]))
    .await;

    let config_dir = tempfile::tempdir().expect("config dir");
    std::fs::write(
        config_dir.path().join("config.json"),
        json!({
            "credentials": {
                "ghcr.io": {"username": "alice", "token": "ghcr-token"},
                registry.registry(): {"username": "operator", "token": "registry-key"}
            }
        })
        .to_string(),
    )
    .expect("write config");

    let cache = tempfile::tempdir().expect("cache dir");
    let state = tempfile::tempdir().expect("state dir");
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "install",
            "private-app:2.4",
        ])
        .env("ORC_CACHE_DIR", cache.path())
        .env("ORC_STATE_DIR", state.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .env("ORC_GITHUB_API_BASE_URL", github.base_url())
        .output()
        .expect("run orc install");

    assert_success(&output);
    assert_eq!(
        std::fs::read_to_string(state.path().join("apps/private-app/2.4.1/version.txt"))
            .expect("version.txt written by install"),
        "2.4.1"
    );
    github.assert_authorization(
        "/repos/acme/private-app/releases",
        Some("Bearer ghcr-token"),
    );
}

struct MockServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    token_queries: Arc<Mutex<Vec<String>>>,
    /// What each request carried, so a test can pin which stored credential (if
    /// any) reached a given API.
    authorizations: Authorizations,
}

/// Docker-registry token flow for the mock: unauthenticated requests get a 401
/// with a Bearer challenge naming `/token`; the token endpoint validates Basic
/// credentials (or allows anonymous exchange when `credentials` is `None`) and
/// issues `issued`, which every other route then demands as a Bearer token.
#[derive(Clone)]
struct TokenAuth {
    credentials: Option<(String, String)>,
    issued: String,
}

impl MockServer {
    async fn start(routes: BTreeMap<String, MockResponse>) -> Self {
        Self::start_inner(routes, None).await
    }

    async fn start_with_token_auth(
        routes: BTreeMap<String, MockResponse>,
        token_auth: TokenAuth,
    ) -> Self {
        Self::start_inner(routes, Some(token_auth)).await
    }

    async fn start_inner(
        routes: BTreeMap<String, MockResponse>,
        token_auth: Option<TokenAuth>,
    ) -> Self {
        let routes = Arc::new(routes);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let token_queries = Arc::new(Mutex::new(Vec::new()));
        let authorizations = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .fallback(any(mock_handler))
            .with_state(MockState {
                routes,
                requests: Arc::clone(&requests),
                token_queries: Arc::clone(&token_queries),
                authorizations: Arc::clone(&authorizations),
                token_auth,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock server");
        });
        Self {
            addr,
            requests,
            token_queries,
            authorizations,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn registry(&self) -> String {
        self.addr.to_string()
    }

    fn assert_requested(&self, path: &str) {
        assert!(
            self.requests
                .lock()
                .expect("requests lock")
                .iter()
                .any(|request| request == path),
            "expected request to {path}"
        );
    }

    fn assert_requested_count(&self, path: &str, expected: usize) {
        let count = self
            .requests
            .lock()
            .expect("requests lock")
            .iter()
            .filter(|request| *request == path)
            .count();
        assert_eq!(count, expected, "requests to {path}");
    }

    fn assert_not_requested(&self, path: &str) {
        assert!(
            !self
                .requests
                .lock()
                .expect("requests lock")
                .iter()
                .any(|request| request == path),
            "unexpected request to {path}"
        );
    }

    /// Asserts every request to `path` carried exactly `expected` as its
    /// `Authorization` header (`None` = the request was anonymous).
    fn assert_authorization(&self, path: &str, expected: Option<&str>) {
        let seen = self
            .authorizations
            .lock()
            .expect("authorizations lock")
            .iter()
            .filter(|(requested, _)| requested == path)
            .map(|(_, authorization)| authorization.clone())
            .collect::<Vec<_>>();
        assert!(!seen.is_empty(), "expected request to {path}");
        let expected = expected.map(str::to_owned);
        assert!(
            seen.iter().all(|authorization| *authorization == expected),
            "authorization headers on {path}: {seen:?}, expected {expected:?}"
        );
    }

    fn assert_token_query_contains(&self, needle: &str) {
        assert!(
            self.token_queries
                .lock()
                .expect("token queries lock")
                .iter()
                .any(|query| query.contains(needle)),
            "expected a /token query containing {needle:?}"
        );
    }
}

#[derive(Clone)]
struct MockState {
    routes: Arc<BTreeMap<String, MockResponse>>,
    requests: Arc<Mutex<Vec<String>>>,
    token_queries: Arc<Mutex<Vec<String>>>,
    authorizations: Authorizations,
    token_auth: Option<TokenAuth>,
}

async fn mock_handler(State(state): State<MockState>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    // A route may key on the query string as well: the page size a version source is
    // asked for is part of what a test wants to pin. Both spellings are recorded and
    // both are looked up, so a route registered under the bare path still answers.
    let addressed = request
        .uri()
        .path_and_query()
        .map_or_else(|| path.clone(), |target| target.as_str().to_owned());
    {
        let mut requests = state.requests.lock().expect("requests lock");
        requests.push(path.clone());
        if addressed != path {
            requests.push(addressed.clone());
        }
    }
    {
        let authorization = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        state
            .authorizations
            .lock()
            .expect("authorizations lock")
            .push((path.clone(), authorization));
    }
    if let Some(token_auth) = &state.token_auth {
        if path == "/token" {
            return token_endpoint_response(&state, token_auth, &request);
        }
        let expected = format!("Bearer {}", token_auth.issued);
        let got = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if got != Some(expected.as_str()) {
            return bearer_challenge_response(&request, &path);
        }
    }
    let Some(mock_response) = state
        .routes
        .get(&addressed)
        .or_else(|| state.routes.get(&path))
    else {
        return response(
            StatusCode::NOT_FOUND,
            HeaderMap::new(),
            b"not found".to_vec(),
        );
    };
    if let Some(token) = &mock_response.required_bearer {
        let expected = format!("Bearer {token}");
        let got = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if got != Some(expected.as_str()) {
            return response(
                StatusCode::UNAUTHORIZED,
                HeaderMap::new(),
                b"denied".to_vec(),
            );
        }
    }
    if let Some((user, pass)) = &mock_response.required_basic {
        let expected = format!("Basic {}", basic_credentials(user, pass));
        let got = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if got != Some(expected.as_str()) {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"mock\"".parse().expect("challenge header"),
            );
            return response(StatusCode::UNAUTHORIZED, headers, b"denied".to_vec());
        }
    }
    mock_response.to_response()
}

fn token_endpoint_response(
    state: &MockState,
    token_auth: &TokenAuth,
    request: &Request,
) -> Response {
    state
        .token_queries
        .lock()
        .expect("token queries lock")
        .push(request.uri().query().unwrap_or_default().to_owned());
    if let Some((user, pass)) = &token_auth.credentials {
        let expected = format!("Basic {}", basic_credentials(user, pass));
        let got = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if got != Some(expected.as_str()) {
            return response(
                StatusCode::UNAUTHORIZED,
                HeaderMap::new(),
                b"denied".to_vec(),
            );
        }
    }
    let body = json!({"token": token_auth.issued, "expires_in": 300})
        .to_string()
        .into_bytes();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("content type"),
    );
    response(StatusCode::OK, headers, body)
}

fn bearer_challenge_response(request: &Request, path: &str) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    let mut challenge = format!("Bearer realm=\"http://{host}/token\",service=\"mock-registry\"");
    if let Some(scope) = mock_scope_for(request.method(), path) {
        use std::fmt::Write as _;
        let _ = write!(challenge, ",scope=\"{scope}\"");
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::WWW_AUTHENTICATE,
        challenge.parse().expect("challenge header"),
    );
    response(StatusCode::UNAUTHORIZED, headers, b"unauthorized".to_vec())
}

fn mock_scope_for(method: &axum::http::Method, path: &str) -> Option<String> {
    let rest = path.strip_prefix("/v2/")?;
    if rest.starts_with("_catalog") {
        return Some("registry:catalog:*".to_owned());
    }
    let keyword_start = ["/manifests/", "/blobs/", "/tags/"]
        .iter()
        .filter_map(|keyword| rest.rfind(keyword))
        .max()?;
    let repository = &rest[..keyword_start];
    if repository.is_empty() {
        return None;
    }
    let actions = if method == axum::http::Method::GET || method == axum::http::Method::HEAD {
        "pull"
    } else {
        "pull,push"
    };
    Some(format!("repository:{repository}:{actions}"))
}

fn basic_credentials(user: &str, pass: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
}

#[derive(Clone)]
struct MockResponse {
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    required_bearer: Option<String>,
    required_basic: Option<(String, String)>,
}

impl MockResponse {
    fn json(value: &serde_json::Value) -> Self {
        Self::bytes(value.to_string().into_bytes(), "application/json")
    }

    fn manifest(body: Vec<u8>) -> Self {
        Self::bytes(body, OCI_MANIFEST)
    }

    fn bytes(body: Vec<u8>, content_type: &'static str) -> Self {
        Self {
            status: StatusCode::OK,
            content_type,
            body,
            required_bearer: None,
            required_basic: None,
        }
    }

    fn require_bearer(mut self, token: &str) -> Self {
        self.required_bearer = Some(token.to_owned());
        self
    }

    fn require_basic(mut self, user: &str, pass: &str) -> Self {
        self.required_basic = Some((user.to_owned(), pass.to_owned()));
        self
    }

    fn to_response(&self) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            self.content_type.parse().expect("content type"),
        );
        response(self.status, headers, self.body.clone())
    }
}

fn response(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn app_config(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("serialize config")
}

fn app_manifest(config: &[u8], description: &str) -> Vec<u8> {
    app_manifest_layers(config, description, &[])
}

fn app_manifest_with_layer(config: &[u8], payload_digest: &str, description: &str) -> Vec<u8> {
    let layers = [json!({
            "mediaType": "application/octet-stream",
            "digest": payload_digest,
            "size": 7,
            "annotations": {"org.opencontainers.image.title": "payload.bin"}
    })];
    app_manifest_layers(config, description, &layers)
}

fn app_manifest_layers(config: &[u8], description: &str, layers: &[serde_json::Value]) -> Vec<u8> {
    let config_digest = digest_bytes(config);
    serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "artifactType": APP_ARTIFACT_TYPE,
        "config": {
            "mediaType": APP_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config.len()
        },
        "layers": layers,
        "annotations": {
            "org.opencontainers.image.description": description
        }
    }))
    .expect("serialize manifest")
}

fn non_orc_manifest() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "artifactType": "application/vnd.oci.image.config.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": digest_bytes(b"{}"),
            "size": 2
        },
        "layers": []
    }))
    .expect("serialize manifest")
}

fn digest_bytes(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut out = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "status: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_merges_github_tags_source() {
    let default_config = app_config(&json!({
        "versions": {
            "source": "github_tags",
            "url": "https://github.com/aws/aws-cli",
            "filter": {"pattern": "^2\\.[0-9.]+$"}
        }
    }));
    let default_digest = digest_bytes(&default_config);
    let default_manifest = app_manifest(&default_config, "AWS CLI");

    // aws/aws-cli publishes tags only — no GitHub releases — so the tags API is
    // the enumerable source; entries carry no prerelease concept.
    let github = MockServer::start(BTreeMap::from([(
        "/repos/aws/aws-cli/tags".to_owned(),
        MockResponse::json(&json!([
            {"name": "2.23.0"},
            {"name": "2.22.1"},
            {"name": "1.34.10"}
        ])),
    )]))
    .await;
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/aws/manifests/default".to_owned(),
            MockResponse::manifest(default_manifest),
        ),
        (
            format!("/v2/acme/aws/blobs/{default_digest}"),
            MockResponse::bytes(default_config, "application/json"),
        ),
        (
            "/v2/acme/aws/tags/list".to_owned(),
            MockResponse::json(&json!({"name": "acme/aws", "tags": ["default"]})),
        ),
    ]))
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            "ghcr.io/acme",
            "versions",
            "aws",
            "--format",
            "json",
        ])
        .env(
            "ORC_CONFIG_DIR",
            tempfile::tempdir().expect("config").path(),
        )
        .env("ORC_GITHUB_API_BASE_URL", github.base_url())
        .env("ORC_GHCR_REGISTRY_BASE_URL", registry.base_url())
        .output()
        .expect("run orc versions");

    assert_success(&output);
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    let versions = rows
        .as_array()
        .expect("array")
        .iter()
        .map(|row| row["version"].as_str().expect("version").to_owned())
        .collect::<Vec<_>>();
    // The 1.x tag is filtered out by the recipe pattern; 2.x tags survive newest-first.
    assert_eq!(versions, vec!["2.23.0", "2.22.1"]);
}

/// The default listing is curated — the recipe's `latest_per` and `limit` stages run — and
/// `--all` prints the same pipeline with those two stages dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_all_bypasses_line_pruning_and_limit() {
    let config = app_config(&json!({
        "versions": {
            "list": ["1.5.7", "1.5.0", "1.4.9", "1.4.0"],
            "filter": {"exclude": ["1.4.0"], "latest_per": "minor", "limit": 1}
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "Curated versions");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/curated-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/curated-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        (
            "/v2/acme/curated-app/tags/list".to_owned(),
            MockResponse::json(&json!({"name": "acme/curated-app", "tags": ["default"]})),
        ),
    ]))
    .await;
    let prefix = format!("{}/acme", registry.registry());

    let curated = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &prefix,
            "versions",
            "curated-app",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc versions");
    assert_success(&curated);
    assert_eq!(listed_versions(&curated), vec!["1.5.7"]);

    let all = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &prefix,
            "versions",
            "curated-app",
            "--all",
            "--format",
            "json",
        ])
        .output()
        .expect("run orc versions --all");
    assert_success(&all);
    // Line pruning and the count limit are gone; `exclude` still holds.
    assert_eq!(listed_versions(&all), vec!["1.5.7", "1.5.0", "1.4.9"]);

    // Text output keeps its columns, additively.
    let text = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args(["--registry", &prefix, "versions", "curated-app", "--all"])
        .output()
        .expect("run orc versions --all");
    assert_success(&text);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(
        stdout.starts_with("VERSION          DEFAULT  PLATFORMS"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("1.4.9"), "stdout: {stdout}");
    assert!(!stdout.contains("1.4.0"), "stdout: {stdout}");
}

/// `orc install app:1.5` resolves the prefix to the newest version on that line and
/// installs — and records — that concrete version. `1.55.0` is a different line.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_resolves_version_prefix_to_newest_match() {
    let install_script = b"printf '%s' \"$APP_VERSION\" > version.txt\n".to_vec();
    let script_digest = digest_bytes(&install_script);
    let versions = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.55.0\n1.5.7\n1.5.0\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = app_config(&json!({
        "install": {"command": "sh install.sh"},
        "versions": {"source": "http", "url": format!("{}/versions.txt", versions.base_url())}
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest_layers(
        &config,
        "Prefix app",
        &[json!({
            "mediaType": "application/octet-stream",
            "digest": script_digest,
            "size": install_script.len(),
            "annotations": {"org.opencontainers.image.title": "install.sh"}
        })],
    );
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/prefix-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/prefix-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        (
            format!("/v2/acme/prefix-app/blobs/{script_digest}"),
            MockResponse::bytes(install_script, "application/octet-stream"),
        ),
    ]))
    .await;

    let cache = tempfile::tempdir().expect("cache dir");
    let state = tempfile::tempdir().expect("state dir");
    let config_dir = tempfile::tempdir().expect("config dir");
    let install = || {
        Command::new(env!("CARGO_BIN_EXE_orc"))
            .args([
                "--registry",
                &format!("{}/acme", registry.registry()),
                "install",
                "prefix-app:1.5",
            ])
            .env("ORC_CACHE_DIR", cache.path())
            .env("ORC_STATE_DIR", state.path())
            .env("ORC_CONFIG_DIR", config_dir.path())
            .output()
            .expect("run orc install")
    };
    let output = install();

    assert_success(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "Resolved prefix-app:1.5 via version discovery (installing default package pinned to 1.5.7)"
        ),
        "stderr: {stderr}"
    );
    // The install ran with APP_VERSION=1.5.7, in the work directory of the resolved version.
    assert_eq!(
        std::fs::read_to_string(state.path().join("apps/prefix-app/1.5.7/version.txt"))
            .expect("version.txt written by install"),
        "1.5.7"
    );
    assert!(
        !state.path().join("apps/prefix-app/1.5").exists(),
        "the prefix must not become a work directory of its own"
    );
    // The install record — and the printed reference — name the resolved version.
    let record: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(state.path().join("installs/prefix-app/1.5.7.json"))
            .expect("install record for the resolved version"),
    )
    .expect("record json");
    assert_eq!(record["version"], "1.5.7");
    assert_eq!(
        record["reference"],
        json!(format!("{}/acme/prefix-app:1.5.7", registry.registry()))
    );
    assert!(!state.path().join("installs/prefix-app/1.5.json").exists());
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with(&format!(
            "{}/acme/prefix-app:1.5.7@sha256:",
            registry.registry()
        )),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Repeating the prefix install reuses the resolved install rather than refusing to
    // overwrite its own materialized files.
    let again = install();
    assert_success(&again);
    assert!(
        String::from_utf8_lossy(&again.stderr)
            .contains("Resolved prefix-app:1.5 to 1.5.7 via version discovery (already installed)"),
        "stderr: {}",
        String::from_utf8_lossy(&again.stderr)
    );
}

/// `orc start app:1.5` resolves the prefix exactly as `orc install` does — the CLI-parity
/// rule covers both — and a second start reuses the resolved install.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_resolves_version_prefix_and_reuses_the_resolved_install() {
    let versions = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.55.0\n1.5.7\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = app_config(&json!({
        "install": {"command": "printf '%s' \"$APP_VERSION\" > installed.txt"},
        "start": {"command": "printf 'started:%s\\n' \"$APP_VERSION\""},
        "versions": {"source": "http", "url": format!("{}/versions.txt", versions.base_url())}
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "Prefix app");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/prefix-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/prefix-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
    ]))
    .await;

    let cache = tempfile::tempdir().expect("cache dir");
    let state = tempfile::tempdir().expect("state dir");
    let config_dir = tempfile::tempdir().expect("config dir");
    let start = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_orc"))
            .args(args)
            .env("ORC_CACHE_DIR", cache.path())
            .env("ORC_STATE_DIR", state.path())
            .env("ORC_CONFIG_DIR", config_dir.path())
            .output()
            .expect("run orc")
    };
    let prefix = format!("{}/acme", registry.registry());

    let first = start(&["--registry", &prefix, "start", "prefix-app:1.5"]);
    assert_success(&first);
    // The app ran as the resolved version, and was installed under it.
    assert_eq!(String::from_utf8_lossy(&first.stdout), "started:1.5.7\n");
    assert!(
        String::from_utf8_lossy(&first.stderr).contains(
            "Resolved prefix-app:1.5 via version discovery (installing default package pinned to 1.5.7)"
        ),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(state.path().join("apps/prefix-app/1.5.7/installed.txt"))
            .expect("installed.txt written by the install phase"),
        "1.5.7"
    );
    assert!(!state.path().join("apps/prefix-app/1.5").exists());

    // A second start reads the line off the local install records and runs what it
    // finds there — no registry, no source, nothing to reinstall.
    let second = start(&["--registry", &prefix, "start", "prefix-app:1.5"]);
    assert_success(&second);
    assert_eq!(String::from_utf8_lossy(&second.stdout), "started:1.5.7\n");
    assert!(
        !String::from_utf8_lossy(&second.stderr).contains("version discovery"),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    // The run is recorded against the resolved version, not the prefix.
    let status = start(&["status", "prefix-app", "--format", "json"]);
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(rows.as_array().expect("array").len(), 1);
    assert_eq!(rows[0]["version"], "1.5.7");
    assert_eq!(rows[0]["state"], "completed");
}

/// A prefix nothing is published under is a not-found: exit 4, and nothing installed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_exits_4_when_no_discovered_version_matches_the_prefix() {
    let versions = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.5.7\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = app_config(&json!({
        "install": {"command": "sh install.sh"},
        "versions": {"source": "http", "url": format!("{}/versions.txt", versions.base_url())}
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest(&config, "Prefix app");
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/prefix-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/prefix-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
    ]))
    .await;

    let cache = tempfile::tempdir().expect("cache dir");
    let state = tempfile::tempdir().expect("state dir");
    let config_dir = tempfile::tempdir().expect("config dir");
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "install",
            "prefix-app:1.6",
        ])
        .env("ORC_CACHE_DIR", cache.path())
        .env("ORC_STATE_DIR", state.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run orc install");

    assert_eq!(
        output.status.code(),
        Some(4),
        "expected not-found exit code"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no discovered version matches \"1.6\""),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("via version discovery"),
        "stderr: {stderr}"
    );
    assert!(!state.path().join("apps/prefix-app").exists());
}

/// Curation shapes `orc versions`, not what may be installed: an exact version the
/// recipe's `latest_per` prunes out of the listing still installs as itself.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_accepts_an_exact_version_hidden_by_curation() {
    let install_script = b"printf '%s' \"$APP_VERSION\" > version.txt\n".to_vec();
    let script_digest = digest_bytes(&install_script);
    let config = app_config(&json!({
        "install": {"command": "sh install.sh"},
        "versions": {
            "list": ["1.5.7", "1.5.0"],
            "filter": {"latest_per": "minor"}
        }
    }));
    let config_digest = digest_bytes(&config);
    let manifest = app_manifest_layers(
        &config,
        "Curated app",
        &[json!({
            "mediaType": "application/octet-stream",
            "digest": script_digest,
            "size": install_script.len(),
            "annotations": {"org.opencontainers.image.title": "install.sh"}
        })],
    );
    let registry = MockServer::start(BTreeMap::from([
        (
            "/v2/acme/curated-app/manifests/default".to_owned(),
            MockResponse::manifest(manifest),
        ),
        (
            format!("/v2/acme/curated-app/blobs/{config_digest}"),
            MockResponse::bytes(config, "application/json"),
        ),
        (
            format!("/v2/acme/curated-app/blobs/{script_digest}"),
            MockResponse::bytes(install_script, "application/octet-stream"),
        ),
    ]))
    .await;

    let cache = tempfile::tempdir().expect("cache dir");
    let state = tempfile::tempdir().expect("state dir");
    let config_dir = tempfile::tempdir().expect("config dir");
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "install",
            "curated-app:1.5.0",
        ])
        .env("ORC_CACHE_DIR", cache.path())
        .env("ORC_STATE_DIR", state.path())
        .env("ORC_CONFIG_DIR", config_dir.path())
        .output()
        .expect("run orc install");

    assert_success(&output);
    assert_eq!(
        std::fs::read_to_string(state.path().join("apps/curated-app/1.5.0/version.txt"))
            .expect("version.txt written by install"),
        "1.5.0"
    );
}

fn listed_versions(output: &std::process::Output) -> Vec<String> {
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    rows.as_array()
        .expect("array")
        .iter()
        .map(|row| row["version"].as_str().expect("version").to_owned())
        .collect()
}

/// A CLI sandbox: its own cache, state, and config directories, alive for the whole test.
///
/// Every run needs its own cache. An app config is a content-addressed cached blob like
/// any other, so a run that leaked into the developer's real cache would pass once and
/// then serve its own leftovers to the next run.
struct CliEnv {
    cache: tempfile::TempDir,
    state: tempfile::TempDir,
    config: tempfile::TempDir,
}

impl CliEnv {
    fn new() -> Self {
        Self {
            cache: tempfile::tempdir().expect("cache dir"),
            state: tempfile::tempdir().expect("state dir"),
            config: tempfile::tempdir().expect("config dir"),
        }
    }

    fn state(&self) -> &std::path::Path {
        self.state.path()
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_orc"))
            .args(args)
            .env("ORC_CACHE_DIR", self.cache.path())
            .env("ORC_STATE_DIR", self.state.path())
            .env("ORC_CONFIG_DIR", self.config.path())
            .output()
            .expect("run orc")
    }
}

/// An address nothing answers on: a port is bound to learn a free one, then released.
/// Pointing a command at it proves the command never went to the network.
fn dead_registry() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
    let addr = listener.local_addr().expect("probe address");
    drop(listener);
    format!("{addr}/acme")
}

/// Routes serving one tag of `repository`: its manifest, its config blob, and a blob for
/// every named file the package carries.
fn package_routes(
    repository: &str,
    tag: &str,
    config: &[u8],
    files: &[(&str, &[u8])],
) -> Vec<(String, MockResponse)> {
    let mut routes = vec![
        (
            format!("/v2/{repository}/manifests/{tag}"),
            MockResponse::manifest(package_manifest(config, files)),
        ),
        (
            format!("/v2/{repository}/blobs/{}", digest_bytes(config)),
            MockResponse::bytes(config.to_vec(), "application/json"),
        ),
    ];
    for (_, body) in files {
        routes.push((
            format!("/v2/{repository}/blobs/{}", digest_bytes(body)),
            MockResponse::bytes((*body).to_vec(), "application/octet-stream"),
        ));
    }
    routes
}

/// The manifest of a package carrying `files` as its layers.
fn package_manifest(config: &[u8], files: &[(&str, &[u8])]) -> Vec<u8> {
    let layers = files
        .iter()
        .map(|(name, body)| {
            json!({
                "mediaType": "application/octet-stream",
                "digest": digest_bytes(body),
                "size": body.len(),
                "annotations": {"org.opencontainers.image.title": name}
            })
        })
        .collect::<Vec<_>>();
    app_manifest_layers(config, "Version-line app", &layers)
}

/// A config whose install phase records the version it ran as, under `versions`' recipe.
fn marker_config(versions: &serde_json::Value) -> Vec<u8> {
    app_config(&json!({
        "install": {"command": "printf '%s' \"$APP_VERSION\" > version.txt"},
        "versions": versions
    }))
}

fn install_record(env: &CliEnv, app: &str, version: &str) -> serde_json::Value {
    let path = env.state().join(format!("installs/{app}/{version}.json"));
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&body).expect("record json")
}

fn read_state(env: &CliEnv, relative: &str) -> String {
    let path = env.state().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// A version line resolves to a concrete version, and that version's own tag is the
/// package to install. `app:1.5.7` typed out and `app:1.5` resolved record the same
/// reference, so they must not end up with different bits; `default` stands in only where
/// the registry has no such tag.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_of_a_version_line_prefers_the_resolved_versions_own_tag() {
    let source = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.5.7\n1.5.0\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let default_config = app_config(&json!({
        "install": {"command": "sh install.sh"},
        "versions": {"source": "http", "url": format!("{}/versions.txt", source.base_url())}
    }));
    let default_script = b"printf 'default-package' > package.txt\n".to_vec();
    // The 1.5.7 tag carries a different package: another install script, and with it
    // another config and another manifest digest.
    let tag_config = app_config(&json!({"install": {"command": "sh install.sh"}}));
    let tag_script = b"printf 'own-tag' > package.txt\n".to_vec();
    let tag_files: &[(&str, &[u8])] = &[("install.sh", tag_script.as_slice())];

    let mut routes = BTreeMap::new();
    routes.extend(package_routes(
        "acme/line-app",
        "default",
        &default_config,
        &[("install.sh", default_script.as_slice())],
    ));
    routes.extend(package_routes(
        "acme/line-app",
        "1.5.7",
        &tag_config,
        tag_files,
    ));
    let registry = MockServer::start(routes).await;

    let env = CliEnv::new();
    let output = env.run(&[
        "--registry",
        &format!("{}/acme", registry.registry()),
        "install",
        "line-app:1.5",
    ]);

    assert_success(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Resolved line-app:1.5 to 1.5.7 via version discovery"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("installing default package"),
        "the resolved version has a tag of its own: {stderr}"
    );
    // The files are the 1.5.7 tag's, and so is the recorded manifest digest.
    assert_eq!(
        read_state(&env, "apps/line-app/1.5.7/package.txt"),
        "own-tag"
    );
    let record = install_record(&env, "line-app", "1.5.7");
    assert_eq!(
        record["digest"],
        json!(digest_bytes(&package_manifest(&tag_config, tag_files)))
    );
    assert_eq!(
        record["reference"],
        json!(format!("{}/acme/line-app:1.5.7", registry.registry()))
    );
}

/// `orc start` reads a version line off the local install records before it reaches for
/// anything: an installed app starts with the registry — and the version source behind it
/// — unreachable. `orc install` stays network-first; going and looking is its job.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_of_a_version_line_reads_local_records_before_the_network() {
    let source = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.55.0\n1.5.7\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = app_config(&json!({
        "install": {"command": "printf '%s' \"$APP_VERSION\" > version.txt"},
        "start": {"command": "printf 'started:%s\\n' \"$APP_VERSION\""},
        "versions": {"source": "http", "url": format!("{}/versions.txt", source.base_url())}
    }));
    let registry = MockServer::start(
        package_routes("acme/line-app", "default", &config, &[])
            .into_iter()
            .collect(),
    )
    .await;

    let env = CliEnv::new();
    let installed = env.run(&[
        "--registry",
        &format!("{}/acme", registry.registry()),
        "install",
        "line-app:1.5",
    ]);
    assert_success(&installed);
    assert_eq!(read_state(&env, "apps/line-app/1.5.7/version.txt"), "1.5.7");

    // Nothing is listening on this registry, so neither it nor the version source it
    // fronts can be consulted.
    let started = env.run(&["--registry", &dead_registry(), "start", "line-app:1.5"]);
    assert_success(&started);
    assert_eq!(String::from_utf8_lossy(&started.stdout), "started:1.5.7\n");
    assert!(
        !String::from_utf8_lossy(&started.stderr).contains("version discovery"),
        "stderr: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    // The install read the source once; the start read it not at all.
    source.assert_requested_count("/versions.txt", 1);
}

/// A version line is normalized before it is read: a trailing dot and a leading `v` name
/// the same line as the bare number.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_normalizes_a_trailing_dot_and_a_leading_v_in_a_version_line() {
    let source = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.55.0\n1.5.7\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = marker_config(&json!({
        "source": "http",
        "url": format!("{}/versions.txt", source.base_url())
    }));
    let registry = MockServer::start(
        package_routes("acme/line-app", "default", &config, &[])
            .into_iter()
            .collect(),
    )
    .await;
    let prefix = format!("{}/acme", registry.registry());

    // Each spelling gets its own state, so each resolves from nothing.
    for spelling in ["line-app:1.5.", "line-app:v1.5"] {
        let env = CliEnv::new();
        let output = env.run(&["--registry", &prefix, "install", spelling]);
        assert_success(&output);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("pinned to 1.5.7"),
            "{spelling} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            read_state(&env, "apps/line-app/1.5.7/version.txt"),
            "1.5.7",
            "{spelling} must install as 1.5.7"
        );
        assert_eq!(
            install_record(&env, "line-app", "1.5.7")["version"],
            "1.5.7"
        );
    }
}

/// Curation shapes the listing, not what may be installed — and neither does the reader's
/// own hundred-version cap. A source publishing far more than a hundred versions still
/// installs an exact version from below that horizon, whether the curated list offers it
/// or the uncurated evaluation has to reach past the cap for it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_accepts_an_exact_version_beyond_the_uncurated_cap() {
    // 150 versions on the 1.1 line, newest first, then a single 1.0 release: `1.1.0` sits
    // at raw position 149 and `1.0.0` at 150, both past the newest hundred.
    let mut published = (0..150)
        .rev()
        .map(|patch| format!("1.1.{patch}"))
        .collect::<Vec<_>>();
    published.push("1.0.0".to_owned());
    let source = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(published.join("\n").into_bytes(), "text/plain"),
    )]))
    .await;
    let config = marker_config(&json!({
        "source": "http",
        "url": format!("{}/versions.txt", source.base_url()),
        "filter": {"latest_per": "minor"}
    }));
    let mut routes = BTreeMap::from([(
        // `orc versions` reads the repository's own tags alongside the recipe.
        "/v2/acme/deep-app/tags/list".to_owned(),
        MockResponse::json(&json!({"name": "acme/deep-app", "tags": ["default"]})),
    )]);
    routes.extend(package_routes("acme/deep-app", "default", &config, &[]));
    let registry = MockServer::start(routes).await;
    let prefix = format!("{}/acme", registry.registry());
    let env = CliEnv::new();

    // `1.0.0` is the newest on its own minor line, so curation keeps it — and the curated
    // evaluation is the one install-time matching runs first.
    let curated = env.run(&["--registry", &prefix, "install", "deep-app:1.0.0"]);
    assert_success(&curated);
    assert_eq!(read_state(&env, "apps/deep-app/1.0.0/version.txt"), "1.0.0");

    // `1.1.0` is pruned out of the curated list and lies past the raw hundred, so only an
    // uncurated evaluation with the cap lifted can find it.
    let uncurated = env.run(&["--registry", &prefix, "install", "deep-app:1.1.0"]);
    assert_success(&uncurated);
    assert_eq!(read_state(&env, "apps/deep-app/1.1.0/version.txt"), "1.1.0");

    // The listing itself stays curated: one entry per minor line.
    let listed = env.run(&[
        "--registry",
        &prefix,
        "versions",
        "deep-app",
        "--format",
        "json",
    ]);
    assert_success(&listed);
    assert_eq!(listed_versions(&listed), vec!["1.1.149", "1.0.0"]);

    // The uncurated listing is the whole feed: the reader's cap is curation too, and it
    // is lifted with the rest of it.
    let all = env.run(&[
        "--registry",
        &prefix,
        "versions",
        "deep-app",
        "--all",
        "--format",
        "json",
    ]);
    assert_success(&all);
    let all_versions = listed_versions(&all);
    assert_eq!(all_versions.len(), 151);
    assert_eq!(all_versions.last().map(String::as_str), Some("1.0.0"));
}

/// Curated-first is what keeps a heavy release feed readable. The recipe's own `limit`
/// bounds the page the source is asked for; the uncurated evaluation would ask for a full
/// hundred entries, which on this feed overruns the response budget. An exact version the
/// curated list offers installs without that page ever being fetched.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_from_a_heavy_release_feed_never_asks_for_the_uncurated_page() {
    let small_page = json!([
        {"tag_name": "v2.3.0", "prerelease": false},
        {"tag_name": "v2.2.0", "prerelease": false},
        {"tag_name": "v2.1.0", "prerelease": false}
    ]);
    // Over the 16 MiB response cap: whatever asks for this page fails, and the body never
    // has to parse for that to happen — the advertised length is refused first.
    let heavy_page = vec![b'x'; 17 * 1024 * 1024];
    let github = MockServer::start(BTreeMap::from([
        (
            "/repos/acme/heavy/releases?per_page=3".to_owned(),
            MockResponse::json(&small_page),
        ),
        (
            "/repos/acme/heavy/releases?per_page=100".to_owned(),
            MockResponse::bytes(heavy_page, "application/json"),
        ),
    ]))
    .await;
    let config = marker_config(&json!({
        "source": "github_releases",
        "url": "https://github.com/acme/heavy",
        "filter": {"limit": 3}
    }));
    let registry = MockServer::start(
        package_routes("acme/heavy-app", "default", &config, &[])
            .into_iter()
            .collect(),
    )
    .await;

    let env = CliEnv::new();
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "install",
            "heavy-app:2.2.0",
        ])
        .env("ORC_CACHE_DIR", env.cache.path())
        .env("ORC_STATE_DIR", env.state.path())
        .env("ORC_CONFIG_DIR", env.config.path())
        .env("ORC_GITHUB_API_BASE_URL", github.base_url())
        .output()
        .expect("run orc install");

    assert_success(&output);
    assert_eq!(
        read_state(&env, "apps/heavy-app/2.2.0/version.txt"),
        "2.2.0"
    );
    // The page fetched is the one the recipe's limit describes, and only that one.
    github.assert_requested("/repos/acme/heavy/releases?per_page=3");
    github.assert_not_requested("/repos/acme/heavy/releases?per_page=100");
}

/// A forced install replaces the directory it installs into — and only that one. A version
/// line that used to be an exact version, and has since moved on to a longer one, installs
/// alongside the earlier install rather than over it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forced_install_of_a_moved_version_line_keeps_the_earlier_install() {
    // Two servers, because a mock serves static routes and the source has to answer
    // differently before and after the line moves.
    let before = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.5\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let after = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.5.7\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let old_config = marker_config(&json!({
        "source": "http",
        "url": format!("{}/versions.txt", before.base_url())
    }));
    let new_config = marker_config(&json!({
        "source": "http",
        "url": format!("{}/versions.txt", after.base_url())
    }));
    let old_registry = MockServer::start(
        package_routes("acme/line-app", "default", &old_config, &[])
            .into_iter()
            .collect(),
    )
    .await;
    let new_registry = MockServer::start(
        package_routes("acme/line-app", "default", &new_config, &[])
            .into_iter()
            .collect(),
    )
    .await;

    // One machine: both installs share a state directory.
    let env = CliEnv::new();
    let first = env.run(&[
        "--registry",
        &format!("{}/acme", old_registry.registry()),
        "install",
        "line-app:1.5",
    ]);
    assert_success(&first);
    assert_eq!(read_state(&env, "apps/line-app/1.5/version.txt"), "1.5");

    let forced = env.run(&[
        "--registry",
        &format!("{}/acme", new_registry.registry()),
        "install",
        "line-app:1.5",
        "--force",
    ]);
    assert_success(&forced);
    assert_eq!(read_state(&env, "apps/line-app/1.5.7/version.txt"), "1.5.7");
    // The install the force did not touch is still whole: its files and its record.
    assert_eq!(read_state(&env, "apps/line-app/1.5/version.txt"), "1.5");
    assert_eq!(install_record(&env, "line-app", "1.5")["version"], "1.5");
    assert_eq!(
        install_record(&env, "line-app", "1.5.7")["version"],
        "1.5.7"
    );

    let status = env.run(&["status", "line-app", "--format", "json"]);
    assert_success(&status);
    let rows: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    let versions = rows
        .as_array()
        .expect("array")
        .iter()
        .map(|row| row["version"].as_str().expect("version"))
        .collect::<Vec<_>>();
    assert_eq!(versions, vec!["1.5", "1.5.7"]);
}

/// A version the source publishes past its first page is installable by name. The
/// curated pass reads one page and does not find it; the uncurated fallback walks the
/// listing, the way the server's reconcile does, so the CLI and the server agree on
/// what exists. The curated pass is still the cheap one — it never asks for page two.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_install_reaches_a_version_past_the_first_page() {
    let page_one: Vec<serde_json::Value> = (0..100)
        .map(|n| json!({"tag_name": format!("2.0.{}", 100 - n), "prerelease": false}))
        .collect();
    let github = MockServer::start(BTreeMap::from([
        // What the curated pass asks for: one page the size of the recipe's limit.
        (
            "/repos/acme/big/releases?per_page=5".to_owned(),
            MockResponse::json(&json!(page_one[..5])),
        ),
        (
            "/repos/acme/big/releases?per_page=100".to_owned(),
            MockResponse::json(&json!(page_one)),
        ),
        (
            "/repos/acme/big/releases?per_page=100&page=2".to_owned(),
            MockResponse::json(&json!([{"tag_name": "1.0.0", "prerelease": false}])),
        ),
    ]))
    .await;
    let config = app_config(&json!({
        "install": {"command": "printf '%s' \"$APP_VERSION\" > version.txt"},
        // A curated view of the newest few; 1.0.0 is nowhere near it.
        "versions": {
            "source": "github_releases",
            "url": "https://github.com/acme/big",
            "filter": {"limit": 5}
        }
    }));
    let registry = MockServer::start(
        package_routes("acme/big-app", "default", &config, &[])
            .into_iter()
            .collect(),
    )
    .await;

    let env = CliEnv::new();
    let output = Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "--registry",
            &format!("{}/acme", registry.registry()),
            "install",
            "big-app:1.0.0",
        ])
        .env("ORC_CACHE_DIR", env.cache.path())
        .env("ORC_STATE_DIR", env.state.path())
        .env("ORC_CONFIG_DIR", env.config.path())
        .env("ORC_GITHUB_API_BASE_URL", github.base_url())
        .output()
        .expect("run orc install");

    assert_success(&output);
    assert_eq!(read_state(&env, "apps/big-app/1.0.0/version.txt"), "1.0.0");
    // The curated pass asked for its own small page and stopped there; only the
    // uncurated fallback walked on.
    github.assert_requested("/repos/acme/big/releases?per_page=5");
    github.assert_not_requested("/repos/acme/big/releases?per_page=5&page=2");
    github.assert_requested("/repos/acme/big/releases?per_page=100&page=2");
}

/// A version line names the newest *release* on it: a release candidate published
/// against `1.5` does not become what `1.5` installs. Naming the prerelease exactly
/// still installs it — curation shapes what a line means, never what is installable.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_line_installs_the_newest_stable_over_a_prerelease() {
    let source = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.5.8-rc1\n1.5.7\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = app_config(&json!({
        "install": {"command": "printf '%s' \"$APP_VERSION\" > version.txt"},
        "versions": {"source": "http", "url": format!("{}/versions.txt", source.base_url())}
    }));
    let registry = MockServer::start(
        package_routes("acme/line-app", "default", &config, &[])
            .into_iter()
            .collect(),
    )
    .await;

    let env = CliEnv::new();
    let registry_arg = format!("{}/acme", registry.registry());
    let line = env.run(&["--registry", &registry_arg, "install", "line-app:1.5"]);
    assert_success(&line);
    assert_eq!(read_state(&env, "apps/line-app/1.5.7/version.txt"), "1.5.7");
    assert!(
        !env.state().join("apps/line-app/1.5.8-rc1").exists(),
        "the line must not have resolved onto the release candidate"
    );

    let exact = env.run(&["--registry", &registry_arg, "install", "line-app:1.5.8-rc1"]);
    assert_success(&exact);
    assert_eq!(
        read_state(&env, "apps/line-app/1.5.8-rc1/version.txt"),
        "1.5.8-rc1"
    );
}

/// Two installs on one line and a destructive command: `uninstall` and `stop` refuse
/// rather than guess, and name both candidates. An exact version still works, which is
/// what the refusal asks for.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_and_uninstall_refuse_a_version_line_that_names_two_installs() {
    let source = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.5.8-rc1\n1.5.7\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = app_config(&json!({
        "install": {"command": "printf '%s' \"$APP_VERSION\" > version.txt"},
        "uninstall": {"command": "printf '%s' \"$APP_VERSION\" > ../uninstalled.txt"},
        "versions": {"source": "http", "url": format!("{}/versions.txt", source.base_url())}
    }));
    let registry = MockServer::start(
        package_routes("acme/line-app", "default", &config, &[])
            .into_iter()
            .collect(),
    )
    .await;

    let env = CliEnv::new();
    let registry_arg = format!("{}/acme", registry.registry());
    for version in ["line-app:1.5.7", "line-app:1.5.8-rc1"] {
        assert_success(&env.run(&["--registry", &registry_arg, "install", version]));
    }

    let dead = dead_registry();
    for command in ["stop", "uninstall"] {
        let refused = env.run(&["--registry", &dead, command, "line-app:1.5"]);
        assert!(!refused.status.success(), "{command} must refuse the line");
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("1.5.7") && stderr.contains("1.5.8-rc1"),
            "{command} must name both installs: {stderr}"
        );
    }
    // Nothing was removed by the refusals, and naming one exactly still resolves.
    let removed = env.run(&["--registry", &dead, "uninstall", "line-app:1.5.7"]);
    assert_success(&removed);
    assert_eq!(read_state(&env, "apps/line-app/uninstalled.txt"), "1.5.7");
    assert!(env.state().join("apps/line-app/1.5.8-rc1").exists());
}

/// `orc uninstall` and `orc stop` read a version line off the local install records and
/// nothing else. The line names the install it resolved to, and uninstall takes all of it:
/// the app's own uninstall phase, its files, and its record.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uninstall_and_stop_resolve_a_version_line_off_local_records() {
    let source = MockServer::start(BTreeMap::from([(
        "/versions.txt".to_owned(),
        MockResponse::bytes(b"1.5.7\n1.4.9\n".to_vec(), "text/plain"),
    )]))
    .await;
    let config = app_config(&json!({
        "install": {"command": "printf '%s' \"$APP_VERSION\" > version.txt"},
        // The work directory goes away with the uninstall, so the phase leaves its mark
        // one level up, next to it.
        "uninstall": {"command": "printf '%s' \"$APP_VERSION\" > ../uninstalled.txt"},
        "versions": {"source": "http", "url": format!("{}/versions.txt", source.base_url())}
    }));
    let registry = MockServer::start(
        package_routes("acme/line-app", "default", &config, &[])
            .into_iter()
            .collect(),
    )
    .await;

    let env = CliEnv::new();
    let installed = env.run(&[
        "--registry",
        &format!("{}/acme", registry.registry()),
        "install",
        "line-app:1.5",
    ]);
    assert_success(&installed);
    assert_eq!(read_state(&env, "apps/line-app/1.5.7/version.txt"), "1.5.7");

    // Nothing answers on this registry: both commands are local by construction.
    let dead = dead_registry();
    let stopped = env.run(&["--registry", &dead, "stop", "line-app:1.5"]);
    assert_success(&stopped);
    assert!(
        String::from_utf8_lossy(&stopped.stderr).contains("line-app:1.5.7 is not running"),
        "stop must report on the resolved version: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );

    let removed = env.run(&["--registry", &dead, "uninstall", "line-app:1.5"]);
    assert_success(&removed);
    assert!(
        String::from_utf8_lossy(&removed.stderr).contains("Uninstalled line-app:1.5.7"),
        "stderr: {}",
        String::from_utf8_lossy(&removed.stderr)
    );
    assert_eq!(read_state(&env, "apps/line-app/uninstalled.txt"), "1.5.7");
    assert!(
        !env.state().join("apps/line-app/1.5.7").exists(),
        "the resolved install's files must be gone"
    );
    assert!(
        !env.state().join("installs/line-app/1.5.7.json").exists(),
        "the resolved install's record must be gone"
    );
}
