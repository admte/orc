use orc_app::credential::StoredCredential;
use orc_app::error::{CliError, Result};

#[derive(Debug, Clone)]
pub struct GitHubPackageLister {
    http: reqwest::Client,
    api_base: String,
    token: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Package {
    name: String,
    #[serde(default)]
    package_type: String,
}

impl GitHubPackageLister {
    pub fn new(credential: Option<&StoredCredential>) -> Result<Self> {
        let api_base = std::env::var("ORC_GITHUB_API_BASE_URL")
            .unwrap_or_else(|_| "https://api.github.com".to_owned())
            .trim_end_matches('/')
            .to_owned();
        let http = reqwest::Client::builder()
            .user_agent(concat!("orc-cli/", env!("ORC_VERSION")))
            .build()
            .map_err(|err| CliError::Operational(format!("build GitHub client: {err}")))?;
        Ok(Self {
            http,
            api_base,
            token: credential.map(|credential| credential.token.clone()),
        })
    }

    pub async fn list_container_packages(&self, namespace: &str) -> Result<Vec<String>> {
        let (owner, package_prefix) = namespace
            .split_once('/')
            .map_or((namespace, ""), |(owner, rest)| (owner, rest));
        if owner.is_empty() {
            return Err(CliError::Usage(
                "ghcr.io listing requires an owner namespace".to_owned(),
            ));
        }

        let org_path = format!("/orgs/{owner}/packages?package_type=container&per_page=100");
        let packages = match self.get_json::<Vec<Package>>(&org_path).await {
            Ok(packages) => packages,
            Err(CliError::NotFound(_) | CliError::Auth(_)) => {
                let user_path =
                    format!("/users/{owner}/packages?package_type=container&per_page=100");
                self.get_json::<Vec<Package>>(&user_path).await?
            }
            Err(err) => return Err(err),
        };

        let prefix = if package_prefix.is_empty() {
            String::new()
        } else {
            format!("{package_prefix}/")
        };
        Ok(packages
            .into_iter()
            .filter(|package| {
                package.package_type.is_empty() || package.package_type == "container"
            })
            .filter_map(|package| {
                if prefix.is_empty() {
                    Some(package.name)
                } else {
                    package.name.strip_prefix(&prefix).map(str::to_owned)
                }
            })
            .collect())
    }

    async fn get_json<T>(&self, path: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut request = self.http.get(format!("{}{path}", self.api_base));
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|err| CliError::Operational(format!("GitHub GET {path}: {err}")))?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(CliError::Auth(format!("GitHub access denied for {path}")));
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::NotFound(format!(
                "GitHub resource not found: {path}"
            )));
        }
        if !status.is_success() {
            return Err(CliError::Operational(format!(
                "GitHub GET {path} returned {status}"
            )));
        }
        response
            .json()
            .await
            .map_err(|err| CliError::Operational(format!("decode GitHub response: {err}")))
    }
}
