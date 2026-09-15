use serde::{Deserialize, Serialize};

/// A docker-login-style credential as stored in the CLI config: a username
/// and a secret (password, PAT, or API key).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoredCredential {
    pub username: String,
    pub token: String,
}

/// The credential a registry client authenticates with. The kind is explicit
/// rather than inferred from the username.
#[derive(Debug, Clone)]
pub enum RegistryCredential {
    /// A docker-login username/secret pair, driven through the challenge
    /// flow: exchanged at a Bearer realm's token endpoint, or sent as Basic
    /// when the registry challenges with Basic.
    Basic { username: String, secret: String },
    /// A pre-minted registry bearer token (an internally minted registry
    /// JWT). Sent as-is; it cannot be exchanged at a token service.
    Bearer { token: String },
}

impl From<&StoredCredential> for RegistryCredential {
    fn from(credential: &StoredCredential) -> Self {
        Self::Basic {
            username: credential.username.clone(),
            secret: credential.token.clone(),
        }
    }
}
