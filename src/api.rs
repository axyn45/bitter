use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Determines the API and Identity URLs from the user-configured server URL
pub fn get_endpoints(server_url: &str) -> (String, String) {
    let server = server_url.trim_end_matches('/');
    if server.contains("bitwarden.com") {
        (
            "https://api.bitwarden.com".to_string(),
            "https://identity.bitwarden.com".to_string(),
        )
    } else {
        (format!("{}/api", server), format!("{}/identity", server))
    }
}

/// Determines the Notifications URL from the user-configured server URL
pub fn get_notifications_endpoints(server_url: &str) -> String {
    let server = server_url.trim_end_matches('/');
    if server.contains("bitwarden.com") {
        "https://notifications.bitwarden.com".to_string()
    } else {
        server.to_string() // Self-hosted Vaultwarden hosts it on the same domain
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginRequest {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: u32,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct KdfJson {
    pub kdf_type: u32,
    pub iterations: u32,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MasterPasswordUnlockJson {
    pub kdf: KdfJson,
    pub master_key_wrapped_user_key: String,
    pub salt: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct UserDecryptionOptionsJson {
    pub has_master_password: bool,
    pub master_password_unlock: Option<MasterPasswordUnlockJson>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u32,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub key: String, // MasterKeyWrappedUserKey
    pub kdf: u32,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
    pub user_decryption_options: Option<UserDecryptionOptionsJson>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSync {
    pub id: String,
    pub email: String,
    pub key: String, // MasterKeyWrappedUserKey
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FieldSync {
    pub name: String,
    pub value: Option<String>,
    pub r#type: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LoginSync {
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentSync {
    pub id: String,
    pub file_name: Option<String>,
    pub size: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SshKeySync {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherSync {
    pub id: String,
    pub r#type: i32, // 1: Login, 2: SecureNote, etc.
    pub name: Option<String>,
    pub notes: Option<String>,
    pub fields: Option<Vec<FieldSync>>,
    pub login: Option<LoginSync>,
    pub attachments: Option<Vec<AttachmentSync>>,
    pub ssh_key: Option<SshKeySync>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: ProfileSync,
    pub ciphers: Vec<CipherSync>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NegotiateResponse {
    #[serde(alias = "ConnectionToken")]
    pub connection_token: Option<String>,
    #[serde(alias = "ConnectionId")]
    pub connection_id: Option<String>,
    #[serde(alias = "Url")]
    pub url: Option<String>,
}

pub struct ApiClient {
    client: reqwest::Client,
    api_url: String,
    identity_url: String,
}

impl ApiClient {
    pub fn new(server_url: &str) -> Self {
        let (api_url, identity_url) = get_endpoints(server_url);
        ApiClient {
            client: reqwest::Client::new(),
            api_url,
            identity_url,
        }
    }

    /// Fetches the user's client-side KDF configuration via prelogin endpoint
    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse, String> {
        let url = format!("{}/accounts/prelogin", self.api_url);
        let req = PreloginRequest {
            email: email.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Prelogin failed with status: {}",
                response.status()
            ));
        }

        let resp: PreloginResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse prelogin response: {}", e))?;

        Ok(resp)
    }

    /// Authenticates using master password (email + login hash)
    pub async fn login_password(
        &self,
        email: &str,
        login_hash: &str,
        device_id: &str,
        device_name: &str,
    ) -> Result<TokenResponse, String> {
        let url = format!("{}/connect/token", self.identity_url);

        let mut params = HashMap::new();
        params.insert("grant_type", "password".to_string());
        params.insert("client_id", "cli".to_string());
        params.insert("scope", "api offline_access".to_string());
        params.insert("username", email.to_string());
        params.insert("password", login_hash.to_string());
        params.insert("device_identifier", device_id.to_string());
        params.insert("device_name", device_name.to_string());
        params.insert("device_type", "14".to_string()); // CLI type is 14

        let response = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Login request failed: {}", e))?;

        if !response.status().is_success() {
            let err_text = response.text().await.unwrap_or_default();
            return Err(format!("Login failed ({}): {}", url, err_text));
        }

        let token_resp: TokenResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        Ok(token_resp)
    }

    /// Authenticates using Personal API Key client credentials
    pub async fn login_api_key(
        &self,
        client_id: &str,
        client_secret: &str,
        device_id: &str,
        device_name: &str,
    ) -> Result<TokenResponse, String> {
        let url = format!("{}/connect/token", self.identity_url);

        let mut params = HashMap::new();
        params.insert("grant_type", "client_credentials".to_string());
        params.insert("client_id", client_id.to_string());
        params.insert("client_secret", client_secret.to_string());
        params.insert("scope", "api".to_string());
        params.insert("device_identifier", device_id.to_string());
        params.insert("device_name", device_name.to_string());
        params.insert("device_type", "14".to_string()); // CLI type is 14

        let response = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("API Key Login request failed: {}", e))?;

        if !response.status().is_success() {
            let err_text = response.text().await.unwrap_or_default();
            return Err(format!("API Key Login failed: {}", err_text));
        }

        let token_resp: TokenResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        Ok(token_resp)
    }

    /// Fetches the user's encrypted vault payload
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse, String> {
        let url = format!("{}/sync", self.api_url);

        let response = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("Sync request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Sync failed with status: {}", response.status()));
        }

        let sync_resp: SyncResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse sync response: {}", e))?;

        Ok(sync_resp)
    }

    /// Fetches individual cipher details
    pub async fn get_cipher_details(
        &self,
        access_token: &str,
        cipher_id: &str,
    ) -> Result<CipherSync, String> {
        let url = format!("{}/ciphers/{}/details", self.api_url, cipher_id);

        let response = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("Cipher details request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Failed to fetch cipher details: {}",
                response.status()
            ));
        }

        let cipher_resp: CipherSync = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse cipher details response: {}", e))?;

        Ok(cipher_resp)
    }

    /// Negotiates a SignalR WebSocket connection token
    pub async fn negotiate(
        &self,
        token: &str,
        notifications_url: &str,
    ) -> Result<NegotiateResponse, String> {
        let url = format!(
            "{}/notifications/hub/negotiate",
            notifications_url.trim_end_matches('/')
        );
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| format!("Negotiation request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let err_text = response.text().await.unwrap_or_default();
            return Err(format!(
                "Negotiation failed with status {}: {}",
                status, err_text
            ));
        }

        let negotiate_resp: NegotiateResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse negotiate JSON: {}", e))?;

        Ok(negotiate_resp)
    }
}
