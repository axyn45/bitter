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
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "expires_in")]
    pub expires_in: u32,
    #[serde(rename = "token_type")]
    pub token_type: String,
    #[serde(rename = "refresh_token")]
    pub refresh_token: Option<String>,
    pub key: String, // MasterKeyWrappedUserKey
    pub kdf: u32,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
    pub user_decryption_options: Option<UserDecryptionOptionsJson>,
}
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct RefreshTokenResponse {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "expires_in")]
    pub expires_in: u32,
    #[serde(rename = "token_type")]
    pub token_type: String,
    #[serde(rename = "refresh_token")]
    pub refresh_token: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationSync {
    pub id: String,
    pub name: String,
    pub key: String,
    pub object: String,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSync {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub premium: bool,
    pub premium_from_organization: bool,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub security_stamp: Option<String>,
    pub two_factor_enabled: bool,
    pub uses_key_connector: bool,
    pub culture: String,
    pub creation_date: String,
    pub avatar_color: Option<String>,
    pub force_password_reset: bool,
    pub key: String, // MasterKeyWrappedUserKey
    pub organizations: Option<Vec<OrganizationSync>>,
    pub provider_organizations: Option<Vec<serde_json::Value>>,
    pub providers: Option<Vec<serde_json::Value>>,
    #[serde(rename = "_status")]
    pub _status: Option<i32>,
    pub object: String,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
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
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    pub r#type: i32, // 1: Login, 2: SecureNote, etc.
    pub name: Option<String>,
    pub notes: Option<String>,
    pub favorite: bool,
    pub reprompt: i32,
    pub organization_use_totp: bool,
    pub edit: bool,
    pub view_password: bool,
    pub creation_date: String,
    pub revision_date: String,
    pub deleted_date: Option<String>,
    pub archived_date: Option<String>,
    pub key: Option<String>,
    pub login: Option<LoginSync>,
    pub card: Option<serde_json::Value>,
    pub identity: Option<serde_json::Value>,
    pub secure_note: Option<serde_json::Value>,
    pub ssh_key: Option<SshKeySync>,
    pub fields: Option<Vec<FieldSync>>,
    pub attachments: Option<Vec<AttachmentSync>>,
    pub collection_ids: Option<Vec<String>>,
    pub password_history: Option<Vec<serde_json::Value>>,
    pub permissions: Option<serde_json::Value>,
    pub object: String,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FolderSync {
    pub id: String,
    pub name: String,
    pub object: String,
    pub revision_date: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KdfSync {
    pub kdf_type: u32,
    pub iterations: u32,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordUnlockSync {
    pub kdf: KdfSync,
    pub master_key_wrapped_user_key: String,
    pub salt: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserDecryptionSync {
    pub master_password_unlock: Option<MasterPasswordUnlockSync>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: ProfileSync,
    pub ciphers: Vec<CipherSync>,
    pub folders: Option<Vec<FolderSync>>,
    pub domains: Option<serde_json::Value>,
    pub policies: Option<Vec<serde_json::Value>>,
    pub sends: Option<Vec<serde_json::Value>>,
    pub object: String,
    pub user_decryption: Option<UserDecryptionSync>,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
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

#[derive(Clone)]
pub struct ApiClient {
    client: reqwest::Client,
    api_url: String,
    identity_url: String,
}

impl ApiClient {
    pub fn new(server_url: &str) -> Self {
        let (api_url, identity_url) = get_endpoints(server_url);
        use reqwest::header::{HeaderMap, HeaderValue};
        
        let mut headers = HeaderMap::new();
        headers.insert("X-Client-Type", HeaderValue::from_static("web"));
        headers.insert("X-Client-Version", HeaderValue::from_static("2026.1.0"));
        headers.insert("Bitwarden-Client-Version", HeaderValue::from_static("2026.1.0"));
        headers.insert("X-Client-Feature-Flags", HeaderValue::from_static("ssh-key-vault-item,ssh-agent"));
        headers.insert("Device-Type", HeaderValue::from_static("9"));
        headers.insert("device-type", HeaderValue::from_static("9"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        ApiClient {
            client,
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
        params.insert("client_id", "web".to_string());
        params.insert("scope", "api offline_access".to_string());
        params.insert("username", email.to_string());
        params.insert("password", login_hash.to_string());
        params.insert("device_identifier", device_id.to_string());
        params.insert("device_name", device_name.to_string());
        params.insert("device_type", "9".to_string()); // Chrome Browser type is 9

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

    /// Refreshes access token using a refresh token
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<RefreshTokenResponse, String> {
        let url = format!("{}/connect/token", self.identity_url);

        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token".to_string());
        params.insert("client_id", "web".to_string());
        params.insert("refresh_token", refresh_token.to_string());

        let response = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Token refresh request failed: {}", e))?;

        if !response.status().is_success() {
            let err_text = response.text().await.unwrap_or_default();
            return Err(format!("Token refresh failed ({}): {}", url, err_text));
        }

        let resp: RefreshTokenResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        Ok(resp)
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
        params.insert("device_type", "9".to_string()); // Chrome Browser type is 9

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

    pub async fn exchange_sso_code(
        &self,
        client_id: &str,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        device_id: &str,
    ) -> Result<TokenResponse, String> {
        let url = format!("{}/connect/token", self.identity_url);

        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code".to_string());
        params.insert("client_id", client_id.to_string());
        params.insert("redirect_uri", redirect_uri.to_string());
        params.insert("code", code.to_string());
        params.insert("code_verifier", code_verifier.to_string());
        params.insert("deviceIdentifier", device_id.to_string());
        params.insert("deviceName", "bitter_client".to_string());
        params.insert("deviceType", "9".to_string());

        let response = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("SSO token exchange request failed: {}", e))?;

        if !response.status().is_success() {
            let err_text = response.text().await.unwrap_or_default();
            return Err(format!("SSO token exchange failed: {}", err_text));
        }

        let token_resp: TokenResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse SSO token response: {}", e))?;

        Ok(token_resp)
    }

    pub async fn fetch_sso_prevalidate_token(&self) -> Result<Option<String>, String> {
        let url = format!("{}/sso/prevalidate", self.identity_url);
        
        let response = match self.client.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => return Err(format!("SSO prevalidate request failed: {}", e)),
        };

        if !response.status().is_success() {
            return Ok(None);
        }

        #[derive(Deserialize)]
        struct PrevalidateResponse {
            token: String,
        }

        match response.json::<PrevalidateResponse>().await {
            Ok(json_resp) => Ok(Some(json_resp.token)),
            Err(_) => Ok(None),
        }
    }

    /// Fetches the user's encrypted vault payload
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse, String> {
        let url = format!("{}/sync?excludeDomains=true", self.api_url);

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
            let mut err_text = response.text().await.unwrap_or_default();
            if err_text.trim().starts_with('<') {
                err_text = "HTML response (possibly a proxy 404 or page not found)".to_string();
            } else if err_text.len() > 120 {
                err_text.truncate(120);
                err_text.push_str("...");
            }
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
