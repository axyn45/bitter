use ssh_encoding::Encode;
use ssh_key::private::PrivateKey;
use tracing::{debug, warn};

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        if self.offset + 1 > self.data.len() {
            return Err("Unexpected EOF reading u8".to_string());
        }
        let val = self.data[self.offset];
        self.offset += 1;
        Ok(val)
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        if self.offset + 4 > self.data.len() {
            return Err("Unexpected EOF reading u32".to_string());
        }
        let val = u32::from_be_bytes(self.data[self.offset..self.offset + 4].try_into().unwrap());
        self.offset += 4;
        Ok(val)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.offset + len > self.data.len() {
            return Err("Unexpected EOF reading bytes".to_string());
        }
        let val = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(val)
    }

    fn read_string(&mut self) -> Result<&'a [u8], String> {
        let len = self.read_u32()? as usize;
        self.read_bytes(len)
    }
}

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    fn write_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    fn write_bytes(&mut self, val: &[u8]) {
        self.buf.extend_from_slice(val);
    }

    fn write_string(&mut self, val: &[u8]) {
        self.write_u32(val.len() as u32);
        self.write_bytes(val);
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

// SSH Agent message types
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_FAILURE: u8 = 5;

// RSA SHA2 flags
const _SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

pub fn handle_agent_request(request_data: &[u8], keys: &[PrivateKey]) -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(request_data);
    let msg_type = reader.read_u8()?;
    debug!("SSH Agent request received, type: {}", msg_type);

    match msg_type {
        SSH2_AGENTC_REQUEST_IDENTITIES => {
            debug!("SSH Agent requested identities. Returning {} keys.", keys.len());
            let mut writer = Writer::new();
            writer.write_u8(SSH2_AGENT_IDENTITIES_ANSWER);
            writer.write_u32(keys.len() as u32);

            for key in keys {
                let pubkey = key.public_key();
                let pubkey_bytes = pubkey
                    .to_bytes()
                    .map_err(|e| format!("Failed to serialize public key: {}", e))?;
                writer.write_string(&pubkey_bytes);
                writer.write_string(key.comment().as_bytes());
            }

            Ok(writer.into_bytes())
        }
        SSH2_AGENTC_SIGN_REQUEST => {
            let pubkey_blob = reader.read_string()?;
            let data_to_sign = reader.read_string()?;
            let _flags = reader.read_u32()?;
            debug!("SSH Agent signature request received. Looking for matching public key...");

            // Find matching key
            let mut matching_key = None;
            for key in keys {
                let pubkey = key.public_key();
                let pubkey_bytes = pubkey
                    .to_bytes()
                    .map_err(|e| format!("Failed to serialize public key: {}", e))?;
                if pubkey_bytes == pubkey_blob {
                    matching_key = Some(key);
                    break;
                }
            }

            let key = match matching_key {
                Some(k) => {
                    debug!("Found matching key: '{}'", k.comment());
                    k
                }
                None => {
                    warn!("No matching key found in keyring for signature request.");
                    let mut writer = Writer::new();
                    writer.write_u8(SSH_AGENT_FAILURE);
                    return Ok(writer.into_bytes());
                }
            };

            use signature::Signer;

            // Perform signature
            debug!("Signing raw SSH agent challenge ({} bytes)...", data_to_sign.len());
            let signature = key
                .try_sign(data_to_sign)
                .map_err(|e| format!("Signing failed: {}", e))?;

            // Serialize signature to standard SSH signature format
            let mut sig_bytes = Vec::new();
            signature
                .encode(&mut sig_bytes)
                .map_err(|e| format!("Failed to serialize signature: {}", e))?;
            debug!("Signature generated successfully ({} bytes).", sig_bytes.len());

            let mut writer = Writer::new();
            writer.write_u8(SSH2_AGENT_SIGN_RESPONSE);
            writer.write_string(&sig_bytes);

            Ok(writer.into_bytes())
        }
        _ => {
            // Return failure for unsupported messages
            warn!("Unsupported SSH Agent request code: {}", msg_type);
            let mut writer = Writer::new();
            writer.write_u8(SSH_AGENT_FAILURE);
            Ok(writer.into_bytes())
        }
    }
}
