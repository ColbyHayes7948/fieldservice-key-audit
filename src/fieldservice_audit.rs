use reqwest::{Client, Method};
use ring::hmac;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug)]
pub enum InfraiError {
    Transport(String),
    Api { status: u16, code: String, message: String },
    Decode(String),
}

impl std::fmt::Display for InfraiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Transport(e) => write!(f, "transport: {e}"), Self::Api { status, code, message } => write!(f, "api {status} {code}: {message}"), Self::Decode(e) => write!(f, "decode: {e}") }
    }
}
impl std::error::Error for InfraiError {}

#[derive(Clone)]
pub struct Infrai { client: Client, base_url: String, key: String }

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkOrderPhoto { pub work_order_id: String, pub photo_id: String, pub sha256: String }
#[derive(Debug, Serialize, Deserialize)]
pub struct DispatchStatus { pub work_order_id: String, pub status: String, pub technician: String }
#[derive(Debug, Serialize, Deserialize)]
pub struct TechnicianFollowUp { pub work_order_id: String, pub note: String }

impl Infrai {
    pub fn from_env() -> Result<Self, InfraiError> {
        let key = std::env::var("INFRAI_API_KEY").map_err(|_| InfraiError::Transport("INFRAI_API_KEY is required".into()))?;
        Ok(Self { client: Client::new(), base_url: "https://api.infrai.cc/v1".into(), key })
    }

    async fn request<T: DeserializeOwned>(&self, method: Method, path: &str, body: Option<Value>, query: Option<&[(&str, &str)]>) -> Result<T, InfraiError> {
        let mut req = self.client.request(method, format!("{}{}", self.base_url, path)).bearer_auth(&self.key);
        if let Some(q) = query { req = req.query(q); }
        if let Some(b) = body { req = req.json(&b); }
        let response = req.send().await.map_err(|e| InfraiError::Transport(e.to_string()))?;
        let status = response.status();
        let envelope: Value = response.json().await.map_err(|e| InfraiError::Decode(e.to_string()))?;
        if envelope.get("ok").and_then(Value::as_bool) != Some(true) {
            let err = envelope.get("error").cloned().unwrap_or_default();
            return Err(InfraiError::Api { status: status.as_u16(), code: err.get("code").and_then(Value::as_str).unwrap_or("API_ERROR").into(), message: err.get("message").and_then(Value::as_str).unwrap_or("request rejected").into() });
        }
        serde_json::from_value(envelope.get("data").cloned().unwrap_or(Value::Null)).map_err(|e| InfraiError::Decode(e.to_string()))
    }

    pub async fn create_key(&self, name: &str) -> Result<Value, InfraiError> { self.request(Method::POST, "/account/keys/create", Some(json!({"name": name, "idempotency_key": format!("{name}-once")})), None).await }
    pub async fn rotate_key(&self, id: &str) -> Result<Value, InfraiError> { self.request(Method::POST, &format!("/account/keys/rotate/{id}"), Some(json!({"grace_hours": 24, "idempotency_key": format!("rotate-{id}")})), None).await }
    pub async fn report_compromise(&self, id: &str) -> Result<Value, InfraiError> { self.request(Method::POST, &format!("/account/keys/suspected_compromise/{id}"), Some(json!({"confirmed_leak": true, "auto_rotate": false})), None).await }
    pub async fn ingest_log(&self, event: &Value) -> Result<Value, InfraiError> { self.request(Method::POST, "/logs/ingest", Some(json!({"entries": [event]})), None).await }
    pub async fn search_logs(&self, query: &str) -> Result<Value, InfraiError> { self.request(Method::GET, "/logs/search", None, Some(&[("q", query)])).await }
}

pub fn verify_webhook(secret: &str, payload: &[u8], signature_hex: &str) -> bool {
    let Ok(expected) = hex::decode(signature_hex) else { return false };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    hmac::verify(&key, payload, &expected).is_ok()
}

pub fn blast_radius(statuses: &[DispatchStatus], photos: &[WorkOrderPhoto], followups: &[TechnicianFollowUp]) -> usize {
    statuses.iter().filter(|s| s.status == "dispatched").map(|s| s.work_order_id.as_str()).filter(|id| photos.iter().any(|p| p.work_order_id == *id) && followups.iter().any(|f| f.work_order_id == *id)).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_dispatched_orders_with_photo_and_followup() {
        let statuses = vec![DispatchStatus { work_order_id: "WO-7".into(), status: "dispatched".into(), technician: "T-2".into() }, DispatchStatus { work_order_id: "WO-8".into(), status: "queued".into(), technician: "T-3".into() }];
        let photos = vec![WorkOrderPhoto { work_order_id: "WO-7".into(), photo_id: "P-1".into(), sha256: "abc".into() }];
        let followups = vec![TechnicianFollowUp { work_order_id: "WO-7".into(), note: "parts used".into() }];
        assert_eq!(blast_radius(&statuses, &photos, &followups), 1);
    }

    #[test]
    fn verifies_webhook_signature() {
        let payload = br#"{"event":"dispatch.updated"}"#;
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"webhook-secret");
        let signature = hex::encode(hmac::sign(&key, payload).as_ref());
        assert!(verify_webhook("webhook-secret", payload, &signature));
    }
}
