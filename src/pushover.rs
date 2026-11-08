//! Pushover Messages API client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;

/// Emergency (priority 2) retry/expire parameters required by Pushover.
pub const EMERGENCY_RETRY_SECS: u32 = 60;
pub const EMERGENCY_EXPIRE_SECS: u32 = 3600;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    pub title: Option<String>,
    pub message: String,
    pub priority: i8,
    pub url: Option<String>,
    pub url_title: Option<String>,
    pub device: Option<String>,
    pub sound: Option<String>,
}

#[derive(Debug)]
pub enum SendError {
    /// Network error or timeout.
    Transport,
    /// Pushover answered with a non-success status.
    Upstream(u16),
}

#[derive(Deserialize)]
struct ApiResponse {
    status: i64,
}

/// Unknown until the first Pushover response.
const QUOTA_UNKNOWN: u64 = u64::MAX;

pub struct PushoverClient {
    http: reqwest::Client,
    url: String,
    token: String,
    user: String,
    remaining: AtomicU64,
}

impl PushoverClient {
    pub fn new(url: String, token: String, user: String) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("metriccupid-push/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            url,
            token,
            user,
            remaining: AtomicU64::new(QUOTA_UNKNOWN),
        })
    }

    /// Last `X-Limit-App-Remaining` seen, if any.
    pub fn quota_remaining(&self) -> Option<u64> {
        match self.remaining.load(Ordering::Relaxed) {
            QUOTA_UNKNOWN => None,
            n => Some(n),
        }
    }

    fn form(&self, m: &Message) -> Vec<(&'static str, String)> {
        let mut f = vec![
            ("token", self.token.clone()),
            ("user", self.user.clone()),
            ("message", m.message.clone()),
            ("priority", m.priority.to_string()),
        ];
        let optional = [
            ("title", &m.title),
            ("url", &m.url),
            ("url_title", &m.url_title),
            ("device", &m.device),
            ("sound", &m.sound),
        ];
        for (k, v) in optional {
            if let Some(v) = v {
                f.push((k, v.clone()));
            }
        }
        if m.priority == 2 {
            f.push(("retry", EMERGENCY_RETRY_SECS.to_string()));
            f.push(("expire", EMERGENCY_EXPIRE_SECS.to_string()));
        }
        f
    }

    pub async fn send(&self, m: &Message) -> Result<(), SendError> {
        let resp = self
            .http
            .post(&self.url)
            .form(&self.form(m))
            .send()
            .await
            .map_err(|_| SendError::Transport)?;

        if let Some(n) = resp
            .headers()
            .get("x-limit-app-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            self.remaining
                .store(n.min(QUOTA_UNKNOWN - 1), Ordering::Relaxed);
        }

        let status = resp.status();
        if !status.is_success() {
            return Err(SendError::Upstream(status.as_u16()));
        }
        // Pushover signals success with {"status":1}.
        let body = resp.bytes().await.map_err(|_| SendError::Transport)?;
        match serde_json::from_slice::<ApiResponse>(&body) {
            Ok(r) if r.status == 1 => Ok(()),
            _ => Err(SendError::Upstream(status.as_u16())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> PushoverClient {
        PushoverClient::new("http://127.0.0.1:1".into(), "tok".into(), "usr".into()).unwrap()
    }

    #[test]
    fn form_minimal() {
        let c = client();
        let m = Message {
            message: "hi".into(),
            ..Default::default()
        };
        let f = c.form(&m);
        assert_eq!(
            f,
            vec![
                ("token", "tok".to_string()),
                ("user", "usr".to_string()),
                ("message", "hi".to_string()),
                ("priority", "0".to_string()),
            ]
        );
    }

    #[test]
    fn form_emergency_adds_retry_expire() {
        let c = client();
        let m = Message {
            message: "x".into(),
            priority: 2,
            title: Some("t".into()),
            device: Some("phone".into()),
            ..Default::default()
        };
        let f = c.form(&m);
        assert!(f.contains(&("title", "t".into())));
        assert!(f.contains(&("device", "phone".into())));
        assert!(f.contains(&("retry", "60".into())));
        assert!(f.contains(&("expire", "3600".into())));
    }

    #[test]
    fn quota_unknown_initially() {
        assert_eq!(client().quota_remaining(), None);
    }
}
