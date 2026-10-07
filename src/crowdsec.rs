//! A [CrowdSec](https://www.crowdsec.net) bouncer: blocks the IPs and ranges the
//! CrowdSec Local API bans. Requires the `crowdsec` feature.
//!
//! ```rust,no_run
//! use axum_ipware::crowdsec::CrowdSec;
//! use axum_ipware::IpFilter;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let filter = IpFilter::new();
//! // Register the bouncer with `cscli bouncers add axum-app` to get a key.
//! let bouncer = CrowdSec::new("http://127.0.0.1:8080", "<bouncer key>")?
//!     .refresh(&filter.handle())?
//!     .spawn();
//! # Ok(())
//! # }
//! ```
//!
//! The bouncer polls the decisions stream, keeps the active `ban` decisions with
//! `Ip` or `Range` scope, and installs them as the block list `crowdsec`. The
//! first poll and every poll after an error fetch the full state, so a missed
//! update never leaves stale bans behind.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipware::IpRanges;
use serde_json::Value;

use crate::filter::IpFilterHandle;
use crate::refresh::{read_capped, BoxError, InvalidUrl, Refresh, Safeguards, Source};

/// Connection settings for the CrowdSec Local API.
#[derive(Clone, Debug)]
pub struct CrowdSec {
    url: reqwest::Url,
    api_key: String,
    insecure_http: bool,
    decision_types: HashSet<String>,
}

impl CrowdSec {
    /// Connects to the Local API at `url` with a bouncer API key.
    ///
    /// `https://` URLs are always accepted; `http://` only for loopback hosts
    /// such as `127.0.0.1` or `localhost`, unless
    /// [`allow_insecure_http`](Self::allow_insecure_http) is set.
    pub fn new(url: &str, api_key: impl Into<String>) -> Result<Self, InvalidUrl> {
        let url = reqwest::Url::parse(url).map_err(|_| InvalidUrl(url.to_owned()))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(InvalidUrl(url.to_string()));
        }
        Ok(CrowdSec {
            url,
            api_key: api_key.into(),
            insecure_http: false,
            decision_types: HashSet::from(["ban".to_owned()]),
        })
    }

    /// Accepts `http://` URLs with non-loopback hosts, such as a container name
    /// on a private Docker network. The API key and decisions travel unencrypted.
    pub fn allow_insecure_http(mut self) -> Self {
        self.insecure_http = true;
        self
    }

    /// The decision types to block. Defaults to `ban`.
    pub fn decision_types<I, T>(mut self, types: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.decision_types = types
            .into_iter()
            .map(|kind| kind.into().to_ascii_lowercase())
            .collect();
        self
    }

    fn check_scheme(&self) -> Result<(), BoxError> {
        if self.url.scheme() == "https" || self.insecure_http {
            return Ok(());
        }
        let host = self.url.host_str().unwrap_or_default();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if loopback {
            Ok(())
        } else {
            Err(format!(
                "refusing plain http to {}; use https or CrowdSec::allow_insecure_http",
                self.url
            )
            .into())
        }
    }

    /// A [`Source`] that returns the active decisions as one range per line.
    pub fn source(&self) -> Result<Source, InvalidUrl> {
        self.check_scheme()
            .map_err(|_| InvalidUrl(self.url.to_string()))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("axum-ipware/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| InvalidUrl(self.url.to_string()))?;
        let stream_url = self
            .url
            .join("v1/decisions/stream")
            .map_err(|_| InvalidUrl(self.url.to_string()))?;
        let settings = Arc::new(self.clone());
        // Active decisions by id; `None` until the next poll fetches the full state.
        let decisions: Arc<Mutex<Option<HashMap<i64, String>>>> = Arc::default();
        Ok(Source::from_loader(move |max_bytes| {
            let (client, url, settings, decisions) = (
                client.clone(),
                stream_url.clone(),
                settings.clone(),
                decisions.clone(),
            );
            Box::pin(async move {
                let current = decisions.lock().expect("decision state lock").clone();
                let result = poll(&client, url, &settings, current, max_bytes).await;
                let mut state = decisions.lock().expect("decision state lock");
                match result {
                    Ok(active) => {
                        let text = active.values().cloned().collect::<Vec<_>>().join("\n");
                        *state = Some(active);
                        Ok(text)
                    }
                    Err(err) => {
                        // Fetch the full state next time.
                        *state = None;
                        Err(err)
                    }
                }
            })
        }))
    }

    /// A [`Refresh`] of the block list `crowdsec`, polling every 10 seconds.
    ///
    /// Its safeguards accept empty lists and sudden changes, since bans expire
    /// and arrive in bulk, but keep the size and address coverage limits of
    /// [`Safeguards::for_block_lists`]. Adjust it before calling
    /// [`spawn`](Refresh::spawn).
    pub fn refresh(&self, handle: &IpFilterHandle) -> Result<Refresh, InvalidUrl> {
        Ok(Refresh::block_list(handle, "crowdsec")
            .source(self.source()?)
            .every(Duration::from_secs(10))
            .safeguards(
                Safeguards::for_block_lists()
                    .allow_empty(true)
                    .max_shrink(None)
                    .max_growth(None),
            ))
    }
}

/// Fetches one batch of decisions and applies it to `current`.
async fn poll(
    client: &reqwest::Client,
    mut url: reqwest::Url,
    settings: &CrowdSec,
    current: Option<HashMap<i64, String>>,
    max_bytes: usize,
) -> Result<HashMap<i64, String>, BoxError> {
    let startup = current.is_none();
    url.query_pairs_mut()
        .append_pair("startup", if startup { "true" } else { "false" })
        .append_pair("scopes", "ip,range");
    let mut response = client
        .get(url)
        .header("X-Api-Key", &settings.api_key)
        .send()
        .await?
        .error_for_status()?;
    let body = read_capped(&mut response, max_bytes).await?;
    let mut active = current.unwrap_or_default();
    apply(
        &mut active,
        &serde_json::from_str(&body)?,
        &settings.decision_types,
    )?;
    Ok(active)
}

/// Applies a stream response `{"new": [...], "deleted": [...]}` to `active`.
fn apply(
    active: &mut HashMap<i64, String>,
    response: &Value,
    types: &HashSet<String>,
) -> Result<(), BoxError> {
    let decisions = |key: &str| -> Result<Vec<Value>, BoxError> {
        match response.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) => Ok(items.clone()),
            Some(_) => Err(format!("`{key}` is not a list of decisions").into()),
        }
    };
    for decision in decisions("deleted")? {
        if let Some(id) = decision.get("id").and_then(Value::as_i64) {
            active.remove(&id);
        }
    }
    for decision in decisions("new")? {
        let field = |name: &str| decision.get(name).and_then(Value::as_str);
        let (Some(id), Some(value)) = (decision.get("id").and_then(Value::as_i64), field("value"))
        else {
            continue;
        };
        let scope = field("scope").unwrap_or_default().to_ascii_lowercase();
        let kind = field("type").unwrap_or_default().to_ascii_lowercase();
        if !types.contains(&kind) || !matches!(scope.as_str(), "ip" | "range") {
            continue;
        }
        if IpRanges::parse([value]).is_err() {
            tracing::warn!(value, "ignoring CrowdSec decision with an invalid address");
            continue;
        }
        active.insert(id, value.to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bans() -> HashSet<String> {
        HashSet::from(["ban".to_owned()])
    }

    #[test]
    fn applies_new_and_deleted_decisions() {
        let mut active = HashMap::new();
        let startup = serde_json::json!({
            "new": [
                {"id": 1, "scope": "Ip", "type": "ban", "value": "203.0.113.9"},
                {"id": 2, "scope": "Range", "type": "ban", "value": "198.51.100.0/24"},
                {"id": 3, "scope": "Ip", "type": "captcha", "value": "192.0.2.1"},
                {"id": 4, "scope": "Country", "type": "ban", "value": "RU"},
                {"id": 5, "scope": "Ip", "type": "ban", "value": "not-an-ip"},
                {"id": 6, "scope": "Ip", "type": "ban", "value": "203.0.113.9"}
            ],
            "deleted": null
        });
        apply(&mut active, &startup, &bans()).unwrap();
        let mut values: Vec<_> = active.values().cloned().collect();
        values.sort();
        assert_eq!(values, ["198.51.100.0/24", "203.0.113.9", "203.0.113.9"]);

        // Deleting one of two bans on the same IP keeps it banned.
        let update = serde_json::json!({"new": null, "deleted": [{"id": 1}, {"id": 2}]});
        apply(&mut active, &update, &bans()).unwrap();
        assert_eq!(active.values().collect::<Vec<_>>(), ["203.0.113.9"]);

        let empty = serde_json::json!({"new": null, "deleted": null});
        apply(&mut active, &empty, &bans()).unwrap();
        assert_eq!(active.len(), 1);

        assert!(apply(&mut active, &serde_json::json!({"new": "x"}), &bans()).is_err());
    }

    #[test]
    fn only_loopback_http_by_default() {
        assert!(CrowdSec::new("http://127.0.0.1:8080", "k")
            .unwrap()
            .source()
            .is_ok());
        assert!(CrowdSec::new("http://localhost:8080", "k")
            .unwrap()
            .source()
            .is_ok());
        assert!(CrowdSec::new("http://[::1]:8080", "k")
            .unwrap()
            .source()
            .is_ok());
        assert!(CrowdSec::new("https://lapi.example.com", "k")
            .unwrap()
            .source()
            .is_ok());
        let docker = CrowdSec::new("http://crowdsec:8080", "k").unwrap();
        assert!(docker.source().is_err());
        assert!(docker.allow_insecure_http().source().is_ok());
        assert!(CrowdSec::new("ftp://127.0.0.1", "k").is_err());
        assert!(CrowdSec::new("not a url", "k").is_err());
    }
}
