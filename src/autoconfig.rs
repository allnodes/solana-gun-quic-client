//! Opt-in endpoint autoconfiguration: discover endpoints over HTTPS, probe them over
//! QUIC, connect to the fastest, and optionally fall back to a static endpoint.

use {
    crate::{
        client::{self, SolanaGunQuicClient},
        config::ClientConfig,
        error::{AutoConfigError, ConnectError},
        tls,
    },
    serde::Deserialize,
    std::{
        fmt,
        net::SocketAddr,
        sync::Arc,
        time::{Duration, Instant},
    },
    tokio::{sync::Semaphore, task::JoinSet},
};

/// Bundled discovery API.
pub const DEFAULT_DISCOVERY_URL: &str = "https://www.allnodes.com/api/v1/solana-gun/discovery";

/// Settings for [`SolanaGunQuicClient::connect_auto`](crate::SolanaGunQuicClient::connect_auto).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct AutoConfig {
    /// Discovery API URL; must be `https://`.
    pub discovery_url: String,
    /// Static `host:port` used when autoconfiguration cannot establish the initial
    /// connection. `None` means such failures return [`ConnectError::AutoConfig`].
    pub fallback_endpoint: Option<String>,
    /// Ceiling on the whole discovery request.
    pub discovery_timeout: Duration,
    /// Ceiling on DNS resolution per endpoint and on the QUIC handshake per address.
    pub probe_timeout: Duration,
}

impl Default for AutoConfig {
    fn default() -> Self {
        Self {
            discovery_url: DEFAULT_DISCOVERY_URL.to_owned(),
            fallback_endpoint: None,
            discovery_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(3),
        }
    }
}

impl AutoConfig {
    /// Reject degenerate settings before any network activity.
    pub fn validate(&self) -> Result<(), ConnectError> {
        if self.discovery_url.is_empty() {
            return Err(ConnectError::Config("discovery_url is empty".into()));
        }
        if !self.discovery_url.starts_with("https://") {
            return Err(ConnectError::Config(
                "discovery_url must start with https://".into(),
            ));
        }
        if self.discovery_timeout.is_zero() {
            return Err(ConnectError::Config("discovery_timeout must be > 0".into()));
        }
        if self.probe_timeout.is_zero() {
            return Err(ConnectError::Config("probe_timeout must be > 0".into()));
        }
        if let Some(fallback) = &self.fallback_endpoint {
            client::split_host_port(fallback)
                .map_err(|e| ConnectError::Config(format!("fallback_endpoint: {e}")))?;
        }
        Ok(())
    }
}

/// How the client's active endpoint was chosen; fixed for the client's lifetime.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum EndpointSource {
    /// Supplied by the caller via `connect` / `connect_addr`.
    Manual,
    /// Lowest-latency endpoint returned by the discovery API.
    Discovered {
        endpoint: String,
        addr: SocketAddr,
        latency: Duration,
    },
    /// `AutoConfig::fallback_endpoint`, used because of `reason`.
    Fallback {
        endpoint: String,
        reason: FallbackReason,
    },
}

/// Why the static fallback was used, or why autoconfiguration failed without one.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum FallbackReason {
    /// Transport error, timeout, refused redirect, or non-2xx status (with the body's
    /// `error` code when present, e.g. `503 ENDPOINTS_NOT_FOUND`).
    DiscoveryFailed(String),
    /// Body is not an accepted JSON shape or has no usable `host:port` entries.
    InvalidResponse(String),
    /// Every discovered endpoint failed its probe; `(endpoint, error)` per endpoint.
    AllProbesFailed(Vec<(String, String)>),
    /// The selected endpoint failed the dial or token handshake.
    InitialConnectFailed { endpoint: String, error: String },
}

impl fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DiscoveryFailed(e) => write!(f, "discovery request failed: {e}"),
            Self::InvalidResponse(e) => write!(f, "discovery response invalid: {e}"),
            Self::AllProbesFailed(list) => {
                write!(
                    f,
                    "all {} discovered endpoints failed their probes:",
                    list.len()
                )?;
                for (endpoint, error) in list {
                    write!(f, " [{endpoint}: {error}]")?;
                }
                Ok(())
            }
            Self::InitialConnectFailed { endpoint, error } => write!(
                f,
                "selected endpoint {endpoint} failed the initial connection: {error}"
            ),
        }
    }
}

/// Accepted discovery response shapes; unknown fields are ignored.
#[derive(Deserialize)]
#[serde(untagged)]
enum DiscoveryBody {
    Bare(Vec<String>),
    Wrapped { endpoints: Vec<String> },
}

/// Trimmed, deduplicated `host:port` entries in discovery order; invalid entries dropped.
pub(crate) fn parse_endpoints(body: &str) -> Result<Vec<String>, FallbackReason> {
    let parsed: DiscoveryBody = serde_json::from_str(body)
        .map_err(|e| FallbackReason::InvalidResponse(format!("not a JSON endpoint list: {e}")))?;
    let raw = match parsed {
        DiscoveryBody::Bare(v) | DiscoveryBody::Wrapped { endpoints: v } => v,
    };
    let total = raw.len();
    let mut out: Vec<String> = Vec::new();
    for entry in &raw {
        let entry = entry.trim();
        if entry.is_empty() || client::split_host_port(entry).is_err() {
            continue;
        }
        if !out.iter().any(|e| e == entry) {
            out.push(entry.to_owned());
        }
    }
    if out.is_empty() {
        return Err(FallbackReason::InvalidResponse(format!(
            "no usable endpoints in {total} entries"
        )));
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub(crate) struct ProbeOk {
    pub endpoint: String,
    pub addr: SocketAddr,
    pub latency: Duration,
}

/// Index into `results` of the lowest latency; ties go to the earlier discovery index.
pub(crate) fn select_best(results: &[(usize, ProbeOk)]) -> Option<usize> {
    results
        .iter()
        .enumerate()
        .min_by_key(|(_, (order, ok))| (ok.latency, *order))
        .map(|(i, _)| i)
}

/// Upper bound on concurrent endpoint probes; every endpoint is still probed.
const MAX_CONCURRENT_PROBES: usize = 16;

pub(crate) async fn connect_auto(
    token: &str,
    config: ClientConfig,
    auto: AutoConfig,
) -> Result<SolanaGunQuicClient, ConnectError> {
    config.validate()?;
    client::validate_token(token)?;
    auto.validate()?;
    let config = with_resolved_roots(config).await?;

    let reason = match try_discovered(token, &config, &auto).await {
        Ok(client) => return Ok(client),
        Err(reason) => reason,
    };
    tracing::warn!(%reason, "autoconfiguration could not use a discovered endpoint");

    let Some(fallback) = auto.fallback_endpoint.as_deref() else {
        tracing::error!(%reason, "autoconfiguration failed and no fallback_endpoint is configured");
        return Err(AutoConfigError {
            reason,
            fallback_endpoint: None,
            fallback_error: None,
        }
        .into());
    };
    let source = EndpointSource::Fallback {
        endpoint: fallback.to_owned(),
        reason: reason.clone(),
    };
    match SolanaGunQuicClient::connect_with_source(fallback, token, config, source).await {
        Ok(client) => {
            tracing::info!(endpoint = fallback, %reason, "connected via static fallback endpoint");
            Ok(client)
        }
        Err(e) => {
            tracing::error!(endpoint = fallback, %reason, error = %e, "static fallback endpoint failed");
            Err(AutoConfigError {
                reason,
                fallback_endpoint: Some(fallback.to_owned()),
                fallback_error: Some(Box::new(e)),
            }
            .into())
        }
    }
}

/// Loads system roots once, off the runtime, so probes neither block on nor time the
/// load and every connection in the run shares one store.
async fn with_resolved_roots(mut config: ClientConfig) -> Result<ClientConfig, ConnectError> {
    if config.root_store.is_none() {
        let roots = tokio::task::spawn_blocking(tls::system_roots)
            .await
            .map_err(|e| ConnectError::Tls(format!("loading system roots: {e}")))??;
        config.root_store = Some(Arc::new(roots));
    }
    Ok(config)
}

async fn try_discovered(
    token: &str,
    config: &ClientConfig,
    auto: &AutoConfig,
) -> Result<SolanaGunQuicClient, FallbackReason> {
    let endpoints = discover(&auto.discovery_url, auto.discovery_timeout, config).await?;
    let best = probe_all(&endpoints, config, auto.probe_timeout).await?;
    let (host, _) =
        client::split_host_port(&best.endpoint).map_err(FallbackReason::InvalidResponse)?;
    let source = EndpointSource::Discovered {
        endpoint: best.endpoint.clone(),
        addr: best.addr,
        latency: best.latency,
    };
    match SolanaGunQuicClient::connect_addr_with_source(
        best.addr,
        host,
        token,
        config.clone(),
        source,
    )
    .await
    {
        Ok(client) => {
            tracing::info!(
                endpoint = best.endpoint,
                addr = %best.addr,
                latency_ms = best.latency.as_millis() as u64,
                "connected via discovered endpoint"
            );
            Ok(client)
        }
        Err(e) => Err(FallbackReason::InitialConnectFailed {
            endpoint: best.endpoint,
            error: e.to_string(),
        }),
    }
}

async fn discover(
    url: &str,
    timeout: Duration,
    config: &ClientConfig,
) -> Result<Vec<String>, FallbackReason> {
    let tls_config = tls::https_client_config(config.root_store.as_ref())
        .map_err(|e| FallbackReason::DiscoveryFailed(format!("tls setup: {e}")))?;
    let http = reqwest::Client::builder()
        .timeout(timeout)
        .https_only(true)
        .use_preconfigured_tls(tls_config)
        .build()
        .map_err(|e| {
            FallbackReason::DiscoveryFailed(format!("http client: {}", error_chain(&e)))
        })?;
    tracing::debug!(url, "sending discovery request");
    let response = http
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| FallbackReason::DiscoveryFailed(error_chain(&e)))?;
    let status = response.status();
    let body = response.text().await.map_err(|e| {
        FallbackReason::DiscoveryFailed(format!(
            "{}: reading body: {}",
            status.as_u16(),
            error_chain(&e)
        ))
    })?;
    if !status.is_success() {
        return Err(FallbackReason::DiscoveryFailed(format!(
            "{} {}",
            status.as_u16(),
            error_summary(&body)
        )));
    }
    let endpoints = parse_endpoints(&body)?;
    tracing::debug!(
        url,
        status = status.as_u16(),
        endpoint_count = endpoints.len(),
        "discovery response received"
    );
    Ok(endpoints)
}

/// The API's `{"error": "..."}` code, else the first 200 chars of the body.
fn error_summary(body: &str) -> String {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    match serde_json::from_str::<ErrorBody>(body) {
        Ok(e) => e.error,
        Err(_) => body.chars().take(200).collect(),
    }
}

/// Error with its `source()` chain; reqwest's top-level message alone is too vague.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(next) = cur {
        out.push_str(": ");
        out.push_str(&next.to_string());
        cur = next.source();
    }
    out
}

async fn probe_all(
    endpoints: &[String],
    config: &ClientConfig,
    timeout: Duration,
) -> Result<ProbeOk, FallbackReason> {
    let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES));
    let mut set = JoinSet::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        let endpoint = endpoint.clone();
        let config = config.clone();
        let limiter = Arc::clone(&limiter);
        set.spawn(async move {
            let _permit = limiter
                .acquire_owned()
                .await
                .expect("semaphore is never closed");
            let result = probe_one(&endpoint, &config, timeout).await;
            (index, endpoint, result)
        });
    }
    let mut results: Vec<(usize, ProbeOk)> = Vec::new();
    let mut failures: Vec<(usize, String, String)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        let (index, endpoint, result) = match joined {
            Ok(r) => r,
            Err(e) => {
                failures.push((usize::MAX, "<probe task>".into(), e.to_string()));
                continue;
            }
        };
        match result {
            Ok((addr, latency)) => {
                tracing::debug!(endpoint, %addr, latency_ms = latency.as_millis() as u64, "probe succeeded");
                results.push((
                    index,
                    ProbeOk {
                        endpoint,
                        addr,
                        latency,
                    },
                ));
            }
            Err(error) => {
                tracing::debug!(endpoint, error, "probe failed");
                failures.push((index, endpoint, error));
            }
        }
    }
    results.sort_by_key(|(i, _)| *i);
    let Some(best_i) = select_best(&results) else {
        failures.sort_by_key(|(i, _, _)| *i);
        return Err(FallbackReason::AllProbesFailed(
            failures.into_iter().map(|(_, e, err)| (e, err)).collect(),
        ));
    };
    let ranking: Vec<String> = results
        .iter()
        .map(|(_, ok)| format!("{}={}ms", ok.endpoint, ok.latency.as_millis()))
        .collect();
    let best = results[best_i].1.clone();
    tracing::info!(
        endpoint = best.endpoint,
        addr = %best.addr,
        latency_ms = best.latency.as_millis() as u64,
        candidates = ?ranking,
        failed = failures.len(),
        "selected lowest-latency endpoint"
    );
    Ok(best)
}

async fn probe_one(
    endpoint: &str,
    config: &ClientConfig,
    timeout: Duration,
) -> Result<(SocketAddr, Duration), String> {
    let (host, _) = client::split_host_port(endpoint)?;
    let addrs: Vec<SocketAddr> = tokio::time::timeout(timeout, tokio::net::lookup_host(endpoint))
        .await
        .map_err(|_| format!("dns lookup timed out after {timeout:?}"))?
        .map_err(|e| format!("dns: {e}"))?
        .collect();
    probe_addrs(addrs, host, config, timeout).await
}

/// Probes all addresses concurrently, each under its own `timeout`, and returns the
/// fastest success. On total failure, returns the first address's error.
pub(crate) async fn probe_addrs(
    addrs: Vec<SocketAddr>,
    server_name: &str,
    config: &ClientConfig,
    timeout: Duration,
) -> Result<(SocketAddr, Duration), String> {
    if addrs.is_empty() {
        return Err("no addresses".into());
    }
    let mut set = JoinSet::new();
    for (index, addr) in addrs.into_iter().enumerate() {
        let server_name = server_name.to_owned();
        let config = config.clone();
        set.spawn(async move {
            let result = match tokio::time::timeout(
                timeout,
                probe_addr(addr, &server_name, &config),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => Err(format!("probe timed out after {timeout:?}")),
            };
            (index, addr, result)
        });
    }
    let mut best: Option<(SocketAddr, Duration)> = None;
    let mut first_err: Option<(usize, String)> = None;
    while let Some(joined) = set.join_next().await {
        let Ok((index, addr, result)) = joined else {
            continue;
        };
        match result {
            Ok(latency) => {
                if best.is_none_or(|(_, b)| latency < b) {
                    best = Some((addr, latency));
                }
            }
            Err(e) => {
                if first_err.as_ref().is_none_or(|(i, _)| index < *i) {
                    first_err = Some((index, format!("{addr}: {e}")));
                }
            }
        }
    }
    best.ok_or_else(|| {
        first_err
            .map(|(_, e)| e)
            .unwrap_or_else(|| "probe task failed".into())
    })
}

/// Times a TLS-verified QUIC handshake. No token is sent, so probes never use a
/// per-token connection slot.
async fn probe_addr(
    addr: SocketAddr,
    server_name: &str,
    config: &ClientConfig,
) -> Result<Duration, String> {
    let endpoint = client::build_endpoint(addr, config).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let connection = endpoint
        .connect(addr, server_name)
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    let latency = started.elapsed();
    connection.close(quinn::VarInt::from_u32(0), b"probe");
    Ok(latency)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_degenerate_config() {
        let mutate: [fn(&mut AutoConfig); 7] = [
            |a| a.discovery_url = String::new(),
            |a| a.discovery_url = "http://127.0.0.1:8080/discovery".into(),
            |a| a.discovery_url = "ftp://example.com/x".into(),
            |a| a.discovery_url = "www.allnodes.com/api".into(),
            |a| a.discovery_timeout = Duration::ZERO,
            |a| a.probe_timeout = Duration::ZERO,
            |a| a.fallback_endpoint = Some("fra1.solanagun.com".into()),
        ];
        for (i, m) in mutate.iter().enumerate() {
            let mut a = AutoConfig::default();
            m(&mut a);
            assert!(
                matches!(a.validate(), Err(ConnectError::Config(_))),
                "mutation {i} should be rejected"
            );
        }
        let ok = AutoConfig {
            discovery_url: "https://127.0.0.1:8443/discovery".into(),
            fallback_endpoint: Some("[::1]:7000".into()),
            ..AutoConfig::default()
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn parse_filters_trims_and_dedupes_without_truncating() {
        let got = parse_endpoints(
            r#"[" fra1:7000 ", "fra1:7000", "", "nohost", "bad:0", "bad:99999", "bad:abc", "[2001:db8::1]:7000"]"#,
        )
        .unwrap();
        assert_eq!(got, ["fra1:7000", "[2001:db8::1]:7000"]);

        let many: Vec<String> = (1..=100).map(|i| format!("\"h{i}:7000\"")).collect();
        let all = parse_endpoints(&format!("[{}]", many.join(","))).unwrap();
        assert_eq!(all.len(), 100);
        assert_eq!(all[99], "h100:7000");
    }

    #[tokio::test]
    async fn probe_addrs_keeps_success_regardless_of_address_order() {
        let (good, roots) = crate::client::test_support::spawn_stub_server().await;
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead = blackhole.local_addr().unwrap();
        let config = ClientConfig {
            root_store: Some(roots),
            ..ClientConfig::default()
        };
        let timeout = Duration::from_millis(500);

        for addrs in [vec![dead, good], vec![good, dead]] {
            let started = Instant::now();
            let (addr, latency) = probe_addrs(addrs, "127.0.0.1", &config, timeout)
                .await
                .expect("the reachable address must win");
            assert_eq!(addr, good);
            assert!(latency < timeout, "latency {latency:?}");
            assert!(
                started.elapsed() < timeout * 2,
                "addresses must be probed concurrently, took {:?}",
                started.elapsed()
            );
        }
        let err = probe_addrs(vec![dead], "127.0.0.1", &config, timeout)
            .await
            .unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert!(
            probe_addrs(vec![], "127.0.0.1", &config, timeout)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn system_roots_are_resolved_once_for_the_whole_run() {
        let resolved = with_resolved_roots(ClientConfig::default()).await.unwrap();
        assert!(resolved.root_store.as_ref().is_some_and(|r| !r.is_empty()));

        let (_, roots) = crate::client::test_support::spawn_stub_server().await;
        let config = ClientConfig {
            root_store: Some(Arc::clone(&roots)),
            ..ClientConfig::default()
        };
        let kept = with_resolved_roots(config).await.unwrap();
        assert!(Arc::ptr_eq(kept.root_store.as_ref().unwrap(), &roots));
    }
}
