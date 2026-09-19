use std::{sync::Arc, time::Duration};

use crate::error::ConnectError;

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Extra trust roots for tests; `None` = system roots. Chain + hostname validation always runs.
    pub root_store: Option<Arc<rustls::RootCertStore>>,
    pub idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub reconnect: ReconnectPolicy,
    pub send_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            root_store: None,
            idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(10),
            reconnect: ReconnectPolicy::default(),
            send_timeout: Duration::from_secs(10),
        }
    }
}

/// Transparent reconnection behavior for `send_transaction_bytes`. `Default` is
/// enabled with a 10s per-attempt connect timeout, 100ms->5s jittered backoff, and a
/// bounded 10 attempts; set `enabled: false` to opt out.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    pub enabled: bool,
    pub connect_timeout: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_attempts: Option<u32>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            connect_timeout: Duration::from_secs(10),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            max_attempts: Some(10),
        }
    }
}

impl ClientConfig {
    /// Validate operational parameters before dialing.
    pub fn validate(&self) -> Result<(), ConnectError> {
        if let Some(roots) = &self.root_store
            && roots.is_empty()
        {
            return Err(ConnectError::Config(
                "root_store override is empty; every handshake would fail".into(),
            ));
        }
        if self.send_timeout.is_zero() {
            return Err(ConnectError::Config("send_timeout must be > 0".into()));
        }
        if self.idle_timeout.is_zero() {
            return Err(ConnectError::Config("idle_timeout must be > 0".into()));
        }
        if self.keep_alive_interval.is_zero() {
            return Err(ConnectError::Config(
                "keep_alive_interval must be > 0".into(),
            ));
        }
        if self.keep_alive_interval >= self.idle_timeout {
            return Err(ConnectError::Config(
                "keep_alive_interval must be < idle_timeout (else keepalives never fire before idle)".into(),
            ));
        }
        if self.reconnect.connect_timeout.is_zero() {
            return Err(ConnectError::Config(
                "reconnect.connect_timeout must be > 0".into(),
            ));
        }
        if self.reconnect.initial_backoff.is_zero() {
            return Err(ConnectError::Config(
                "reconnect.initial_backoff must be > 0".into(),
            ));
        }
        if self.reconnect.max_backoff < self.reconnect.initial_backoff {
            return Err(ConnectError::Config(
                "reconnect.max_backoff must be >= reconnect.initial_backoff".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_degenerate_config() {
        // A known-good baseline validates.
        assert!(ClientConfig::default().validate().is_ok());

        // Each mutation makes exactly one field degenerate; all must be rejected.
        let good = ClientConfig::default;
        let mutate: [fn(&mut ClientConfig); 8] = [
            |c| c.root_store = Some(Arc::new(rustls::RootCertStore::empty())),
            |c| c.send_timeout = Duration::ZERO,
            |c| c.idle_timeout = Duration::ZERO,
            |c| c.keep_alive_interval = Duration::ZERO,
            |c| c.keep_alive_interval = c.idle_timeout, // == idle_timeout: keepalive too slow
            |c| c.reconnect.connect_timeout = Duration::ZERO,
            |c| c.reconnect.initial_backoff = Duration::ZERO,
            |c| {
                c.reconnect.initial_backoff = Duration::from_secs(2);
                c.reconnect.max_backoff = Duration::from_millis(1);
            },
        ];
        for (i, m) in mutate.iter().enumerate() {
            let mut c = good();
            m(&mut c);
            assert!(c.validate().is_err(), "mutation {i} should be rejected");
        }
    }
}
