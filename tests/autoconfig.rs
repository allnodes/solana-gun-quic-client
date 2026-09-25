mod common;

use {
    common::*,
    solana_gun_quic_client::{
        AutoConfig, AutoConfigError, ConnectError, DEFAULT_DISCOVERY_URL, EndpointSource,
        FallbackReason, SolanaGunQuicClient,
    },
    std::time::Duration,
};

fn expect_discovered(client: &SolanaGunQuicClient) -> (String, Duration) {
    match client.endpoint_source() {
        EndpointSource::Discovered {
            endpoint, latency, ..
        } => (endpoint.clone(), *latency),
        other => panic!("expected Discovered, got {other:?}"),
    }
}

/// Healthy fallback stub plus an `AutoConfig` with discovery at `https_url`.
async fn fallback_auto(ca: &Ca, https_url: String) -> (QuicStub, AutoConfig) {
    let fb = QuicStub::spawn(ca, Duration::ZERO, Handshake::Ok).await;
    let mut auto = auto_config(https_url);
    auto.fallback_endpoint = Some(fb.endpoint());
    (fb, auto)
}

#[tokio::test]
async fn default_discovery_url_is_bundled_and_overridable() {
    assert_eq!(
        DEFAULT_DISCOVERY_URL,
        "https://www.allnodes.com/api/v1/solana-gun/discovery"
    );
    assert_eq!(AutoConfig::default().discovery_url, DEFAULT_DISCOVERY_URL);
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let https = HttpsStub::serve(&ca, 200, &format!(r#"["{}"]"#, stub.endpoint())).await;
    let auto = auto_config(https.url());
    assert_ne!(auto.discovery_url, DEFAULT_DISCOVERY_URL);
    let client = SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto)
        .await
        .expect("connect via overridden discovery url");
    assert_eq!(https.hits(), 1);
    assert_eq!(expect_discovered(&client).0, stub.endpoint());
    client.close().await;
}

#[tokio::test]
async fn selects_lowest_latency_endpoint() {
    let ca = Ca::new();
    let slow = QuicStub::spawn(&ca, Duration::from_millis(300), Handshake::Ok).await;
    let fast = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let https = HttpsStub::serve(
        &ca,
        200,
        &format!(r#"["{}","{}"]"#, slow.endpoint(), fast.endpoint()),
    )
    .await;
    let client =
        SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto_config(https.url()))
            .await
            .unwrap();
    let (endpoint, latency) = expect_discovered(&client);
    assert_eq!(endpoint, fast.endpoint());
    assert!(latency < Duration::from_millis(300), "latency {latency:?}");
    assert_eq!(fast.handshakes(), 1);
    assert_eq!(slow.handshakes(), 0, "probes must not send the token");
    client.close().await;
}

#[tokio::test]
async fn tolerates_partial_probe_failure() {
    let ca = Ca::new();
    let dead = Blackhole::bind();
    let good = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let https = HttpsStub::serve(
        &ca,
        200,
        &format!(r#"["{}","{}"]"#, dead.endpoint(), good.endpoint()),
    )
    .await;
    let client =
        SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto_config(https.url()))
            .await
            .unwrap();
    assert_eq!(expect_discovered(&client).0, good.endpoint());
    client.close().await;
}

#[tokio::test]
async fn accepts_wrapped_response_shape() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let https = HttpsStub::serve(
        &ca,
        200,
        &format!(r#"{{"endpoints":["{}"],"version":2}}"#, stub.endpoint()),
    )
    .await;
    let client =
        SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto_config(https.url()))
            .await
            .unwrap();
    assert_eq!(expect_discovered(&client).0, stub.endpoint());
    client.close().await;
}

#[tokio::test]
async fn discovered_endpoint_is_pinned_across_reconnect() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let https = HttpsStub::serve(&ca, 200, &format!(r#"["{}"]"#, stub.endpoint())).await;
    let (fb, auto) = fallback_auto(&ca, https.url()).await;
    let client = SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto)
        .await
        .unwrap();
    assert_eq!(stub.handshakes(), 1);
    assert_eq!(https.hits(), 1);

    stub.close_all();
    tokio::time::sleep(Duration::from_millis(200)).await;
    client
        .send_transaction_bytes(&[0u8; 8])
        .await
        .expect("send must transparently reconnect");

    assert_eq!(
        stub.handshakes(),
        2,
        "reconnect must re-dial the selected endpoint"
    );
    assert_eq!(https.hits(), 1, "reconnect must not re-run discovery");
    assert_eq!(
        fb.handshakes(),
        0,
        "reconnect must not activate the fallback"
    );
    assert_eq!(expect_discovered(&client).0, stub.endpoint());
    client.close().await;
}

fn expect_fallback(client: &SolanaGunQuicClient) -> (String, FallbackReason) {
    match client.endpoint_source() {
        EndpointSource::Fallback { endpoint, reason } => (endpoint.clone(), reason.clone()),
        other => panic!("expected Fallback, got {other:?}"),
    }
}

fn expect_autoconfig_error(result: Result<SolanaGunQuicClient, ConnectError>) -> AutoConfigError {
    match result {
        Err(ConnectError::AutoConfig(e)) => e,
        Err(other) => panic!("expected ConnectError::AutoConfig, got {other:?}"),
        Ok(_) => panic!("expected an error, got a connected client"),
    }
}

#[tokio::test]
async fn all_probes_fail_uses_fallback_with_reason() {
    let ca = Ca::new();
    let (d1, d2) = (Blackhole::bind(), Blackhole::bind());
    let https = HttpsStub::serve(
        &ca,
        200,
        &format!(r#"["{}","{}"]"#, d1.endpoint(), d2.endpoint()),
    )
    .await;
    let (fb, auto) = fallback_auto(&ca, https.url()).await;
    let client = SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto)
        .await
        .unwrap();
    let (endpoint, reason) = expect_fallback(&client);
    assert_eq!(endpoint, fb.endpoint());
    match reason {
        FallbackReason::AllProbesFailed(list) => {
            assert_eq!(list.len(), 2);
            assert_eq!(list[0].0, d1.endpoint());
            assert!(list[0].1.contains("timed out"), "{}", list[0].1);
        }
        other => panic!("expected AllProbesFailed, got {other:?}"),
    }
    assert_eq!(fb.handshakes(), 1);
    client.close().await;
}

#[tokio::test]
async fn all_probes_fail_without_fallback_is_actionable_error() {
    let ca = Ca::new();
    let dead = Blackhole::bind();
    let https = HttpsStub::serve(&ca, 200, &format!(r#"["{}"]"#, dead.endpoint())).await;
    let err = expect_autoconfig_error(
        SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto_config(https.url()))
            .await,
    );
    assert!(matches!(err.reason, FallbackReason::AllProbesFailed(_)));
    assert!(err.fallback_endpoint.is_none());
    assert!(err.fallback_error.is_none());
    let msg = err.to_string();
    assert!(msg.contains("set AutoConfig::fallback_endpoint"), "{msg}");
}

#[tokio::test]
async fn invalid_and_empty_responses_use_fallback() {
    let ca = Ca::new();
    for body in [
        "not json",
        "[]",
        r#"{"endpoints":[]}"#,
        r#"{"error":"proxy"}"#,
        r#"["no-port"]"#,
    ] {
        let https = HttpsStub::serve(&ca, 200, body).await;
        let (fb, auto) = fallback_auto(&ca, https.url()).await;
        let client = SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto)
            .await
            .unwrap();
        let (endpoint, reason) = expect_fallback(&client);
        assert_eq!(endpoint, fb.endpoint(), "{body:?}");
        assert!(
            matches!(reason, FallbackReason::InvalidResponse(_)),
            "{body:?}: {reason:?}"
        );
        client.close().await;
    }
}

#[tokio::test]
async fn http_error_statuses_surface_api_error_code() {
    let ca = Ca::new();
    for (status, code) in [(503, "ENDPOINTS_NOT_FOUND"), (400, "INVALID_NETWORK")] {
        let https = HttpsStub::serve(&ca, status, &format!(r#"{{"error":"{code}"}}"#)).await;
        let (fb, auto) = fallback_auto(&ca, https.url()).await;
        let client = SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto)
            .await
            .unwrap();
        let (endpoint, reason) = expect_fallback(&client);
        assert_eq!(endpoint, fb.endpoint());
        match reason {
            FallbackReason::DiscoveryFailed(msg) => {
                assert!(
                    msg.contains(&status.to_string()) && msg.contains(code),
                    "{msg}"
                );
            }
            other => panic!("expected DiscoveryFailed, got {other:?}"),
        }
        client.close().await;
    }
}

#[tokio::test]
async fn https_to_http_redirect_is_refused() {
    let ca = Ca::new();
    let good = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let plain = HttpsStub::serve_plain(200, &format!(r#"["{}"]"#, good.endpoint())).await;
    let https = HttpsStub::redirect_to(&ca, &plain.url()).await;
    let (fb, auto) = fallback_auto(&ca, https.url()).await;
    let client = SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto)
        .await
        .unwrap();
    let (endpoint, reason) = expect_fallback(&client);
    assert_eq!(endpoint, fb.endpoint());
    assert!(
        matches!(reason, FallbackReason::DiscoveryFailed(_)),
        "{reason:?}"
    );
    assert_eq!(https.hits(), 1);
    assert_eq!(
        plain.hits(),
        0,
        "the http:// redirect target must not be contacted"
    );
    assert_eq!(good.handshakes(), 0);
    client.close().await;
}

#[tokio::test]
async fn only_reachable_endpoint_beyond_concurrency_window_is_selected() {
    let ca = Ca::new();
    let dead: Vec<Blackhole> = (0..32).map(|_| Blackhole::bind()).collect();
    let good = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let mut list: Vec<String> = dead
        .iter()
        .map(|d| format!("\"{}\"", d.endpoint()))
        .collect();
    list.push(format!("\"{}\"", good.endpoint()));
    let https = HttpsStub::serve(&ca, 200, &format!("[{}]", list.join(","))).await;
    let client =
        SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto_config(https.url()))
            .await
            .expect("the 33rd endpoint must still be probed and selected");
    assert_eq!(expect_discovered(&client).0, good.endpoint());
    client.close().await;
}

#[tokio::test]
async fn fallback_failure_reports_both_errors() {
    let ca = Ca::new();
    let https = HttpsStub::serve(&ca, 200, "not json").await;
    let dead = Blackhole::bind();
    let mut auto = auto_config(https.url());
    auto.fallback_endpoint = Some(dead.endpoint());
    let err = expect_autoconfig_error(
        SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto).await,
    );
    assert!(matches!(err.reason, FallbackReason::InvalidResponse(_)));
    assert_eq!(
        err.fallback_endpoint.as_deref(),
        Some(dead.endpoint().as_str())
    );
    assert!(err.fallback_error.is_some());
    let msg = err.to_string();
    assert!(msg.contains("discovery response invalid"), "{msg}");
    assert!(
        msg.contains(&format!(
            "fallback endpoint {} also failed",
            dead.endpoint()
        )),
        "{msg}"
    );
}

#[tokio::test]
async fn fallback_endpoint_is_pinned_across_reconnect() {
    let ca = Ca::new();
    let https = HttpsStub::serve(&ca, 200, "not json").await;
    let (fb, auto) = fallback_auto(&ca, https.url()).await;
    let client = SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto)
        .await
        .unwrap();
    assert_eq!(fb.handshakes(), 1);
    assert_eq!(https.hits(), 1);

    fb.close_all();
    tokio::time::sleep(Duration::from_millis(200)).await;
    client
        .send_transaction_bytes(&[0u8; 8])
        .await
        .expect("send must transparently reconnect");

    assert_eq!(
        fb.handshakes(),
        2,
        "reconnect must re-dial the fallback endpoint"
    );
    assert_eq!(https.hits(), 1, "reconnect must not re-run discovery");
    assert!(matches!(
        client.endpoint_source(),
        EndpointSource::Fallback { .. }
    ));
    client.close().await;
}

#[tokio::test]
async fn initial_connect_failure_after_selection_uses_fallback() {
    let ca = Ca::new();
    // QUIC probe succeeds; the token handshake is closed with a non-terminal code.
    let bad = QuicStub::spawn(&ca, Duration::ZERO, Handshake::CloseWith(0x77)).await;
    let https = HttpsStub::serve(&ca, 200, &format!(r#"["{}"]"#, bad.endpoint())).await;
    let (fb, auto) = fallback_auto(&ca, https.url()).await;
    let client = SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto)
        .await
        .unwrap();
    let (endpoint, reason) = expect_fallback(&client);
    assert_eq!(endpoint, fb.endpoint());
    match reason {
        FallbackReason::InitialConnectFailed { endpoint, error } => {
            assert_eq!(endpoint, bad.endpoint());
            assert!(error.contains("0x77"), "{error}");
        }
        other => panic!("expected InitialConnectFailed, got {other:?}"),
    }
    assert_eq!(bad.handshakes(), 1);
    assert_eq!(fb.handshakes(), 1);
    client.close().await;
}

#[tokio::test]
async fn token_rejection_after_selection_uses_fallback() {
    let ca = Ca::new();
    let unauthorized = QuicStub::spawn(&ca, Duration::ZERO, Handshake::CloseWith(0x01)).await;
    let https = HttpsStub::serve(&ca, 200, &format!(r#"["{}"]"#, unauthorized.endpoint())).await;
    let (fb, auto) = fallback_auto(&ca, https.url()).await;
    let client = SolanaGunQuicClient::connect_auto("tok", client_config(&ca), auto)
        .await
        .unwrap();
    let (endpoint, reason) = expect_fallback(&client);
    assert_eq!(endpoint, fb.endpoint());
    match reason {
        FallbackReason::InitialConnectFailed { endpoint, error } => {
            assert_eq!(endpoint, unauthorized.endpoint());
            assert!(error.contains("unauthorized"), "{error}");
        }
        other => panic!("expected InitialConnectFailed, got {other:?}"),
    }
    assert_eq!(unauthorized.handshakes(), 1);
    assert_eq!(fb.handshakes(), 1);
    client.close().await;
}

#[tokio::test]
async fn manual_connect_never_touches_discovery() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let https = HttpsStub::serve(&ca, 200, &format!(r#"["{}"]"#, stub.endpoint())).await;
    let client = SolanaGunQuicClient::connect(&stub.endpoint(), "tok", client_config(&ca))
        .await
        .unwrap();
    assert!(matches!(client.endpoint_source(), EndpointSource::Manual));
    client.close().await;
    let addr = stub.endpoint().parse().unwrap();
    let client = SolanaGunQuicClient::connect_addr(addr, "127.0.0.1", "tok", client_config(&ca))
        .await
        .unwrap();
    assert!(matches!(client.endpoint_source(), EndpointSource::Manual));
    client.close().await;
    assert_eq!(
        https.hits(),
        0,
        "manual constructors must not call the discovery API"
    );
    assert_eq!(
        stub.handshakes(),
        2,
        "exactly the two real connections, no probes"
    );
}
