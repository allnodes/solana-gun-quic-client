mod common;

use {
    common::{
        Ca, Handshake, HttpsStub, PlainStub, QuicStub, StubOptions, auto_config, client_config,
        plain_config,
        relay::{Relay, RelayOptions},
    },
    solana_gun_quic_client::{
        ClientConfig, ConnectError, EndpointSource, FallbackReason, HandshakeError, Security,
        SendError, SolanaGunQuicClient, plaintext,
    },
    std::time::{Duration, Instant},
    tracing_test::traced_test,
};

const WARNING: &str =
    "server identity is not verified; the token is sent to an unauthenticated server";

fn is_unencrypted_token_error(e: &ConnectError) -> bool {
    matches!(e, ConnectError::Config(m) if m == "authenticated submission without encryption is unsupported")
}

#[tokio::test]
async fn token_plus_unencrypted_fails_before_any_io() {
    let mut cfg = ClientConfig::default();
    cfg.security = Security::Unencrypted;

    let started = Instant::now();
    let err = SolanaGunQuicClient::connect("192.0.2.1:9", "tok", cfg.clone())
        .await
        .map(|_| ())
        .expect_err("must fail");
    assert!(is_unencrypted_token_error(&err), "{err}");

    let err =
        SolanaGunQuicClient::connect_addr("192.0.2.1:9".parse().unwrap(), "x", "tok", cfg.clone())
            .await
            .map(|_| ())
            .expect_err("must fail");
    assert!(is_unencrypted_token_error(&err), "{err}");

    let mut auto = auto_config("https://192.0.2.1:9/discover".into());
    auto.discovery_timeout = Duration::from_secs(5);
    let err = SolanaGunQuicClient::connect_auto("tok", cfg, auto)
        .await
        .map(|_| ())
        .expect_err("must fail");
    assert!(is_unencrypted_token_error(&err), "{err}");

    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn skip_verification_connects_to_a_self_signed_server_and_verified_does_not() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;

    let mut skip = ClientConfig::default();
    skip.security = Security::SkipVerification;
    skip.reconnect.connect_timeout = Duration::from_secs(3);
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        SolanaGunQuicClient::connect(&stub.endpoint(), "tok", skip),
    )
    .await
    .expect("connect timed out")
    .expect("skip-verification must connect");
    client.close().await;

    // Roots of an unrelated CA: the stub's self-signed certificate is untrusted.
    let other = Ca::new();
    let verified = client_config(&other);
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        SolanaGunQuicClient::connect(&stub.endpoint(), "tok", verified),
    )
    .await
    .expect("connect timed out")
    .map(|_| ())
    .expect_err("verified must refuse an untrusted certificate");
    assert!(!matches!(err, ConnectError::Config(_)), "{err}");
}

#[traced_test]
#[tokio::test]
async fn skip_verification_with_token_warns_once() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let mut cfg = ClientConfig::default();
    cfg.security = Security::SkipVerification;
    cfg.reconnect.connect_timeout = Duration::from_secs(3);
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        SolanaGunQuicClient::connect(&stub.endpoint(), "tok", cfg),
    )
    .await
    .expect("connect timed out")
    .expect("connect");
    client
        .send_transaction_bytes(&[1u8; 64])
        .await
        .expect("send");
    client.close().await;

    logs_assert(|lines: &[&str]| {
        let n = lines.iter().filter(|l| l.contains(WARNING)).count();
        if n == 1 {
            Ok(())
        } else {
            Err(format!("expected 1 warning, got {n}"))
        }
    });
}

#[traced_test]
#[tokio::test]
async fn skip_verification_with_token_warns_when_the_server_refuses() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::CloseWith(0x01)).await;
    let mut cfg = ClientConfig::default();
    cfg.security = Security::SkipVerification;
    cfg.reconnect.connect_timeout = Duration::from_secs(3);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        SolanaGunQuicClient::connect(&stub.endpoint(), "tok", cfg),
    )
    .await
    .expect("connect timed out");
    assert!(result.is_err(), "the stub refuses the token");
    assert!(logs_contain(WARNING));
}

async fn wait_for(what: &str, cond: impl FnMut() -> bool) {
    wait_within(Duration::from_secs(3), what, cond).await;
}

async fn wait_within(limit: Duration, what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

const ANON_HELLO: &str = "SOLANA-GUN-QUIC/1-ANON\n";

#[tokio::test]
async fn anonymous_connect_sends_the_hello_and_delivers() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        SolanaGunQuicClient::connect_anonymous(&stub.endpoint(), client_config(&ca)),
    )
    .await
    .expect("connect timed out")
    .expect("connect");
    tokio::time::timeout(
        Duration::from_secs(5),
        client.send_transaction_bytes(&[7u8; 64]),
    )
    .await
    .expect("send timed out")
    .expect("send");
    wait_for("hello and stream", || {
        stub.hellos().len() == 1 && stub.uni_streams() == 1
    })
    .await;
    assert_eq!(stub.hellos(), vec![ANON_HELLO.to_string()]);
    client.close().await;
}

#[tokio::test]
async fn anonymous_connect_does_not_wait_for_the_reply() {
    let ca = Ca::new();
    let opts = StubOptions {
        ok_delay: Duration::from_millis(300),
        ..Default::default()
    };
    let stub = QuicStub::spawn_with(&ca, Duration::ZERO, Handshake::Ok, opts).await;
    let cfg = client_config(&ca);
    let started = Instant::now();
    let client = SolanaGunQuicClient::connect_anonymous(&stub.endpoint(), cfg)
        .await
        .expect("connect");
    client
        .send_transaction_bytes(&[7u8; 64])
        .await
        .expect("send");
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "{:?}",
        started.elapsed()
    );
    wait_for("hello", || stub.hellos().len() == 1).await;
    client.close().await;
}

#[tokio::test]
async fn old_server_reports_tokenless_unsupported() {
    let ca = Ca::new();
    let opts = StubOptions {
        reject_anonymous: true,
        ..Default::default()
    };
    let stub = QuicStub::spawn_with(&ca, Duration::ZERO, Handshake::Ok, opts).await;
    let client = SolanaGunQuicClient::connect_anonymous(&stub.endpoint(), client_config(&ca))
        .await
        .expect("connect returns before the refusal");
    wait_for("hello", || stub.hellos().len() == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        client.send_transaction_bytes(&[1u8; 64]),
    )
    .await
    .expect("send timed out")
    .expect_err("send must fail");
    assert!(
        matches!(
            &err,
            SendError::Reconnect(ConnectError::Handshake(
                HandshakeError::TokenlessUnsupported
            ))
        ),
        "{err}"
    );
    assert_eq!(stub.handshakes(), 1, "no second dial");
}

#[tokio::test]
async fn token_connect_is_unchanged() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let client = SolanaGunQuicClient::connect(&stub.endpoint(), "tok", client_config(&ca))
        .await
        .expect("connect");
    client
        .send_transaction_bytes(&[1u8; 64])
        .await
        .expect("send");
    assert_eq!(stub.hellos(), vec!["SOLANA-GUN-QUIC/1 tok\n".to_string()]);
    client.close().await;
}

// ---- confirmed send ----

fn verdict_opts(verdicts: &'static [&'static [u8]], stop_upload: bool) -> StubOptions {
    StubOptions {
        verdicts,
        stop_upload,
        ..Default::default()
    }
}

async fn confirmed(client: &SolanaGunQuicClient) -> Result<(), SendError> {
    tokio::time::timeout(
        Duration::from_secs(5),
        client.send_transaction_bytes_confirmed(&[9u8; 64]),
    )
    .await
    .expect("confirmed send timed out")
}

#[tokio::test]
async fn confirmed_send_outcomes() {
    let ca = Ca::new();
    let opts = verdict_opts(
        &[
            &[0x00],
            &[0x01, 250, 0, 0, 0],
            &[0x02],
            &[0x07],
            &[0x01, 1],
            &[0x00, 0x00],
        ],
        false,
    );
    let stub = QuicStub::spawn_with(&ca, Duration::ZERO, Handshake::Ok, opts).await;
    let client = SolanaGunQuicClient::connect_anonymous(&stub.endpoint(), client_config(&ca))
        .await
        .expect("connect");
    confirmed(&client).await.expect("0x00 is Ok");
    let err = confirmed(&client).await.expect_err("rate limited");
    assert!(
        matches!(err, SendError::RateLimited { retry_after } if retry_after == Duration::from_millis(250)),
        "{err}"
    );
    assert_eq!(
        err.to_string(),
        "rate limited by the server; retry after 250ms"
    );
    let err = confirmed(&client).await.expect_err("rejected");
    assert!(matches!(err, SendError::Rejected), "{err}");
    assert_eq!(err.to_string(), "transaction rejected by the server");
    for _ in 0..3 {
        let err = confirmed(&client).await.expect_err("malformed verdict");
        assert!(matches!(err, SendError::Rejected), "{err}");
    }
    assert_eq!(stub.handshakes(), 1, "no reconnect");
    client.close().await;
}

#[tokio::test]
async fn verdict_wins_over_an_upload_stop() {
    let ca = Ca::new();
    let stub = QuicStub::spawn_with(
        &ca,
        Duration::ZERO,
        Handshake::Ok,
        verdict_opts(&[&[0x01, 250, 0, 0, 0]], true),
    )
    .await;
    let client = SolanaGunQuicClient::connect_anonymous(&stub.endpoint(), client_config(&ca))
        .await
        .expect("connect");
    let err = confirmed(&client).await.expect_err("rate limited");
    assert!(matches!(err, SendError::RateLimited { .. }), "{err}");
    client.close().await;
}

#[tokio::test]
async fn rate_limit_is_never_resubmitted() {
    let ca = Ca::new();
    let stub = QuicStub::spawn_with(
        &ca,
        Duration::ZERO,
        Handshake::Ok,
        verdict_opts(&[&[0x01, 10, 0, 0, 0]], false),
    )
    .await;
    let client = SolanaGunQuicClient::connect_anonymous(&stub.endpoint(), client_config(&ca))
        .await
        .expect("connect");
    let err = confirmed(&client).await.expect_err("rate limited");
    assert!(matches!(err, SendError::RateLimited { .. }), "{err}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stub.bidi_streams(), 1);
    assert_eq!(stub.handshakes(), 1);
    client.close().await;
}

#[tokio::test]
async fn old_server_times_out_without_resubmission() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let mut cfg = client_config(&ca);
    cfg.send_timeout = Duration::from_millis(300);
    let client = SolanaGunQuicClient::connect_anonymous(&stub.endpoint(), cfg)
        .await
        .expect("connect");
    let err = confirmed(&client).await.expect_err("timeout");
    assert!(matches!(err, SendError::Timeout), "{err}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stub.bidi_streams(), 1, "one stream, never resubmitted");
    assert_eq!(stub.handshakes(), 1, "no reconnect");
    client.close().await;
}

#[tokio::test]
async fn confirmed_send_reconnects_once_when_the_connection_was_already_lost() {
    let ca = Ca::new();
    let stub = QuicStub::spawn_with(
        &ca,
        Duration::ZERO,
        Handshake::Ok,
        verdict_opts(&[&[0x00]], false),
    )
    .await;
    let client = SolanaGunQuicClient::connect_anonymous(&stub.endpoint(), client_config(&ca))
        .await
        .expect("connect");
    wait_for("hello", || stub.hellos().len() == 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    stub.close_all();
    tokio::time::sleep(Duration::from_millis(150)).await;
    confirmed(&client).await.expect("reconnect and deliver");
    assert_eq!(stub.handshakes(), 2);
    assert_eq!(stub.bidi_streams(), 1);
    client.close().await;
}

#[tokio::test]
async fn normal_send_is_unchanged() {
    let ca = Ca::new();
    let stub = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let client = SolanaGunQuicClient::connect_anonymous(&stub.endpoint(), client_config(&ca))
        .await
        .expect("connect");
    client
        .send_transaction_bytes(&[1u8; 64])
        .await
        .expect("uni send");
    wait_for("uni stream", || stub.uni_streams() == 1).await;
    assert_eq!(stub.bidi_streams(), 0);
    client.close().await;
}

// ---- unencrypted mode ----

const fn is_version_mismatch(e: &ConnectError) -> bool {
    matches!(
        e,
        ConnectError::Connection(quinn::ConnectionError::VersionMismatch)
    )
}

async fn plain_client(endpoint: &str) -> SolanaGunQuicClient {
    tokio::time::timeout(
        Duration::from_secs(2),
        SolanaGunQuicClient::connect_anonymous(endpoint, plain_config()),
    )
    .await
    .expect("connect timed out")
    .expect("connect")
}

async fn send(client: &SolanaGunQuicClient, tx: &[u8]) -> Result<(), SendError> {
    tokio::time::timeout(Duration::from_secs(5), client.send_transaction_bytes(tx))
        .await
        .expect("send timed out")
}

#[tokio::test]
async fn unencrypted_first_send_needs_no_server_packet() {
    let stub = PlainStub::spawn(&[]).await;
    let relay = Relay::start(
        stub.addr(),
        RelayOptions {
            hold_server_to_client: true,
            ..Default::default()
        },
    )
    .await;
    let client = plain_client(&relay.endpoint()).await;
    let tx = vec![0xAB; 1232];
    let sender = {
        let (client, tx) = (client.clone(), tx.clone());
        tokio::spawn(async move { client.send_transaction_bytes(&tx).await })
    };
    wait_within(Duration::from_secs(1), "tx at the server", || {
        stub.txs().len() == 1
    })
    .await;
    assert_eq!(stub.txs()[0], tx);
    wait_within(
        Duration::from_secs(1),
        "the server's answer at the relay",
        || relay.s2c_seen() > 0,
    )
    .await;
    assert_eq!(relay.s2c_forwarded(), 0, "nothing reached the client");
    relay.release().await;
    tokio::time::timeout(Duration::from_secs(5), sender)
        .await
        .expect("send timed out")
        .unwrap()
        .expect("send completes once the server is heard");
    client.close().await;
}

#[tokio::test]
async fn unencrypted_opens_parked_at_the_early_limit_complete_after_establishment() {
    let stub = PlainStub::spawn(&[]).await;
    let relay = Relay::start(
        stub.addr(),
        RelayOptions {
            hold_server_to_client: true,
            ..Default::default()
        },
    )
    .await;
    let client = plain_client(&relay.endpoint()).await;
    let n = plaintext::EARLY_MAX_UNI_STREAMS as usize + 3;
    let mut senders = Vec::new();
    for i in 0..n {
        let client = client.clone();
        senders.push(tokio::spawn(async move {
            client.send_transaction_bytes(&[i as u8; 64]).await
        }));
    }
    let early = plaintext::EARLY_MAX_UNI_STREAMS as usize;
    wait_within(Duration::from_secs(1), "early txs", || {
        stub.txs().len() == early
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        stub.txs().len(),
        early,
        "only the early stream credit is usable"
    );
    relay.release().await;
    for s in senders {
        tokio::time::timeout(Duration::from_secs(3), s)
            .await
            .expect("a parked open never completed")
            .unwrap()
            .expect("send");
    }
    assert_eq!(stub.txs().len(), n);
    assert_eq!(stub.connections(), 1, "no reconnect");
    client.close().await;
}

#[tokio::test]
async fn unencrypted_confirmed_send_and_reconnect_work() {
    let stub = PlainStub::spawn(&[&[0x00]]).await;
    let client = plain_client(&stub.endpoint()).await;
    confirmed(&client).await.expect("accepted");
    send(&client, &[1u8; 64]).await.expect("uni send");
    stub.close_all();
    tokio::time::sleep(Duration::from_millis(150)).await;
    confirmed(&client).await.expect("reconnect and deliver");
    send(&client, &[2u8; 64])
        .await
        .expect("uni send after reconnect");
    wait_for("both txs", || stub.txs().len() == 2).await;
    assert_eq!(stub.connections(), 2);
    assert_eq!(stub.bidi_streams(), 2);

    // Tokenless disabled on the server (close 0x01) still maps to Unauthorized.
    stub.close_all_with(0x01);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let err = send(&client, &[3u8; 64]).await.expect_err("refused");
    assert!(
        matches!(
            &err,
            SendError::Reconnect(ConnectError::Handshake(HandshakeError::Unauthorized))
        ),
        "{err}"
    );
    assert_eq!(stub.connections(), 2, "no further dial");
    client.close().await;
}

#[tokio::test]
async fn unencrypted_client_against_tls_port_fails_with_version_mismatch_and_tls_client_against_plaintext_port_too()
 {
    let ca = Ca::new();
    let tls = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let client = plain_client(&tls.endpoint()).await;
    let err = send(&client, &[1u8; 64]).await.expect_err("must fail");
    assert!(
        matches!(&err, SendError::Reconnect(e) if is_version_mismatch(e)),
        "{err}"
    );
    let client = plain_client(&tls.endpoint()).await;
    let err = confirmed(&client).await.expect_err("must fail");
    assert!(
        matches!(&err, SendError::Reconnect(e) if is_version_mismatch(e)),
        "{err}"
    );
    assert_eq!(tls.handshakes(), 0);

    let plain = PlainStub::spawn(&[]).await;
    let connect = |token: Option<&'static str>| {
        let (endpoint, config) = (plain.endpoint(), client_config(&ca));
        async move {
            let r = match token {
                Some(t) => SolanaGunQuicClient::connect(&endpoint, t, config).await,
                None => SolanaGunQuicClient::connect_anonymous(&endpoint, config).await,
            };
            r.map(|_| ()).expect_err("must fail")
        }
    };
    for token in [None, Some("tok")] {
        let err = tokio::time::timeout(Duration::from_secs(3), connect(token))
            .await
            .expect("connect timed out");
        assert!(is_version_mismatch(&err), "{err}");
    }
    assert_eq!(plain.connections(), 0);
}

#[tokio::test]
async fn probe_in_unencrypted_mode_measures_a_round_trip() {
    let ca = Ca::new();
    let stub = PlainStub::spawn(&[]).await;
    let relay = Relay::start(
        stub.addr(),
        RelayOptions {
            delay: Duration::from_millis(50),
            ..Default::default()
        },
    )
    .await;
    let discovery = HttpsStub::serve(&ca, 200, &format!(r#"["{}"]"#, relay.endpoint())).await;
    let mut config = plain_config();
    config.root_store = Some(ca.roots());
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        SolanaGunQuicClient::connect_auto_anonymous(config, auto_config(discovery.url())),
    )
    .await
    .expect("connect_auto timed out")
    .expect("connect_auto");
    match client.endpoint_source() {
        EndpointSource::Discovered { latency, .. } => {
            assert!(*latency >= Duration::from_millis(100), "{latency:?}")
        }
        other => panic!("{other:?}"),
    }
    send(&client, &[1u8; 64]).await.expect("send");
    client.close().await;
}

fn probe_errors(err: ConnectError) -> Vec<(String, String)> {
    match err {
        ConnectError::AutoConfig(e) => match e.reason {
            FallbackReason::AllProbesFailed(list) => list,
            other => panic!("{other}"),
        },
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn wrong_kind_discovery_list_fails_every_probe_with_a_mode_naming_error() {
    let ca = Ca::new();
    let (tls_a, tls_b) = (
        QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await,
        QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await,
    );
    let (plain_a, plain_b) = (PlainStub::spawn(&[]).await, PlainStub::spawn(&[]).await);
    let cases = [
        (
            Security::Unencrypted,
            [tls_a.endpoint(), tls_b.endpoint()],
            "not an unencrypted QUIC port",
        ),
        (
            Security::VerifiedTls,
            [plain_a.endpoint(), plain_b.endpoint()],
            "not a TLS QUIC port",
        ),
    ];
    for (security, list, expected) in cases {
        let discovery =
            HttpsStub::serve(&ca, 200, &format!(r#"["{}","{}"]"#, list[0], list[1])).await;
        let mut config = client_config(&ca);
        config.security = security;
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            SolanaGunQuicClient::connect_auto_anonymous(config, auto_config(discovery.url())),
        )
        .await
        .expect("connect_auto timed out")
        .map(|_| ())
        .expect_err("must fail");
        let errors = probe_errors(err);
        assert_eq!(errors.len(), 2, "{errors:?}");
        for (_, e) in &errors {
            assert!(
                e.contains("version mismatch") && e.contains(expected),
                "{security:?}: {e}"
            );
        }
    }
    assert_eq!(tls_a.handshakes() + tls_b.handshakes(), 0);
    assert_eq!(plain_a.connections() + plain_b.connections(), 0);
}

#[tokio::test]
async fn the_mode_is_never_changed_by_autoconfig_or_reconnect() {
    // Verified TLS: discovery and fallback name a plaintext port → fails, v1 only.
    let ca = Ca::new();
    let plain = PlainStub::spawn(&[]).await;
    let relay = Relay::start(plain.addr(), RelayOptions::default()).await;
    let discovery = HttpsStub::serve(&ca, 200, &format!(r#"["{}"]"#, relay.endpoint())).await;
    let mut auto = auto_config(discovery.url());
    auto.fallback_endpoint = Some(relay.endpoint());
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        SolanaGunQuicClient::connect_auto_anonymous(client_config(&ca), auto),
    )
    .await
    .expect("connect_auto timed out")
    .map(|_| ())
    .expect_err("must fail");
    assert!(
        matches!(&err, ConnectError::AutoConfig(e) if e.fallback_error.is_some()),
        "{err}"
    );
    let versions = relay.c2s_versions();
    assert!(!versions.is_empty());
    assert!(versions.iter().all(|v| *v == Some(1)), "{versions:x?}");
    assert_eq!(plain.connections(), 0);

    // Unencrypted: after a server restart the client reconnects with VERSION only.
    let first = PlainStub::spawn(&[]).await;
    let relay = Relay::start(first.addr(), RelayOptions::default()).await;
    let client = plain_client(&relay.endpoint()).await;
    send(&client, &[1u8; 64]).await.expect("first send");
    wait_for("first tx", || first.txs().len() == 1).await;
    first.shutdown().await;
    let second = PlainStub::spawn(&[]).await;
    relay.retarget(second.addr());
    tokio::time::sleep(Duration::from_millis(100)).await;
    send(&client, &[2u8; 64]).await.expect("send after restart");
    wait_for("tx at the restarted server", || second.txs().len() == 1).await;
    assert_eq!(second.connections(), 1);
    let versions = relay.c2s_versions();
    let long: Vec<_> = versions.iter().flatten().collect();
    assert!(long.len() >= 2, "two dials: {versions:x?}");
    assert!(
        long.iter().all(|v| **v == plaintext::VERSION),
        "{versions:x?}"
    );
    client.close().await;
}

#[tokio::test]
async fn unencrypted_close_after_the_server_read_a_confirmed_tx_is_not_resubmitted() {
    // The server reads the tx and closes before the client hears anything: quinn fails
    // the early stream as "0-RTT rejected", but the tx did reach the server.
    let stub = PlainStub::spawn_closing_after_confirmed_read().await;
    let relay = Relay::start(stub.addr(), RelayOptions::default()).await;
    relay.drop_server_to_client(true);
    let mut config = plain_config();
    config.idle_timeout = Duration::from_secs(2);
    config.keep_alive_interval = Duration::from_millis(500);
    config.send_timeout = Duration::from_secs(6);
    let client = SolanaGunQuicClient::connect_anonymous(&relay.endpoint(), config)
        .await
        .expect("connect");
    let pending = {
        let client = client.clone();
        tokio::spawn(async move { client.send_transaction_bytes_confirmed(&[5u8; 64]).await })
    };
    wait_for("confirmed tx read", || stub.bidi_streams() == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // From now on the client may hear the server's close.
    relay.drop_server_to_client(false);
    let err = tokio::time::timeout(Duration::from_secs(8), pending)
        .await
        .expect("confirmed send timed out")
        .unwrap()
        .expect_err("must fail");
    assert!(matches!(err, SendError::ConnectionLost(_)), "{err:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(stub.bidi_streams(), 1, "never resubmitted");
    assert_eq!(stub.connections(), 1, "no second connection");
    drop(client);
}

#[tokio::test]
async fn unencrypted_close_0x02_is_transient_and_reconnects() {
    let stub = PlainStub::spawn(&[&[0x00]]).await;
    let client = plain_client(&stub.endpoint()).await;
    confirmed(&client).await.expect("first");
    stub.close_all_with(0x02);
    tokio::time::sleep(Duration::from_millis(150)).await;
    confirmed(&client).await.expect("reconnects after 0x02");
    assert_eq!(stub.connections(), 2);
    client.close().await;
}

#[tokio::test]
async fn unencrypted_version_mismatch_without_reconnect_reports_the_cause() {
    let ca = Ca::new();
    let tls = QuicStub::spawn(&ca, Duration::ZERO, Handshake::Ok).await;
    let mut config = plain_config();
    config.reconnect.enabled = false;
    let client = SolanaGunQuicClient::connect_anonymous(&tls.endpoint(), config)
        .await
        .expect("connect");
    let mismatch = |e: &SendError| {
        matches!(
            e,
            SendError::ConnectionLost(quinn::ConnectionError::VersionMismatch)
        )
    };
    let err = send(&client, &[1u8; 64]).await.expect_err("must fail");
    assert!(mismatch(&err), "{err:?}");
    let err = confirmed(&client).await.expect_err("must fail");
    assert!(mismatch(&err), "{err:?}");
}
