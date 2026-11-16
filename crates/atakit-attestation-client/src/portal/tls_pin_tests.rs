use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::pinned_client;

struct Identity {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}

fn identity(key: &KeyPair, serial: u64, expired: bool) -> Identity {
    let mut params = CertificateParams::new(vec!["atakit-portal".into()]).unwrap();
    params.serial_number = Some(serial.into());
    if expired {
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    }
    Identity {
        cert: params.self_signed(key).unwrap().der().clone(),
        key: key.serialize_der(),
    }
}

async fn endpoint(
    identities: Vec<Identity>,
    protocol: &'static rustls::SupportedProtocolVersion,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut requests = 0;
        for identity in identities {
            let server = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[protocol])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert],
                PrivatePkcs8KeyDer::from(identity.key).into(),
            )
            .unwrap();
            let (socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let accepted = tokio::time::timeout(
                Duration::from_secs(5),
                TlsAcceptor::from(Arc::new(server)).accept(socket),
            )
            .await
            .unwrap();
            if let Ok(mut tls) = accepted {
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(tls.read_u8().await.unwrap());
                    assert!(headers.len() < 8192);
                }
                requests += 1;
                tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .await
                .unwrap();
                let _ = tls.shutdown().await;
            }
        }
        requests
    });
    (address, task)
}

#[tokio::test]
async fn genuine_certificate_works_after_reconnect_for_tls12_and_tls13() {
    for protocol in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let key = KeyPair::generate().unwrap();
        let first = identity(&key, 1, false);
        let der = first.cert.clone();
        let second = Identity {
            cert: der.clone(),
            key: key.serialize_der(),
        };
        let (address, task) = endpoint(vec![first, second], protocol).await;
        let client =
            pinned_client(&der, Duration::from_secs(5), "127.0.0.1", Some(address)).unwrap();
        for _ in 0..2 {
            assert_eq!(
                client
                    .get(format!("https://{address}/"))
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap(),
                "ok"
            );
        }
        assert_eq!(task.await.unwrap(), 2);
    }
}

#[tokio::test]
async fn substituted_certificate_on_reconnect_cannot_receive_secret_body() {
    for protocol in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for reuse_key in [false, true] {
            let key = KeyPair::generate().unwrap();
            let replacement_key = KeyPair::generate().unwrap();
            let first = identity(&key, 1, false);
            let der = first.cert.clone();
            // Even a new certificate using the same private key is not the
            // exact DER that attestation authenticated.
            let second = identity(if reuse_key { &key } else { &replacement_key }, 2, false);
            let (address, task) = endpoint(vec![first, second], protocol).await;
            let client =
                pinned_client(&der, Duration::from_secs(5), "127.0.0.1", Some(address)).unwrap();
            assert_eq!(
                client
                    .get(format!("https://{address}/"))
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap(),
                "ok"
            );
            let error = client
                .post(format!("https://{address}/disks/data/unlock"))
                .body("test-secret-never-sent")
                .send()
                .await
                .unwrap_err();
            assert!(error.is_connect(), "{error:?}");
            assert_eq!(
                task.await.unwrap(),
                1,
                "replacement endpoint received HTTP data"
            );
        }
    }
}

#[tokio::test]
async fn expired_pinned_certificate_is_rejected() {
    let key = KeyPair::generate().unwrap();
    let cert = identity(&key, 1, true);
    let der = cert.cert.clone();
    let (address, task) = endpoint(vec![cert], &rustls::version::TLS13).await;
    let client = pinned_client(&der, Duration::from_secs(5), "127.0.0.1", Some(address)).unwrap();
    assert!(client
        .get(format!("https://{address}/"))
        .send()
        .await
        .unwrap_err()
        .is_connect());
    assert_eq!(task.await.unwrap(), 0);
}

#[tokio::test]
#[ignore = "requires Internet access to a publicly trusted HTTPS endpoint"]
async fn publicly_trusted_certificate_cannot_replace_attested_certificate() {
    let url = "https://example.com/";
    let ordinary = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    assert!(ordinary
        .get(url)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let cert = identity(&KeyPair::generate().unwrap(), 1, false);
    let client = pinned_client(&cert.cert, Duration::from_secs(30), "example.com", None).unwrap();
    assert!(client.get(url).send().await.unwrap_err().is_connect());
}
