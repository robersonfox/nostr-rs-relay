//! Visit counting and statistics events
use crate::config::Settings;
use crate::error::Result;
use crate::event::Event;
use crate::repo::NostrRepo;
use crate::utils::unix_time;
use chrono::{TimeZone, Utc};
use hyper::{Body, Response};
use lazy_static::lazy_static;
use nostr::event::tag::TagKind;
use nostr::key::{FromSkStr, Keys};
use nostr::secp256k1::{Message, Secp256k1};
use nostr::{EventId, Kind, Tag, Timestamp};
use regex::Regex;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;
use tokio::sync::Mutex;
use tracing::warn;

pub const VISIT_KIND: u64 = 20918;
pub const STATS_KIND: u64 = 30918;

const HOUR_SECONDS: u64 = 3600;
const DAY_SECONDS: u64 = 86400;

const PIXEL_PNG: [u8; 68] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x60, 0x00, 0x02, 0x00,
    0x00, 0x05, 0x00, 0x01, 0x7a, 0x5e, 0xab, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44,
    0xae, 0x42, 0x60, 0x82,
];

lazy_static! {
    static ref TARGET_RE: Regex = Regex::new(r"^\d+:[0-9a-f]{64}:.+$").unwrap();
    static ref LAST_STATS_AT: Mutex<u64> = Mutex::new(0);
}

/// Author pubkey of a well-formed visit target
fn target_author(target: &str) -> Option<&str> {
    if TARGET_RE.is_match(target) {
        target.split(':').nth(1)
    } else {
        None
    }
}

/// The visited target of a visit event, if it has exactly one valid `a` tag
pub fn visit_target(event: &Event) -> Option<String> {
    let mut targets = event.tag_values_by_name("a");
    if targets.len() == 1 && target_author(&targets[0]).is_some() {
        targets.pop()
    } else {
        None
    }
}

fn custom_tag(name: &str, values: &[&str]) -> Tag {
    Tag::Generic(
        TagKind::Custom(name.to_owned()),
        values.iter().map(|v| (*v).to_owned()).collect(),
    )
}

fn sign_event(
    keys: &Keys,
    created_at: u64,
    kind: Kind,
    tags: Vec<Tag>,
) -> std::result::Result<nostr::Event, nostr::event::builder::Error> {
    let secp = Secp256k1::new();
    let keypair = &keys.key_pair()?;
    let pubkey = keys.public_key();
    let created_at = Timestamp::from(created_at);
    let content = String::new();
    let id = EventId::new(&pubkey, created_at, &kind, &tags, &content);
    let message = Message::from_slice(id.as_bytes())?;
    Ok(nostr::Event {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig: secp.sign_schnorr(&message, keypair),
        ots: None,
    })
}

/// Count a visit and, if it counted, publish the daily and total statistics
pub async fn count_visit(
    repo: &Arc<dyn NostrRepo>,
    keys: &Keys,
    bcast_tx: &Sender<Event>,
    target: &str,
    visitor: Option<&str>,
    ip: &str,
) -> Result<bool> {
    let author = match target_author(target) {
        Some(author) => author,
        None => return Ok(false),
    };
    if visitor == Some(author) {
        return Ok(false);
    }
    let now = unix_time();
    let hour = now - now % HOUR_SECONDS;
    if !repo.record_visit(target, visitor, ip, hour).await? {
        return Ok(false);
    }
    let day_start = hour - hour % DAY_SECONDS;
    let mut last_stats_at = LAST_STATS_AT.lock().await;
    let (hourly, total) = repo.visit_stats(target, day_start).await?;
    let day = Utc
        .timestamp_opt(day_start as i64, 0)
        .unwrap()
        .format("%Y-%m-%d")
        .to_string();
    let day_total: u64 = hourly.iter().map(|(_, count)| count).sum();

    let mut daily_tags = vec![
        custom_tag("d", &[&format!("{target}:{day}")]),
        custom_tag("a", &[target]),
        custom_tag("p", &[author]),
        custom_tag("day", &[&day]),
        custom_tag("total", &[&day_total.to_string()]),
    ];
    for (hour, count) in &hourly {
        let hour_of_day = Utc
            .timestamp_opt(*hour as i64, 0)
            .unwrap()
            .format("%H")
            .to_string();
        daily_tags.push(custom_tag("hour", &[&hour_of_day, &count.to_string()]));
    }
    let total_tags = vec![
        custom_tag("d", &[target]),
        custom_tag("a", &[target]),
        custom_tag("p", &[author]),
        custom_tag("total", &[&total.to_string()]),
    ];

    for tags in [daily_tags, total_tags] {
        let created_at = unix_time().max(*last_stats_at + 1);
        *last_stats_at = created_at;
        let stats_event: Event =
            sign_event(keys, created_at, Kind::Custom(STATS_KIND), tags)?.into();
        repo.write_event(&stats_event).await?;
        bcast_tx.send(stats_event).ok();
    }
    Ok(true)
}

/// Handle `GET /visit?a=<target>`, always answering with a transparent pixel
pub async fn handle_request(
    query: Option<&str>,
    ip: &str,
    repo: &Arc<dyn NostrRepo>,
    settings: &Settings,
    bcast_tx: &Sender<Event>,
) -> Response<Body> {
    let target = query.and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(name, _)| name == "a")
            .map(|(_, value)| value.into_owned())
    });
    if let Some(target) = target {
        let keys = settings
            .visits
            .secret_key
            .as_deref()
            .and_then(|k| Keys::from_sk_str(k).ok());
        if let Some(keys) = keys {
            if let Err(e) = count_visit(repo, &keys, bcast_tx, &target, None, ip).await {
                warn!("visit counting failed: {:?}", e);
            }
        }
    }
    Response::builder()
        .status(200)
        .header("Content-Type", "image/png")
        .header("Cache-Control", "no-store")
        .body(Body::from(PIXEL_PNG.to_vec()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::sqlite::SqliteRepo;
    use crate::server::create_metrics;
    use crate::subscription::Subscription;
    use tokio::sync::broadcast;

    const AUTHOR_SK: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const RELAY_SK: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const VISITOR_SK: &str = "0000000000000000000000000000000000000000000000000000000000000004";
    const OTHER_VISITOR_SK: &str =
        "0000000000000000000000000000000000000000000000000000000000000005";
    const DAY_START: u64 = 1_700_000_000 - 1_700_000_000 % DAY_SECONDS;

    fn pubkey(sk: &str) -> String {
        Keys::from_sk_str(sk).unwrap().public_key().to_string()
    }

    fn target() -> String {
        format!("30023:{}:my-article", pubkey(AUTHOR_SK))
    }

    async fn test_repo() -> (Arc<dyn NostrRepo>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("nostr-rs-relay-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut settings = Settings::default();
        settings.database.data_directory = dir.to_str().unwrap().to_owned();
        let repo = SqliteRepo::new(&settings, create_metrics().1);
        repo.migrate_up().await.unwrap();
        (Arc::new(repo), dir)
    }

    fn visits_settings() -> Settings {
        let mut settings = Settings::default();
        settings.visits.enabled = true;
        settings.visits.secret_key = Some(RELAY_SK.to_owned());
        settings
    }

    #[tokio::test]
    async fn same_pubkey_in_same_hour_counts_once() {
        let (repo, dir) = test_repo().await;
        let t = target();
        let pk = pubkey(VISITOR_SK);
        assert!(repo
            .record_visit(&t, Some(&pk), "10.0.0.1", DAY_START)
            .await
            .unwrap());
        assert!(!repo
            .record_visit(&t, Some(&pk), "10.0.0.2", DAY_START)
            .await
            .unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn same_ip_with_other_pubkey_does_not_count() {
        let (repo, dir) = test_repo().await;
        let t = target();
        let pk = pubkey(VISITOR_SK);
        let other_pk = pubkey(OTHER_VISITOR_SK);
        assert!(repo
            .record_visit(&t, Some(&pk), "10.0.0.1", DAY_START)
            .await
            .unwrap());
        assert!(!repo
            .record_visit(&t, Some(&other_pk), "10.0.0.1", DAY_START)
            .await
            .unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn counts_again_in_next_hour_and_sums_per_hour() {
        let (repo, dir) = test_repo().await;
        let t = target();
        let pk = pubkey(VISITOR_SK);
        let other_pk = pubkey(OTHER_VISITOR_SK);
        let next_hour = DAY_START + HOUR_SECONDS;
        assert!(repo
            .record_visit(&t, Some(&pk), "10.0.0.1", DAY_START)
            .await
            .unwrap());
        assert!(repo
            .record_visit(&t, Some(&other_pk), "10.0.0.2", DAY_START)
            .await
            .unwrap());
        assert!(repo
            .record_visit(&t, Some(&pk), "10.0.0.1", next_hour)
            .await
            .unwrap());
        let (hourly, total) = repo.visit_stats(&t, DAY_START).await.unwrap();
        assert_eq!(hourly, vec![(DAY_START, 2), (next_hour, 1)]);
        assert_eq!(total, 3);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn author_visit_is_not_counted() {
        let (repo, dir) = test_repo().await;
        let (bcast_tx, mut bcast_rx) = broadcast::channel(8);
        let keys = Keys::from_sk_str(RELAY_SK).unwrap();
        let t = target();
        let author = pubkey(AUTHOR_SK);
        assert!(
            !count_visit(&repo, &keys, &bcast_tx, &t, Some(&author), "10.0.0.1")
                .await
                .unwrap()
        );
        assert_eq!(repo.visit_stats(&t, DAY_START).await.unwrap().1, 0);
        assert!(bcast_rx.try_recv().is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn counted_visit_publishes_daily_and_total_events() {
        let (repo, dir) = test_repo().await;
        let (bcast_tx, mut bcast_rx) = broadcast::channel(8);
        let keys = Keys::from_sk_str(RELAY_SK).unwrap();
        let t = target();
        let pk = pubkey(VISITOR_SK);
        assert!(
            count_visit(&repo, &keys, &bcast_tx, &t, Some(&pk), "10.0.0.1")
                .await
                .unwrap()
        );

        let daily = bcast_rx.try_recv().unwrap();
        let total = bcast_rx.try_recv().unwrap();
        for event in [&daily, &total] {
            assert_eq!(event.kind, STATS_KIND);
            assert_eq!(event.pubkey, pubkey(RELAY_SK));
            assert_eq!(event.tag_values_by_name("p"), vec![pubkey(AUTHOR_SK)]);
            assert_eq!(event.tag_values_by_name("a"), vec![t.clone()]);
            assert_eq!(event.tag_values_by_name("total"), vec!["1".to_owned()]);
        }
        assert_eq!(total.tag_values_by_name("d"), vec![t.clone()]);
        assert!(daily.tag_values_by_name("d")[0].starts_with(&format!("{t}:")));
        assert_eq!(daily.tag_values_by_name("hour").len(), 1);

        assert!(
            !count_visit(&repo, &keys, &bcast_tx, &t, Some(&pk), "10.0.0.1")
                .await
                .unwrap()
        );
        assert!(bcast_rx.try_recv().is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn two_visits_in_same_second_are_both_reflected_in_stored_daily_event() {
        let (repo, dir) = test_repo().await;
        let (bcast_tx, _bcast_rx) = broadcast::channel(8);
        let keys = Keys::from_sk_str(RELAY_SK).unwrap();
        let t = target();
        let pk = pubkey(VISITOR_SK);
        let other_pk = pubkey(OTHER_VISITOR_SK);
        assert!(
            count_visit(&repo, &keys, &bcast_tx, &t, Some(&pk), "10.0.0.1")
                .await
                .unwrap()
        );
        assert!(
            count_visit(&repo, &keys, &bcast_tx, &t, Some(&other_pk), "10.0.0.2")
                .await
                .unwrap()
        );

        let sub: Subscription = serde_json::from_str(&format!(
            "[\"REQ\",\"stats\",{{\"kinds\":[{STATS_KIND}],\"#a\":[\"{t}\"]}}]"
        ))
        .unwrap();
        let (query_tx, mut query_rx) = tokio::sync::mpsc::channel(8);
        let (_abandon_tx, abandon_rx) = tokio::sync::oneshot::channel();
        repo.query_subscription(sub, "client".to_owned(), query_tx, abandon_rx)
            .await
            .unwrap();
        let mut totals = vec![];
        while let Some(result) = query_rx.recv().await {
            if result.event == "EOSE" {
                continue;
            }
            let stored: Event = serde_json::from_str(&result.event).unwrap();
            totals.push(stored.tag_values_by_name("total"));
        }
        totals.sort();
        assert_eq!(totals, vec![vec!["2".to_owned()], vec!["2".to_owned()]]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn visit_route_counts_valid_target_and_always_returns_png() {
        let (repo, dir) = test_repo().await;
        let (bcast_tx, _bcast_rx) = broadcast::channel(8);
        let settings = visits_settings();
        let t = target();
        let total = || async { repo.visit_stats(&t, DAY_START).await.unwrap().1 };

        let encoded = format!("a={}", t.replace(':', "%3A"));
        let response =
            handle_request(Some(&encoded), "10.0.0.1", &repo, &settings, &bcast_tx).await;
        assert_eq!(response.headers()["content-type"], "image/png");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(
            &body[..8],
            &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]
        );
        assert_eq!(total().await, 1);

        handle_request(Some(&encoded), "10.0.0.1", &repo, &settings, &bcast_tx).await;
        assert_eq!(total().await, 1);

        for query in [
            Some("a=not-a-target"),
            Some("a=30023%3Aabc%3Aslug"),
            Some("b=1"),
            None,
        ] {
            let response = handle_request(query, "10.0.0.9", &repo, &settings, &bcast_tx).await;
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["content-type"], "image/png");
        }
        assert_eq!(total().await, 1);
        std::fs::remove_dir_all(dir).ok();
    }
}
