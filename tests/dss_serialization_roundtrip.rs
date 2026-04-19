#![cfg(feature = "dss")]

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use protobuf::Message;
use rusty_secrets::dss::{ss1, thss};
use rusty_secrets::errors::Error;
use rusty_secrets::proto::dss::share::ShareProto;

fn sample_tags() -> BTreeMap<String, String> {
    let mut tags = BTreeMap::new();
    tags.insert("mime_type".to_string(), "text/plain".to_string());
    tags.insert("label".to_string(), "integration-test".to_string());
    tags
}

fn encode_share_proto(proto: &ShareProto) -> String {
    let bytes = proto.write_to_bytes().unwrap();
    format!(
        "{}-{}-{}",
        proto.threshold,
        proto.id,
        STANDARD_NO_PAD.encode(bytes)
    )
}

#[test]
fn ss1_share_strings_roundtrip_with_metadata() {
    let metadata = ss1::MetaData::with_tags(sample_tags());
    let secret = b"SS1 serialized shares keep their metadata".to_vec();

    let shares = ss1::split_secret(
        3,
        5,
        &secret,
        ss1::Reproducibility::reproducible(),
        &Some(metadata.clone()),
    )
    .unwrap();

    let decoded = shares
        .iter()
        .cloned()
        .map(|share| ss1::Share::from_string(&share.into_string()).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(shares, decoded);

    let (recovered, access, recovered_metadata) = ss1::recover_secret(&decoded).unwrap();
    assert_eq!(secret, recovered);
    assert_eq!(3, access.threshold);
    assert_eq!(5, access.shares_count);
    assert_eq!(Some(metadata), recovered_metadata);
}

#[test]
fn thss_share_strings_roundtrip_with_metadata() {
    let mut metadata = thss::MetaData::new();
    metadata
        .tags
        .insert("mime_type".to_string(), "application/octet-stream".to_string());
    metadata
        .tags
        .insert("label".to_string(), "integration-test".to_string());

    let secret = b"ThSS serialized shares keep their metadata".to_vec();

    let shares = thss::split_secret(3, 5, &secret, &Some(metadata.clone())).unwrap();

    let decoded = shares
        .iter()
        .cloned()
        .map(|share| thss::Share::from_string(&share.into_string()).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(shares, decoded);

    let (recovered, access, recovered_metadata) = thss::recover_secret(&decoded).unwrap();
    assert_eq!(secret, recovered);
    assert_eq!(3, access.threshold);
    assert_eq!(5, access.shares_count);
    assert_eq!(Some(metadata), recovered_metadata);
}

#[test]
fn dss_share_string_rejects_tampered_threshold_header() {
    let share = thss::split_secret(3, 5, b"header mismatch", &None)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let encoded = share.into_string();
    let (_, rest) = encoded.split_once('-').unwrap();
    let tampered = format!("4-{rest}");

    let error = thss::Share::from_string(&tampered).unwrap_err();
    assert!(matches!(
        error,
        Error::ShareParsingError(message) if message.contains("Incompatible thresholds")
    ));
}

#[test]
fn dss_share_string_rejects_oversized_payload() {
    let raw = format!("2-1-{}", "A".repeat(1_398_106));

    let error = thss::Share::from_string(&raw).unwrap_err();
    assert!(matches!(
        error,
        Error::ShareParsingError(message) if message.contains("exceeds maximum allowed size")
    ));
}

#[test]
fn ss1_share_string_rejects_proto_values_outside_u8_range() {
    let mut proto = ShareProto::new();
    proto.id = 256;
    proto.threshold = 2;
    proto.shares_count = 5;
    proto.data = vec![1, 2, 3];
    proto.hash = vec![4, 5, 6];

    let error = ss1::Share::from_string(&encode_share_proto(&proto)).unwrap_err();
    assert!(matches!(
        error,
        Error::ShareParsingError(message) if message.contains("exceeds u8 range")
    ));
}

#[test]
fn thss_share_string_rejects_invalid_share_info() {
    let mut proto = ShareProto::new();
    proto.id = 0;
    proto.threshold = 0;
    proto.shares_count = 5;
    proto.data = vec![1, 2, 3];

    let error = thss::Share::from_string(&encode_share_proto(&proto)).unwrap_err();
    assert!(matches!(
        error,
        Error::ShareParsingError(message) if message.contains("Found illegal share info")
    ));
}
