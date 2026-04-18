use crate::errors::*;
use crate::proto::wrapped::share::ShareProto;
use crate::sss::{Share, HASH_ALGO};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use merkle_sigs::{MerklePublicKey, Proof, PublicKey};
use protobuf::Message;

pub(crate) fn share_to_string(
    share: Vec<u8>,
    threshold: u8,
    share_num: u8,
    signature_pair: Option<(Vec<Vec<u8>>, Proof<MerklePublicKey>)>,
) -> String {
    let mut share_protobuf = ShareProto::new();
    share_protobuf.shamir_data = share;

    if let Some((signature, proof)) = signature_pair {
        share_protobuf.signature = signature;
        share_protobuf.proof = proof.write_to_bytes().unwrap();
    }

    let proto_buf = share_protobuf.write_to_bytes().unwrap();
    let b64_share = STANDARD_NO_PAD.encode(&proto_buf);
    format!("{}-{}-{}", threshold, share_num, b64_share)
}

pub(crate) fn share_from_string(s: &str, is_signed: bool) -> Result<Share> {
    let parts: Vec<_> = s.trim().split('-').collect();

    if parts.len() != SSS_SHARE_PARTS_COUNT {
        return Err(Error::ShareParsingError(format!(
            "Expected 3 parts separated by a minus sign, found {} parts.",
            parts.len()
        )));
    }
    let (k, i, p3) = {
        let mut iter = parts.into_iter();
        let k = iter.next().unwrap().parse::<u8>()?;
        let i = iter.next().unwrap().parse::<u8>()?;
        let p3 = iter.next().unwrap();
        (k, i, p3)
    };

    if i < 1 {
        return Err(Error::ShareParsingInvalidShareId(i));
    } else if k < 2 {
        return Err(Error::ShareParsingInvalidShareThreshold(k, i));
    } else if p3.is_empty() {
        return Err(Error::ShareParsingErrorEmptyShare(i));
    }

    const MAX_SHARE_PAYLOAD_BYTES: usize = 1_048_576; // 1 MB

    if p3.len() > MAX_SHARE_PAYLOAD_BYTES * 4 / 3 + 4 {
        return Err(Error::ShareParsingError(
            "Share payload exceeds maximum allowed size".to_owned(),
        ));
    }

    let raw_data = STANDARD_NO_PAD
        .decode(p3)
        .map_err(|_| Error::ShareParsingError("Base64 decoding of data block failed".to_owned()))?;

    let protobuf_data = ShareProto::parse_from_bytes(raw_data.as_slice()).map_err(|e| {
        Error::ShareParsingError(format!(
            "Protobuf decoding of data block failed with error: {e} ."
        ))
    })?;

    let data = protobuf_data.shamir_data.clone();

    let signature_pair = if is_signed {
        let p = Proof::parse_from_bytes(&protobuf_data.proof, HASH_ALGO)
            .map_err(|e| {
                Error::ShareParsingError(format!("Failed to parse proof protobuf: {e}"))
            })?
            .ok_or_else(|| {
                Error::ShareParsingError("Proof data is incomplete or empty".to_owned())
            })?;

        let pub_key = PublicKey::from_vec(p.value, HASH_ALGO).ok_or_else(|| {
            Error::ShareParsingError("Invalid public key length in proof".to_owned())
        })?;

        let proof = Proof {
            algorithm: HASH_ALGO,
            lemma: p.lemma,
            root_hash: p.root_hash,
            value: MerklePublicKey::new(pub_key),
        };

        let signature = protobuf_data.signature.clone();
        Some((signature, proof).into())
    } else {
        None
    };

    Ok(Share {
        id: i,
        data,
        threshold: k,
        signature_pair,
    })
}

pub(crate) fn format_share_for_signing(k: u8, i: u8, data: &[u8]) -> Vec<u8> {
    let b64_data = STANDARD_NO_PAD.encode(data);
    format!("{}-{}-{}", k, i, b64_data).into_bytes()
}
