use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use protobuf::Message;

use crate::errors::*;
use crate::proto::dss::share::ShareProto;

pub(crate) fn format_share_protobuf(share: &ShareProto) -> String {
    let bytes = share.write_to_bytes().unwrap();
    let base64_data = STANDARD_NO_PAD.encode(&bytes);
    format!("{}-{}-{}", share.threshold, share.id, base64_data)
}

pub(crate) fn parse_share_protobuf(raw: &str) -> Result<ShareProto> {
    let (threshold, id, base64_data) = parse_raw_share(raw)?;

    const MAX_SHARE_PAYLOAD_BYTES: usize = 1_048_576; // 1 MB

    if base64_data.len() > MAX_SHARE_PAYLOAD_BYTES * 4 / 3 + 4 {
        return Err(Error::ShareParsingError(
            "Share payload exceeds maximum allowed size".to_owned(),
        ));
    }

    let data = STANDARD_NO_PAD.decode(&base64_data).map_err(|_| {
        Error::ShareParsingError("Base64 decoding of data block failed".to_string())
    })?;

    let share_proto = ShareProto::parse_from_bytes(data.as_slice()).map_err(|e| {
        Error::ShareParsingError(format!(
            "Protobuf decoding of data block failed with error: {e} ."
        ))
    })?;

    if threshold != share_proto.threshold {
        return Err(Error::ShareParsingError(format!(
            "Incompatible thresholds between decoded Protobuf provided \
                 (k={}) and raw share (k={})",
            share_proto.threshold, threshold
        )));
    }

    if id != share_proto.id {
        return Err(Error::ShareParsingError(format!(
            "Incompatible ids between decoded Protobuf provided \
                 (i={}) and raw share (i={})",
            share_proto.id, id
        )));
    }

    Ok(share_proto)
}

fn parse_raw_share(raw: &str) -> Result<(u32, u32, String)> {
    let parts: Vec<_> = raw.trim().split('-').collect();

    if parts.len() != 3 {
        return Err(Error::ShareParsingError(format!(
            "Expected 3 parts separated by a minus sign, found {} parts.",
            parts.len()
        )));
    }

    let mut iter = parts.into_iter();
    let k = iter.next().unwrap().parse::<u32>()?;
    let i = iter.next().unwrap().parse::<u32>()?;
    let data = iter.next().unwrap();
    Ok((k, i, data.to_string()))
}
