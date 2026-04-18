use super::{MetaData, Share};
use crate::dss::format::{format_share_protobuf, parse_share_protobuf};
use crate::dss::utils::{btreemap_to_hashmap, hashmap_to_btreemap};
use crate::errors::*;
use crate::proto::dss::metadata::MetaDataProto;
use crate::proto::dss::share::ShareProto;

pub(crate) fn share_to_string(share: Share) -> String {
    let proto = share_to_protobuf(share);
    format_share_protobuf(&proto)
}

pub(crate) fn share_from_string(raw: &str) -> Result<Share> {
    let mut proto = parse_share_protobuf(raw)?;

    let metadata_proto = if proto.meta_data.is_some() {
        Some(metadata_from_proto(proto.meta_data.take().unwrap()))
    } else {
        None
    };

    if proto.id > 255 || proto.threshold > 255 || proto.shares_count > 255 {
        return Err(Error::ShareParsingError(format!(
            "Share field value exceeds u8 range: id = {}, threshold = {}, shares_count = {}.",
            proto.id, proto.threshold, proto.shares_count
        )));
    }

    let i = proto.id as u8;
    let k = proto.threshold as u8;
    let n = proto.shares_count as u8;

    if k < 1 || i < 1 {
        return Err(Error::ShareParsingError(format!(
            "Found illegal share info: threshold = {}, identifier = {}.",
            k, i
        )));
    }

    if n < 1 || k > n || i > n {
        return Err(Error::ShareParsingError(format!(
            "Found illegal share info: shares_count = {}, threshold = {}, identifier = {}.",
            n, k, i
        )));
    }

    let share = Share {
        id: i,
        threshold: k,
        shares_count: n,
        data: std::mem::take(&mut proto.data),
        hash: std::mem::take(&mut proto.hash),
        metadata: metadata_proto,
    };

    Ok(share)
}

pub(crate) fn share_to_protobuf(share: Share) -> ShareProto {
    let mut proto = ShareProto::new();

    proto.id = share.id.into();
    proto.threshold = share.threshold.into();
    proto.shares_count = share.shares_count.into();
    proto.data = share.data;
    proto.hash = share.hash;

    if let Some(meta_data) = share.metadata {
        let metadata_proto = metadata_to_proto(meta_data);
        proto.meta_data = protobuf::MessageField::some(metadata_proto);
    }

    proto
}

fn metadata_to_proto(meta_data: MetaData) -> MetaDataProto {
    let mut proto = MetaDataProto::new();
    proto.tags = btreemap_to_hashmap(meta_data.tags);
    proto
}

fn metadata_from_proto(mut proto: MetaDataProto) -> MetaData {
    MetaData {
        tags: hashmap_to_btreemap(std::mem::take(&mut proto.tags)),
    }
}
