use crate::{filter_engine::Verdict, packet::PacketMeta};

/// A packet‐inspector that can make accept/drop decisions
pub trait PacketHandler {
    type Header;

    fn inspect(&mut self, meta: &PacketMeta, header: &Self::Header, payload: &[u8]) -> Verdict;
}
