use crate::{
    filter_engine::Verdict,
    packet::PacketMeta,
    protocol::reassembly::{buffer::ReassemblyBuffer, manager::ReassemblyManager},
};
use std::hash::Hash;

/// A packet‐inspector that can make accept/drop decisions
pub trait PacketHandler {
    type Header;

    fn inspect(&mut self, meta: &PacketMeta, header: &Self::Header, payload: &[u8]) -> Verdict;
}

pub struct ReassemblyPacketHandler<K, B>
where
    K: Eq + Hash + Clone,
    B: ReassemblyBuffer<Seq = u32>,
{
    reassembly: ReassemblyManager<K, B>,
}
