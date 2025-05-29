module nfnetlink_queue;

import core.stdc.stdint;

// /usr/include/libnetfilter_queue/libnetfilter_queue.h
// /usr/include/libnetfilter_queue/linux_nfnetlink_queue.h
extern (C)
{
    alias nfq_handle = void;
    alias nfq_q_handle = void;
    alias nfgenmsg = void;
    alias nfq_data = void;

    nfq_handle* nfq_open();

    int nfq_close(nfq_handle* h);

    int nfq_bind_pf(nfq_handle* h, int pf);
    int nfq_unbind_pf(nfq_handle* h, int pf);

    nfq_q_handle* nfq_create_queue(nfq_handle* h,
        ushort queue_num,
        int function(nfq_q_handle*, nfgenmsg*, nfq_data*, void*),
        void* data);
    int nfq_destroy_queue(nfq_q_handle* qh);

    enum nfqnl_config_mode
    {
        NFQNL_COPY_NONE,
        NFQNL_COPY_META,
        NFQNL_COPY_PACKET,
    }

    // Set copy-mode: copy entire packet or just the header
    int nfq_set_mode(nfq_q_handle* qh, nfqnl_config_mode mode, uint size);

    // Retrieve the fd to select()/poll() on
    int nfq_fd(nfq_handle* h);

    int nfq_handle_packet(nfq_handle* h, const char* buf, uint32_t len);

    int nfq_get_payload(nfq_data* data, ubyte** payload_ptr);

    struct nfqnl_msg_packet_hdr
    {
        uint32_t packet_id; /* ... */
    }

    nfqnl_msg_packet_hdr* nfq_get_msg_packet_hdr(nfq_data* data);

    enum
    {
        NF_ACCEPT = 1,
        NF_DROP = 0
    }

    int nfq_set_verdict(nfq_q_handle* qh,
        uint32_t packet_id,
        uint8_t verdict,
        uint32_t data_len,
        const ubyte* buf);
}

uint32_t extractPacketId(nfq_data* data)
{
    auto ph = nfq_get_msg_packet_hdr(data);
    return ph ? ph.packet_id : 0;
}

ubyte[] extractPayload(nfq_data* data)
{
    ubyte* ptr;
    auto len = nfq_get_payload(data, &ptr);
    if (len <= 0)
        return [];
    return ptr[0 .. len];
}
