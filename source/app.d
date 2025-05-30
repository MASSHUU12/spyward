module main;

import core.stdc.errno;
import core.sys.posix.sys.socket;
import core.sys.posix.unistd;
import nfnetlink_queue;
import std.exception;
import std.process;
import std.stdio;
import std.string;

import ip;

enum Actions
{
    Start,
    Stop,
    Unknown
}

enum IFNAMSIZ = 16;
alias c_short = short;

void ensureRoot()
{
    if (getuid() != 0)
    {
        stderr.writeln("ERROR: This program needs to run with administrative privileges.");
        _exit(1);
    }
}

bool runCmd(string cmd)
{
    auto result = executeShell(cmd);
    if (result.status != 0)
    {
        stderr.writeln("`", cmd, "` failed (exit ", result.status, ")");
        return false;
    }
    return true;
}

void setupNftables()
{
    // TODO: Handle errors
    // TODO: Make nftables chain/table/priority configurable
    // TODO: Check if nft is installed before running commands

    // Create the inet table if it doesn't exist
    runCmd("nft list table inet UTUNFILTER 2>/dev/null || " ~
            "nft add table inet UTUNFILTER");

    // Create (or verify) the input chain
    runCmd("nft list chain inet UTUNFILTER input 2>/dev/null || " ~
            "nft add chain inet UTUNFILTER input " ~ "{ type filter hook input priority 0 \\; policy accept \\; }");

    // Create (or verify) the output chain
    runCmd("nft list chain inet UTUNFILTER output 2>/dev/null || " ~
            "nft add chain inet UTUNFILTER output " ~ "{ type filter hook output priority 0 \\; policy accept \\; }");

    // Flush each chain and send to NFQUEUE #0
    runCmd("nft flush chain inet UTUNFILTER input");
    runCmd("nft flush chain inet UTUNFILTER output");
    runCmd("nft add rule inet UTUNFILTER input queue num 0");
    runCmd("nft add rule inet UTUNFILTER output queue num 0");
}

void teardownNftables()
{
    // TODO: Handle errors
    // TODO: Only remove rules/chains we created (don't delete user rules)

    // Deleting the table will remove all its chains & rules.
    runCmd("nft delete table inet UTUNFILTER 2>/dev/null");
}

Actions parseArgs(string[] args)
{
    if (args.length >= 2)
    {
        switch (args[1])
        {
        case "start":
            return Actions.Start;
        case "stop":
            return Actions.Stop;
        default:
            return Actions.Unknown;
        }
    }
    return Actions.Unknown;
}

extern (C) int packetCallback(nfq_q_handle* qh, void* nfmsg, nfq_data* nfdata, void* _)
{
    ubyte[] packet = extractPayload(nfdata);
    IIPHeader hdr = parseIPHeader(packet);
    int id = extractPacketId(nfdata);

    // TODO: Log only when rejected or --verbose
    // TODO: Add --verbose option
    // TODO: Check DNS for source
    // TODO: Use EasyList to decide if packed should be accepted or rejected
    // TODO: Allow custom blocklist/allowlist
    // TODO: Implement statistics (accepted/rejected counts)
    // TODO: Add unit tests for packetCallback logic

    logIPHeader(hdr);

    auto v = nfq_set_verdict(qh, id, NF_ACCEPT, 0, null);
    if (v < 0)
    {
        stderr.writeln(errno);
        return v;
    }

    return v;
}

void startListenerLoop()
{
    auto h = nfq_open();
    enforce(h !is null, "nfq_open failed");

    enforce(nfq_bind_pf(h, AF_INET) == 0, "nfq_bind_pf failed");
    auto qh = nfq_create_queue(h, 0, &packetCallback, null);
    enforce(qh !is null, "nfq_create_queue failed");

    // Pass entire packet
    enforce(nfq_set_mode(qh, nfqnl_config_mode.NFQNL_COPY_PACKET, 0xffff) >= 0,
        "nfq_set_mode failed");

    scope (exit)
    {
        nfq_unbind_pf(h, AF_INET);
        nfq_close(h);
    }

    writeln("Listening for packets on NFQUEUE #0...");
    enum BUF_SIZE = 65_536;
    char[BUF_SIZE] buf;

    while (true)
    {
        auto fd = nfq_fd(h);
        auto len = recv(fd, buf.ptr, BUF_SIZE, 0);
        if (len > 0)
            nfq_handle_packet(h, buf.ptr, cast(uint) len);
        // TODO: Add signal handling for graceful shutdown (SIGINT/SIGTERM)
        // TODO: Add timeout or error handling for recv
    }
}

int main(string[] args)
{
    ensureRoot();

    // TODO: Load & parse an EasyList-style blocklist
    // TODO: Add logging, privileged-to-unprivileged drop
    // TODO: Config flags
    // TODO: Add version and help flags
    // TODO: Allow running as a daemon/service
    // TODO: Add config file support
    // TODO: Validate system dependencies (nft, nfqueue, permissions)
    // TODO: Self-test and diagnostics mode

    switch (parseArgs(args))
    {
    case Actions.Start:
        setupNftables();
        startListenerLoop();
        break;
    case Actions.Stop:
        teardownNftables();
        writeln("Stopped and cleaned up.");
        break;
    default:
        writef("Usage: %s {start|stop}\n", args[0]);
        // TODO: Print more detailed usage instructions
        return 1;
    }

    return 0;
}
