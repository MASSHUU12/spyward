# Limitations

## 1. Platform & Environment Assumptions

- **Only IPv4 support**:
NFQUEUE binding uses AF_INET. IPv6 (AF_INET6) is not bound or handled,
so any IPv6 traffic is not inspected or filtered.
- **Assumes `nft` is installed and in PATH**:
There is a TODO to check if nftables is installed,
but currently commands invoke `nft` directly without verifying its presence.
- **Requires root privileges**:
Using nftables and NFQUEUE requires elevated privileges.
There is no drop-to-less-privileged-user logic after setup.
- **Linux only**:
Uses Linux-specific APIs (libc poll, netfilter queue via libnetfilter_queue).
No portability layer for other OSes.

## 2. Configuration & Customization

- **Hard-coded table/chain names and queue number**:
`NftManager::new()` sets table `"UTUNFILTER"`, chains `"input"`/`"output"`,
and queue `0` with no way to override at runtime.
No CLI flags or config file integration for these values.
- **No configurable priorities or hooks**:
Chains use priority 0 always; some setups might need different priorities or multiple hooks.
- **No dynamic reload of rules/lists**:
The filter lists (EasyList) are loaded once at startup from a hard-coded path (`"./lists/test_list.txt"`).
There is no mechanism to reload updated lists at runtime.
- **No resource-type filtering options**:
FilterEngine only looks at URL strings;
it does not know resource type (e.g., image vs. script) to apply `$script`,
`$image`, etc., modifiers.
- **Limited CLI integration**:
The NFT manager logs only when `cli.verbose` is true,
but many TODOs reference CLI options that are not yet implemented.

## 3. Protocol Coverage

- **HTTP over TCP only**:
The TCP handler checks for HTTP requests in reassembled TCP streams.
  - **HTTPS only via SNI**:
  For port 443, it inspects only the TLS ClientHello SNI.
  No deeper TLS decryption or MITM; thus filtering is limited to domains seen in SNI.
  Scenarios like encrypted SNI (ESNI/eCH) or no-SNI packets will bypass.
  - **No HTTP/2, HTTP/3, QUIC**:
  Only plain HTTP parsing is implemented; no support for HTTP/2 framing or
  HTTP/3/QUIC over UDP.
- **UDP handling minimal**:
The UDP handler just logs and accepts all UDP traffic.
DNS requests/responses are not parsed or filtered.
- **ICMP always accepts**: The ICMP handler prints and always returns Accept;
no rate-limiting or filtering of ICMP types.
- **Other protocols accepted**:
In `packet_inspection`, any unsupported IPPrtocol falls through and is accepted.
- **No TLS certificate inspection**:
Beyond SNI, nothing examines TLS certificates or OCSP.

## 4. Filter Engine Limitations

- **Basic EasyList parsing**:
  - Only network-related rules (`FilterCategory::Network`) are considered;
  other categories (e.g., cosmetic) are ignored as intended.
  - Domain-based trie handles only literal patterns starting with `||`.
  More complex patterns (regex-based or path-based anchors) may be slower or not fully covered.
  - Liter matching compiles small regex on the fly for `^` anchors;
  no precompiled patterns or caching for performance.
- **No resource-type or third-party detection beyond domain compare**:
  - Third-party logic compares origin host vs request host,
  but no integration with referrer, iframe contexts, or script loading context.
  Is simply uses URL and an optional `origin_host` passed in.
- **No heuristic fallback**:
If URL parsing fails, defaults to accept; malformed URLs cannot be blocked.
- **No URL canonicalization**:
All rules operate on URLs;
IP addresses in requests (e.g., numeric IP instead of domain) are not filtered.
- **No rate-limiting or dynamic adaptations**:
Always static accept/drop based on filter rules; no adaptive behavior.

## 5. Packet Reassembly & State

- **Simple TCP reassembly**:
  - Uses `TCPReassemblyBuffer` in a global DashMap.
  There is no eviction of old/inactive connections;
  memory could grow unbounded.
  - No timeout or buffer size limit checks;
  fragmented or large transfers could exhaust memory.
  - Only reassembles until first HTTP header seen;
  subsequent HTTP requests on same connection are not parsed after `entry.http_done = true`.
- **Stateless UDP**:
  No reassembly for protocols over UDP (e.g., DNS, QUIC).
  Cannot inspect multi-packet UDP protocols.
- **Single threaded packet loop**:
  Packet handling in NFQUEUE callback runs synchronously.
  Heavy parsing or blocking operations could slow down queue processing and drop packets.

## 6. Performance & Scalability

- **Single NFQUEUE (queue 0)**:
All traffic is sent to queue 0 and handled in a single-threaded loop.
No multi-queue or parallel processing. High-throughput traffic may overwhelm the callback.
- **Blocking syscalls in callback**:
The callback does parsing and dispatch under lock (`DISPATCHER.lock()`).
Mutex contention if dispatch is slow.
- **Regex creation per match**:
In `literal_matches`, regex is built on the fly for patterns with `^`.
For large lists, this is costly. Ideally patterns should be precompiled once.
- **Global locks**:
Dispatcher is a `Mutext<PacketDispatcher>`.
PacketDispatcher's internals might also introduce contention.
- **No asynchronous I/O**:
Entire NFQUEUE loop is blocking and synchronous;
no offloading to worker threads for heavy tasks (e.g., DNS resoulution or logging).
- **Logging overhead**:
Printing to stdout/stderr for every packet (even if only on verbose) can be slow under load.

## 7. Loggins, Metrics & Observability

- **Basic logging**:
Uses `println!` or `eprintln!`. No structured logging (e.g., JSON),
no log levels beyond verbose flag.
- **No metrics/telemetry**:
TODO mentions statistics (accepted/dropped counts).
Currently no counters, no metrics endpoint.
- **No error reporting system**:
Errrors in callbacks write to stderr but not collected or surfaced in a monitoring-friendly way.

## 8. Security & Robustness

- **Unsafe code usage**:
The NFQUEUE callback and payload extraction use unsafe pointers.
While unavoidable with libnfnetlink, careful auditing is needed.

- **No sandboxing**:
The packet inspection logic runs in the same process with full privileges.
A bug in parsing (e.g., malformed packet) could crash or be exploited.

- **No checks on packet size**:
Buffer is a Vec with size 65_536, but no checks if packet larger;
though max IP packet is smaller. Reassembly buffers may grow unpredictably.

- **No strict validation of parsed headers**:
HTTP parsing may panic or treat invalid inputs leniently;
some error paths simply Err(_) => {}, potentially hiding issues.

- **No rate-limit for expensive operations**:
E.g., regex matching on many rules per URL for each HTTP request.
Under heavy load, could be DoS target.

- **No privilege separation**:
Root process does everything;
ideally separate process or drop privileges after setting up NFQUEUE/nftables.

## 9. Error Handling & Cleanup

- **Teardown deletes entire table**:
`nft delete table inet {table}` removes all chains and rules in that table;
TODO notes: it should only remove what was created.
If user added manual rules to the same table, they get wiped.

- **Partial cleanup on errors**:
If setup fails halfway, there is no rollback of earlier steps.
E.g., table created but chains not fully flushed.

- **No signal handling**:
The NFQUEUE loop checks a shutdown_flag, but only SIGINT is handled (SIGTERM is not).

- **No detection of existing rules**:
create_chains uses `nft list chain ... || nft add chain ...`,
but flush_chains flushes everything in those chains—including user rules if any existed.
Could disrupt existing firewall rules.

## 10. Testing & Validation

- **Limited unit tests**:
FilterEngine has some unit tests for domain trie, but many parts lack tests:
  - PacketDispatcher logic, protocol parsers, NFQUEUE callbacks, integration tests.
- **No integration tests**:
End-to-end tests simulating packets through NFQUEUE not present.
- **No fuzzing**:
Parsers (HTTP, IP headers) not fuzz-tested against malformed inputs.
- **No configuration validation**:
E.g., invalid EasyList syntax or missing file at startup will panic or exit.

## 11. Extensibility & Plugins

- **No plugin architecture yet**:
TODO mentions plugin support, but currently all handlers are hardcoded.
Adding new protocols or filters requires code changes.
- **No modular configuration of handlers**:
PacketDispatcher is global,
but no dynamic registration at runtime (e.g., load new handler modules without recompiling).
- **No scripting or user hooks**: Cannot inject custom logic easily.

## 12. DNS Resolution & Hostname-based Logic

- **No DNS filtering**:
TODO mentions DNS parsing/filtering.
Currently packets to port 53 are just passed through;
ad domains won't be blocked by DNS-level filtering.
- **No reverse DNS**:
Decisions are purely based on HTTP/SNI or literal URL strings.
Some ads server via IP-only endpoints cannot be blocked.
- **No caching of DNS results**:
Even if DNS logic were added, no caching layer exists.

## 13. Timeouts & Resource Management

- **No connection timeouts**:
TCP reassembly buffers may linger indefinitely.
Memory could accumulate.
- **No garbage collection**:
Old entries in `REASSEMBLY_TABLE` are never evicted.
- **No max buffer sizes**:
Large transfers may cause large in-memory buffers.

## 14. Concurrency & Parallelism

- **Single-threaded dispatch**:
NFQUEUE callback runs in the same thread.
For higher throughput, multiple queues or worker threads would help, but not implemented.
- **Global locks**:
Dispatcher mutex may become contention point.
- **No async runtime**:
Everything is blocking.

## 15. Resource Types & Context

- **No context about how request was initiated**:
E.g., browser vs system update; only URL string and origin host are known.
Cannot apply user-agent based filters.
- **No header inspection beyond Host/first line**:
For HTTP requests, only Host header is used.
Other headers (Referer, User-Agent) are not consulted for filtering rules.
