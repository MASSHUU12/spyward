#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

mod cli;
mod ip;

use clap::Parser;
use cli::{Action, Cli};
use libc::AF_INET;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int, c_void};
use std::process::Command;
use std::ptr;
use std::{env, slice};

extern crate libc;

extern "C" {
    fn getuid() -> libc::uid_t;
    fn _exit(status: c_int) -> !;
    fn recv(fd: c_int, buf: *mut c_char, len: usize, flags: c_int) -> isize;
}

/// Extract the packet ID (in host byte order), or 0 if missing.
pub unsafe fn extract_packet_id(data: *mut nfq_data) -> u32 {
    let ph = nfq_get_msg_packet_hdr(data);
    if ph.is_null() {
        0
    } else {
        // ph.packet_id is in network byte order
        libc::ntohl((*ph).packet_id)
    }
}

/// Copy the packet payload into a Vec<u8>, or return empty if none.
pub unsafe fn extract_payload(data: *mut nfq_data) -> Vec<u8> {
    let mut ptr: *mut u8 = ptr::null_mut();
    let len = nfq_get_payload(data, &mut ptr);
    if len <= 0 || ptr.is_null() {
        Vec::new()
    } else {
        // Safety: libnetfilter_queue promises ptr points to at least `len` bytes
        let slice = slice::from_raw_parts(ptr, len as usize);
        slice.to_vec()
    }
}

const NF_ACCEPT: u32 = 1;
const NFQNL_COPY_PACKET: u8 = 2;

fn ensure_root() {
    unsafe {
        if getuid() != 0 {
            let _ = writeln!(
                io::stderr(),
                "ERROR: This program needs to run with administrative privileges."
            );
            _exit(1);
        }
    }
}

fn run_cmd(cmd: &str) -> bool {
    let status = Command::new("sh").arg("-c").arg(cmd).status();

    match status {
        Ok(s) if s.success() => true,
        Ok(s) => {
            let _ = writeln!(
                io::stderr(),
                "`{}` failed (exit {})",
                cmd,
                s.code().unwrap_or(-1)
            );
            false
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "`{}` failed: {}", cmd, e);
            false
        }
    }
}

fn setup_nftables() {
    // TODO: Handle errors
    // TODO: Make nftables chain/table/priority configurable
    // TODO: Check if nft is installed before running commands

    // Create the inet table if it doesn't exist
    run_cmd(
        "nft list table inet UTUNFILTER 2>/dev/null || \
         nft add table inet UTUNFILTER",
    );

    // Create/verify input/output chains
    run_cmd(
        "nft list chain inet UTUNFILTER input 2>/dev/null || \
         nft add chain inet UTUNFILTER input \
         { type filter hook input priority 0 \\; policy accept \\; }",
    );
    run_cmd(
        "nft list chain inet UTUNFILTER output 2>/dev/null || \
         nft add chain inet UTUNFILTER output \
         { type filter hook output priority 0 \\; policy accept \\; }",
    );

    // Flush + queue rules
    run_cmd("nft flush chain inet UTUNFILTER input");
    run_cmd("nft flush chain inet UTUNFILTER output");
    run_cmd("nft add rule inet UTUNFILTER input queue num 0");
    run_cmd("nft add rule inet UTUNFILTER output queue num 0");
}

fn teardown_nftables() {
    // TODO: Handle errors
    // TODO: Only remove rules/chains we created (don't delete user rules)

    run_cmd("nft delete table inet UTUNFILTER 2>/dev/null");
}

unsafe extern "C" fn packet_callback(
    qh: *mut nfq_q_handle,
    nfmsg: *mut nfgenmsg,
    nfdata: *mut nfq_data,
    data: *mut c_void,
) -> c_int {
    unsafe {
        let packet = extract_payload(nfdata);
        let id = extract_packet_id(nfdata);

        // TODO: Log only when rejected or --verbose
        // TODO: Add --verbose option
        // TODO: Check DNS for source
        // TODO: Use EasyList to decide if packed should be accepted or rejected
        // TODO: Allow custom blocklist/allowlist
        // TODO: Implement statistics (accepted/rejected counts)
        // TODO: Add unit tests for packetCallback logic

        let hdr = ip::parse_ip_header(&packet);
        ip::log_ip_header(&*hdr);

        let v = nfq_set_verdict(qh, id, NF_ACCEPT, 0, ptr::null());
        if v < 0 {
            let err = io::Error::last_os_error();
            let _ = writeln!(io::stderr(), "nfq_set_verdict error: {}", err);
        }
        v
    }
}

fn start_listener_loop() {
    unsafe {
        let h = nfq_open();
        assert!(!h.is_null(), "nfq_open failed");
        assert!(nfq_bind_pf(h, AF_INET as u16) == 0, "nfq_bind_pf failed");

        let qh = nfq_create_queue(h, 0, Some(packet_callback), ptr::null_mut());
        assert!(!qh.is_null(), "nfq_create_queue failed");
        assert!(
            nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) >= 0,
            "nfq_set_mode failed"
        );

        // On exit, clean up
        extern "C" fn cleanup(
            _: *mut nfq_q_handle,
            _: *mut c_void,
            _: *mut nfq_data,
            _: *mut c_void,
        ) -> c_int {
            0
        }

        println!("Listening for packets on NFQUEUE #0...");
        const BUF_SIZE: usize = 65_536;
        let mut buf = vec![0u8; BUF_SIZE];

        loop {
            let fd = nfq_fd(h);
            let len = recv(fd, buf.as_mut_ptr() as *mut c_char, BUF_SIZE, 0);
            if len > 0 {
                nfq_handle_packet(h, buf.as_mut_ptr() as *mut c_char, len as i32);
            }

            // TODO: Add signal handling for graceful shutdown (SIGINT/SIGTERM)
            // TODO: Add timeout or error handling for recv
        }

        // unreachable!()
        // nfq_unbind_pf(h, AF_INET);
        // nfq_close(h);
    }
}

fn main() {
    let cli = Cli::parse();

    ensure_root();

    // TODO: Load & parse an EasyList-style blocklist
    // TODO: Add logging, privileged-to-unprivileged drop
    // TODO: Config flags
    // TODO: Add version and help flags
    // TODO: Allow running as a daemon/service
    // TODO: Add config file support
    // TODO: Validate system dependencies (nft, nfqueue, permissions)
    // TODO: Self-test and diagnostics mode

    match cli.action {
        Action::Start => {
            setup_nftables();
            start_listener_loop();
        }
        Action::Stop => {
            teardown_nftables();
            println!("Stopped and cleaned up.");
        }
    }
}
