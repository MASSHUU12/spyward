#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

mod cli;
mod errors;
mod ip;
mod nfqueue;
mod nftables;

use clap::Parser;
use cli::{Action, Cli};
use errors::SpyWardError;
use nftables::NftManager;
use std::env;

extern crate libc;

fn ensure_root() -> Result<(), SpyWardError> {
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        Err(SpyWardError::NotRoot(uid))
    } else {
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let manager = NftManager::new();

    ensure_root()?;

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
            manager.setup()?;
            let queue = nfqueue::NfQueue::open_and_bind()?;
            queue.run()?;
        }
        Action::Stop => {
            manager.teardown()?;
            println!("Stopped and cleaned up.");
        }
    }

    Ok(())
}
