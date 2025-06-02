mod cli;
mod errors;
mod ip;
mod nfqueue;
mod nftables;
mod tcp;

use clap::Parser;
use cli::{Action, Cli};
use errors::SpyWardError;
use nftables::NftManager;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

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

    // TODO: Handle SIGTERM
    let is_shutting_down = Arc::new(AtomicBool::new(false));

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
            let mut queue = nfqueue::NfQueue::open_and_bind()?;

            {
                let shutdown_flag = is_shutting_down.clone();
                ctrlc::set_handler(move || {
                    eprintln!("SIGINT received; marking shutdown requested.");
                    shutdown_flag.store(true, Ordering::SeqCst);
                })
                .expect("Error installing SIGINT handler");
            }

            queue.run_until_shutdown(is_shutting_down.clone())?;
            queue.unbind()?;
            manager.teardown()?;
        }
        Action::Stop => {
            manager.teardown()?;
            println!("Stopped and cleaned up.");
        }
    }

    Ok(())
}
