use crate::errors::SpyWardError;
use std::io::{self, Write};
use std::process::Command;

pub struct NftManager {
    table: String,
    chain_input: String,
    chain_output: String,
    queue_num: u16,
}

impl NftManager {
    // TODO: Make nftables chain/table/priority configurable by user
    // TODO: Check if nft is installed before running commands

    pub fn new() -> Self {
        Self {
            table: "UTUNFILTER".to_string(),
            chain_input: "input".to_string(),
            chain_output: "output".to_string(),
            queue_num: 0,
        }
    }

    fn run_cmd(cmd: &str) -> Result<(), SpyWardError> {
        match Command::new("sh").arg("-c").arg(cmd).status() {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => {
                let code = s.code().unwrap_or(-1);
                let stderr_msg = format!("`{}` failed (exit {})", cmd, code);
                let _ = writeln!(io::stderr(), "{}", &stderr_msg);
                Err(SpyWardError::NftablesCmd(stderr_msg))
            }
            Err(e) => {
                let stderr_msg = format!("`{}` failed: {}", cmd, e);
                let _ = writeln!(io::stderr(), "{}", &stderr_msg);
                Err(SpyWardError::NftablesCmd(stderr_msg))
            }
        }
    }

    /// Ensure the base table exists (creates it if it doesn’t).
    pub fn create_table(&self) -> Result<(), SpyWardError> {
        let cmd = format!(
            "nft list table inet {table} 2>/dev/null || \
             nft add table inet {table}",
            table = self.table
        );
        Self::run_cmd(&cmd)
    }

    /// Ensure that `input` and `output` chains exist (or create them).
    pub fn create_chains(&self) -> Result<(), SpyWardError> {
        let input_chain = format!(
            "nft list chain inet {table} {chain} 2>/dev/null || \
             nft add chain inet {table} {chain} \
                {{ type filter hook {hook} priority 0 \\; policy accept \\; }}",
            table = self.table,
            chain = self.chain_input,
            hook = "input",
        );
        let output_chain = format!(
            "nft list chain inet {table} {chain} 2>/dev/null || \
             nft add chain inet {table} {chain} \
                {{ type filter hook {hook} priority 0 \\; policy accept \\; }}",
            table = self.table,
            chain = self.chain_output,
            hook = "output",
        );

        Self::run_cmd(&input_chain)?;
        Self::run_cmd(&output_chain)?;
        Ok(())
    }

    pub fn flush_chains(&self) -> Result<(), SpyWardError> {
        let flush_input = format!(
            "nft flush chain inet {table} {chain}",
            table = self.table,
            chain = self.chain_input
        );
        let flush_output = format!(
            "nft flush chain inet {table} {chain}",
            table = self.table,
            chain = self.chain_output
        );
        Self::run_cmd(&flush_input)?;
        Self::run_cmd(&flush_output)?;
        Ok(())
    }

    pub fn add_queue_rules(&self) -> Result<(), SpyWardError> {
        let rule_input = format!(
            "nft add rule inet {table} {chain} queue num {qnum}",
            table = self.table,
            chain = self.chain_input,
            qnum = self.queue_num
        );
        let rule_output = format!(
            "nft add rule inet {table} {chain} queue num {qnum}",
            table = self.table,
            chain = self.chain_output,
            qnum = self.queue_num
        );
        Self::run_cmd(&rule_input)?;
        Self::run_cmd(&rule_output)?;
        Ok(())
    }

    pub fn setup(&self) -> Result<(), SpyWardError> {
        self.create_table()?;
        self.create_chains()?;
        self.flush_chains()?;
        self.add_queue_rules()?;
        Ok(())
    }

    pub fn teardown(&self) -> Result<(), SpyWardError> {
        // TODO: Only remove rules/chains we created (don't delete user rules)
        let cmd = format!("nft delete table inet {} 2>/dev/null", self.table);
        Self::run_cmd(&cmd)
    }

    fn log(&self, cli: &crate::cli::Cli, msg: &str) {
        if cli.verbose {
            eprintln!("[nftables] {}", msg);
        }
    }
}
