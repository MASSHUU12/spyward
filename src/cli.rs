use clap::{Parser, ValueEnum};

#[derive(Debug, ValueEnum, Clone)]
pub enum Action {
    Start,
    Stop,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long)]
    pub action: Action,

    #[arg(short, long)]
    pub verbose: bool,

    // TODO: Default value etc
    #[arg(short, long, default_value = "./config/config.ini")]
    pub config: String,
}
