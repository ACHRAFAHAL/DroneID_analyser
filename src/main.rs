//! # DroneID analyser
//!
//! Wi-Fi frame analysis for drone identification and location and extraction of relevant information.
//!
//! ## Utilisation
//! ```bash
//! cargo run -- --pcap capture.pcap --output-format json
//! ```

mod capture;
mod parser;
mod data;

use clap::{ArgGroup, Parser, ValueEnum};

/// Output format
#[derive(Debug, Clone, ValueEnum)]
pub enum Output {
    Json,
    Csv,
    Text,
}


impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Output::Json => write!(f, "json"),
            Output::Csv => write!(f, "csv"),
            Output::Text => write!(f, "text"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "DroneID Analyser", author, version, about = "Wi-Fi frame analysis for DroneID detection")]
#[command(group(ArgGroup::new("source").args(["pcap", "interface"]).required(false).multiple(false)))]

pub struct Cli {
    /// Retrieve beacon from FILE.
    #[arg(long, value_name = "FILE")]
    pub pcap: Option<String>,

    /// Network interface for live capture (e.g. wlan0).
    #[arg(long, value_name = "INTERFACE")]
    pub interface: Option<String>,

    /// List all available network interfaces and exit.
    #[arg(long)]
    pub cards: bool,

    /// BPF capture filter to apply.
    #[arg(long, default_value = "wlan type mgt subtype beacon")]
    pub filter: String,

    /// Maximum number of packets to capture during live capture.
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub packet_count: usize,

    /// Output format for the results: json, csv or text.
    #[arg(long, default_value = "json")]
    pub output_format: Output,

    /// Output file path where results will be written.
    #[arg(long, default_value = "results.json")]
    pub output_file: String,

    /// Additional debug information.
    #[arg(short, long)]
    pub verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.cards {
        println!("Available interfaces: (Partie 6)");
        return;
    }

    match (&cli.pcap, &cli.interface) {
        (Some(file), None) => {
            let drones = capture::analyse_pcap(file, cli.verbose);
            println!("\n{} drone(s) identified.", drones.len());
            // Partie 4 : sauvegarde ici
        }
        (None, Some(iface)) => {
            println!("Live capture on {iface} — Partie 6");
        }
        _ => {
            eprintln!("Error: specify --pcap or --interface.");
            std::process::exit(1);
        }
    }
}
