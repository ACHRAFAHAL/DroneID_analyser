//! # DroneID analyser
//!
//! Wi-Fi frame analysis for drone identification and location and extraction of relevant information.
//!
//! ## Utilisation
//! ```bash
//! cargo run -- --pcap capture.pcap --output-format json
//! ```

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
#[command(group(
    ArgGroup::new("source")
        .args(["pcap", "interface"])
        .required(false)
        .multiple(false)
))]

pub struct Cli {
    /// Path to the PCAP file to analyse.
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

    // --cards : Interfaces display
    if cli.cards {
        println!("List of network interfaces :");
        return;
    }

    // No --pcap nor --interface → error
    if cli.pcap.is_none() && cli.interface.is_none() {
        eprintln!("Error : specify --pcap <fichier> or --interface <interface>.");
        std::process::exit(1);
    }

    // Dispatch
    match (&cli.pcap, &cli.interface) {
        (Some(fichier), None) => println!("file analysis : {fichier}"),
        (None, Some(iface))   => println!("Capture : {iface}"),
        _                     => unreachable!(),
    }
}

