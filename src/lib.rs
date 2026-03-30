//! # droneID analyzer — library
//!
//! Reusable library for Wi-Fi PCAP analysis and DroneID frame extraction.
//!
//! ## Modules
//! - [`capture`] — opens and reads PCAP files packet by packet
//! - [`parser`]  — parses 802.11 frames and TLV tags
//! - [`drone`]   — data structures for drone information
//! - [`output`]  — saves results to JSON, CSV or text files
//!

pub mod capture;
pub mod data;
pub mod output;
pub mod parser;
