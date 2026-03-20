use pcap::Capture;
use crate::parser;
use crate::data::DroneInfo;

/// Opens a PCAP file and analyses every packet.
pub fn analyse_pcap(path: &str, verbose: bool) -> Vec<DroneInfo> {
    let mut cap = Capture::from_file(path)
        .unwrap_or_else(|e| {
            eprintln!("Error opening PCAP file '{}': {}", path, e);
            std::process::exit(1);
        });

    let mut drones: Vec<DroneInfo> = Vec::new();
    let mut packet_index = 0u32;

    while let Ok(packet) = cap.next_packet() {
        packet_index += 1;
        let data = packet.data;

        // Step 1: get the 802.11 header offset from Radiotap length
        let Some(rt_len) = parser::radiotap_len(data) else {
            continue;
        };

        if verbose {
            println!("[#{packet_index}] Radiotap length: {rt_len} bytes");
        }

        // beacon frame check
        if !parser::is_beacon(data, rt_len) {
            continue;
        }

        // MAC address extraction
        let mac = parser::extract_mac(data, rt_len)
            .unwrap_or_else(|| "<unknown>".to_string());

        // Step 4: jump past MAC header (24B) + fixed beacon params (12B) to reach TLVs
        let tlv_offset = rt_len + 24 + 12;
        if tlv_offset >= data.len() {
            continue;
        }

        // parse TLV tags
        let tlvs = parser::parse_tlvs(&data[tlv_offset..]);

        // Step 6: extract SSID
        let ssid = parser::extract_ssid(&tlvs);
        println!("[#{packet_index}] Beacon | MAC: {mac} | SSID: \"{ssid}\"");

        // Step 7: check for DroneID vendor-specific tag
        if let Some(payload) = parser::extract_drone_payload(&tlvs) {
            if let Some(drone) = parser::parse_drone_payload(payload, &mac) {
                println!(
                    "  ✈ DroneID detected! ID: {} | lat: {:.5} lon: {:.5} alt: {}m",
                    drone.id, drone.position.latitude,
                    drone.position.longitude, drone.position.altitude
                );
                drones.push(drone);
            }
        }
    }

    println!("\nTotal beacon frames: {packet_index}");
    println!("DroneID frames found: {}", drones.len());
    drones
}