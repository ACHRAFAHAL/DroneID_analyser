/// OUI identifying droneID tag
const DRONE_ID_OUI: [u8; 3] = [0x6a, 0x5c, 0x35];

/// TLV tag from the 802.11 management frame
#[derive(Debug)]
pub struct Tlv<'a> {
    pub tag_type: u8,
    pub length:   u8,
    pub value:    &'a [u8],
}

/// Extracts the Radiotap header.
pub fn radiotap_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 4 {
        return None;
    }
    Some(u16::from_le_bytes([packet[2], packet[3]]) as usize)
}

pub fn frame_type_subtype(packet: &[u8], offset: usize) -> Option<(u8, u8)> {
    let fc = *packet.get(offset)?;
    let frame_type    = (fc >> 2) & 0x03;
    let frame_subtype = (fc >> 4) & 0x0F;
    Some((frame_type, frame_subtype))
}

pub fn is_beacon(packet: &[u8], offset: usize) -> bool {
    matches!(frame_type_subtype(packet, offset), Some((0, 8)))
}

/// Extract the source MAC address from the 802.11 MAC header
pub fn extract_mac(packet: &[u8], offset: usize) -> Option<String> {
    let mac = packet.get(offset + 10 .. offset + 16)?;
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

/// Parses the TLV tagged parameters section
pub fn parse_tlvs(data: &[u8]) -> Vec<Tlv> {
    let mut tlvs = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let tag_type = data[i];
        let length   = data[i + 1] as usize;
        i += 2;
        if i + length > data.len() {
            break;
        }
        tlvs.push(Tlv {
            tag_type: tag_type,
            length:   length as u8,
            value:    &data[i .. i + length],
        });
        i += length;
    }
    tlvs
}

/// Extracts the SSID string from the TLV list (0x00).
pub fn extract_ssid(tlvs: &[Tlv]) -> String {
    for tlv in tlvs {
        if tlv.tag_type == 0x00 {
            return String::from_utf8_lossy(tlv.value).to_string();
        }
    }
    String::from("<hidden>")
}

/// Returns the Vendor Specific TLV value if the OUI matches DroneID.
pub fn extract_drone_payload<'a>(tlvs: &[Tlv<'a>]) -> Option<&'a [u8]> {
    for tlv in tlvs {
        if tlv.tag_type == 0xdd && tlv.value.len() >= 4 {
            if tlv.value[0..3] == DRONE_ID_OUI {
                return Some(&tlv.value[4..]); // skip OUI + type byte
            }
        }
    }
    None
}

/// Parses the DroneID payload into a DroneInfo struct.
pub fn parse_drone_payload(payload: &[u8], mac: &str) -> Option<crate::data::DroneInfo> {
    if payload.len() < 27 {
        return None;
    }

    let id = String::from_utf8_lossy(&payload[0..11]).trim().to_string();

    let lat  = i32::from_le_bytes(payload[11..15].try_into().ok()?) as f64 / 1e5;
    let lon  = i32::from_le_bytes(payload[15..19].try_into().ok()?) as f64 / 1e5;
    let alt  = u16::from_le_bytes(payload[19..21].try_into().ok()?) as f32;
    let height  = u16::from_le_bytes(payload[21..23].try_into().ok()?) as f32;
    let speed   = u16::from_le_bytes(payload[23..25].try_into().ok()?) as f32 / 100.0;
    let heading = u16::from_le_bytes(payload[25..27].try_into().ok()?) as f32;

    Some(crate::data::DroneInfo {
        id,
        mac: mac.to_string(),
        position: crate::data::GpsPosition { latitude: lat, longitude: lon, altitude: alt },
        height,
        speed,
        heading,
    })
}