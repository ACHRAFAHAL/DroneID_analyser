use super::data::{DroneInfo, GpsPosition};

/// OUI identifying droneID tag
const DRONE_ID_OUI: [u8; 3] = [0x6a, 0x5c, 0x35];

/// TLV tag from the 802.11 management frame
#[derive(Debug)]
pub struct Tlv<'a> {
    pub tag_type: u8,
    pub _length: u8,
    pub value: &'a [u8],
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
    let frame_type = (fc >> 2) & 0x03;
    let frame_subtype = (fc >> 4) & 0x0F;
    Some((frame_type, frame_subtype))
}

pub fn is_beacon(packet: &[u8], offset: usize) -> bool {
    matches!(frame_type_subtype(packet, offset), Some((0, 8)))
}

/// Extract the source MAC address from the 802.11 MAC header
pub fn extract_mac(packet: &[u8], offset: usize) -> Option<String> {
    let mac = packet.get(offset + 10..offset + 16)?;
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

/// Parses the TLV tagged parameters section
pub fn parse_tlvs(data: &[u8]) -> Vec<Tlv<'_>> {
    let mut tlvs = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let tag_type = data[i];
        let length = data[i + 1] as usize;
        i += 2;
        if i + length > data.len() {
            break;
        }
        tlvs.push(Tlv {
            tag_type,
            _length: length as u8,
            value: &data[i..i + length],
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
pub fn parse_drone_payload(payload: &[u8], mac: &str) -> Option<DroneInfo> {
    let beacon = remoteid::france::FrenchBeacon::decode(payload);
    let id = beacon.identifier_str()?.trim().to_string();
    let lat = beacon.latitude?;
    let lon = beacon.longitude?;
    let alt = beacon.altitude.unwrap_or(0) as f32;
    let height = beacon.height.unwrap_or(0) as f32;
    let speed = beacon.horizontal_speed.unwrap_or(0) as f32;
    let heading = beacon.true_course.unwrap_or(0) as f32;

    Some(DroneInfo {
        id,
        mac: mac.to_string(),
        position: GpsPosition {
            latitude: lat,
            longitude: lon,
            altitude: alt,
        },
        height,
        speed,
        heading,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_french_beacon_tlv() {
        // Body after OUI 6A:5C:35 + type 0x01, per arrete du 27 decembre 2019.
        let mut p = vec![1, 1, 1];
        p.extend([2, 30]);
        p.extend(b"ILLUSTRATION000000000000000001");
        p.extend([4, 4]);
        p.extend(4_885_667i32.to_be_bytes()); // 48.85667
        p.extend([5, 4]);
        p.extend(235_222i32.to_be_bytes()); // 2.35222
        p.extend([6, 2]);
        p.extend(120i16.to_be_bytes());
        p.extend([7, 2]);
        p.extend(85i16.to_be_bytes());
        p.extend([10, 1, 12]);
        p.extend([11, 2]);
        p.extend(270u16.to_be_bytes());

        let d = parse_drone_payload(&p, "aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(d.id, "ILLUSTRATION000000000000000001");
        assert!((d.position.latitude - 48.85667).abs() < 1e-9);
        assert!((d.position.longitude - 2.35222).abs() < 1e-9);
        assert_eq!(d.position.altitude, 120.0);
        assert_eq!(d.height, 85.0);
        assert_eq!(d.speed, 12.0);
        assert_eq!(d.heading, 270.0);
    }
}
