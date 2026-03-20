/// GPS coordinates of a drone.
#[derive(Debug, Clone)]
pub struct GpsPosition {
    /// Latitude in decimal degrees
    pub latitude: f64,
    /// Longitude in decimal degrees
    pub longitude: f64,
    /// Altitude in metres
    pub altitude: f32,
}

/// Data extracted from a DroneID beacon frame.
#[derive(Debug, Clone)]
pub struct DroneInfo {
    /// drone ID
    pub id: String,
    /// Source MAC address of the beacon frame
    pub mac: String,
    /// GPS position of the drone
    pub position: GpsPosition,
    /// Ground height in metres
    pub height: f32,
    /// Horizontal speed
    pub speed: f32,
    /// Heading in degrees
    pub heading: f32,
}