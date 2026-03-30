use crate::data::DroneInfo;
use std::fs::File;
use std::io::Write;

/// Output format chosen by the user.
pub enum Format {
    Json,
    Csv,
    Text,
}

/// Saves drone results to a file in the requested format.
pub fn save_results(drones: &[DroneInfo], format: &Format, path: &str) -> Result<(), String> {
    if drones.is_empty() {
        println!("No drones detected — nothing saved.");
        return Ok(());
    }
    match format {
        Format::Json => save_json(drones, path),
        Format::Csv => save_csv(drones, path),
        Format::Text => save_text(drones, path),
    }
}

fn save_json(drones: &[DroneInfo], path: &str) -> Result<(), String> {
    let json = serde_json::to_string_pretty(drones).map_err(|e| format!("JSON error: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("Cannot write '{}': {e}", path))?;
    println!("Saved {} drone(s) → '{path}' (JSON)", drones.len());
    Ok(())
}

fn save_csv(drones: &[DroneInfo], path: &str) -> Result<(), String> {
    let file = File::create(path).map_err(|e| format!("Cannot create '{}': {e}", path))?;
    let mut w = csv::Writer::from_writer(file);
    w.write_record([
        "id",
        "mac",
        "latitude",
        "longitude",
        "altitude",
        "height",
        "speed",
        "heading",
    ])
    .map_err(|e| format!("CSV header: {e}"))?;
    for d in drones {
        w.write_record(&[
            d.id.clone(),
            d.mac.clone(),
            format!("{:.5}", d.position.latitude),
            format!("{:.5}", d.position.longitude),
            format!("{:.1}", d.position.altitude),
            format!("{:.1}", d.height),
            format!("{:.2}", d.speed),
            format!("{:.1}", d.heading),
        ])
        .map_err(|e| format!("CSV row: {e}"))?;
    }
    w.flush().map_err(|e| format!("CSV flush: {e}"))?;
    println!("Saved {} drone(s) → '{path}' (CSV)", drones.len());
    Ok(())
}

fn save_text(drones: &[DroneInfo], path: &str) -> Result<(), String> {
    let mut file = File::create(path).map_err(|e| format!("Cannot create '{}': {e}", path))?;
    writeln!(file, "DroneID Analysis Results\n========================")
        .map_err(|e| format!("Write error: {e}"))?;
    for (i, d) in drones.iter().enumerate() {
        writeln!(file, "\nDrone #{}", i + 1).ok();
        writeln!(file, "  ID       : {}", d.id).ok();
        writeln!(file, "  MAC      : {}", d.mac).ok();
        writeln!(file, "  Latitude : {:.5}°", d.position.latitude).ok();
        writeln!(file, "  Longitude: {:.5}°", d.position.longitude).ok();
        writeln!(file, "  Altitude : {:.1} m", d.position.altitude).ok();
        writeln!(file, "  Height   : {:.1} m", d.height).ok();
        writeln!(file, "  Speed    : {:.2} m/s", d.speed).ok();
        writeln!(file, "  Heading  : {:.1}°", d.heading).ok();
    }
    println!("Saved {} drone(s) → '{path}' (Text)", drones.len());
    Ok(())
}
