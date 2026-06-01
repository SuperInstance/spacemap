//! Basic usage example for spacemap.

use forbidden_zones::SpaceMap;

fn main() {
    let mut map: SpaceMap<&str, i32> = SpaceMap::new();

    // Occupy some regions
    map.occupy("user_profile", 200);
    map.occupy("settings", 100);

    // Define forbidden zones
    map.forbid("admin_panel");
    map.forbid("debug_endpoint");

    println!("Is clean? {}", map.is_clean()); // true

    // Simulate an intrusion
    map.occupy("admin_panel", 403);
    println!("Is clean? {}", map.is_clean()); // false

    // Get intrusion details
    let intrusions = map.check_intrusions();
    println!("Intrusions: {:?}", intrusions);

    // Audit report
    let report = map.audit();
    println!("Occupied: {}", report.occupied_count);
    println!("Forbidden: {}", report.forbidden_count);
    println!("Intrusion count: {}", report.intrusion_count);
    println!("Negative space ratio: {:.1}%", report.negative_space_ratio);
    println!("Boundaries (early warning): {:?}", report.boundaries);
}
