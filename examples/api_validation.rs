//! API response validation example — ensure forbidden fields never leak into responses.

use spacemap::SpaceMap;

fn main() {
    // Simulate a JSON API response as key-value pairs
    let response_fields: Vec<(&str, &str)> = vec![
        ("id", "12345"),
        ("username", "alice"),
        ("email", "alice@example.com"),
        ("password_hash", "$2b$12$..."),
        ("role", "admin"),
        ("internal_id", "INT-001"),
    ];

    // Define which fields are forbidden in public API responses
    let mut forbidden: SpaceMap<&str, &str> = SpaceMap::new();
    forbidden.forbid("password_hash");
    forbidden.forbid("internal_id");
    forbidden.forbid("ssn");
    forbidden.forbid("credit_card");

    // Populate the map with actual response data
    let mut response_map: SpaceMap<&str, &str> = SpaceMap::new();
    for (key, value) in &response_fields {
        response_map.occupy(*key, *value);
    }

    // Merge the forbidden rules into the response map
    let mut audit_map = response_map.clone();
    for key in forbidden.forbidden_keys() {
        audit_map.forbid(*key);
    }

    // Check for leaked sensitive fields
    let intrusions = audit_map.check_intrusions();
    if !intrusions.is_empty() {
        println!("⚠️  SENSITIVE DATA LEAKED in API response!");
        for field in &intrusions {
            println!("  - Forbidden field present: {}", field);
        }
    }

    // Detailed audit
    let report = audit_map.audit();
    println!("\n📊 Audit Report:");
    println!("  Total fields: {}", report.occupied_count);
    println!("  Forbidden fields defined: {}", report.forbidden_count);
    println!("  Clean: {}", report.is_clean);
    println!("  Negative space ratio: {:.1}%", report.negative_space_ratio);

    // Boundary check — fields that aren't intrusions but are present
    println!("  Boundary fields (present, not forbidden):");
    for field in &report.boundaries {
        println!("    - {}", field);
    }

    assert_eq!(intrusions.len(), 2);
    assert!(!report.is_clean);
    println!("\n✅ Validation complete — intrusions detected as expected.");
}
