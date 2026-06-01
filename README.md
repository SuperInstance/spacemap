# forbidden-zones

**Forbidden output space checking.** Define regions of your output space that must remain empty, then check if any actual output intrudes. Like a firewall for your data — define what's NOT allowed and verify nothing crosses the boundary.

[![crates.io](https://img.shields.io/crates/v/forbidden-zones.svg)](https://crates.io/crates/forbidden-zones)
[![docs.rs](https://docs.rs/forbidden-zones/badge.svg)](https://docs.rs/forbidden-zones)

## 30-Second Example

```rust
use forbidden_zones::SpaceMap;

let mut sm: SpaceMap<&str, i32> = SpaceMap::new();

// Mark regions as having output
sm.occupy("endpoint_a", 200);
sm.occupy("endpoint_b", 404);

// Define forbidden zones
sm.forbid("admin_panel");
sm.forbid("debug_endpoint");

// Everything's clean
assert!(sm.is_clean());

// Simulate an intrusion — output appeared in a forbidden zone
sm.occupy("admin_panel", 403);
assert!(!sm.is_clean());

// Get the full picture
let report = sm.audit();
println!("Intrusions: {:?}", report.intrusions);
println!("Clean ratio: {:.1}%", report.negative_space_ratio);
```

## Why?

Most validation tools check that things *are* present. `forbidden-zones` checks that things *aren't*. This is useful anywhere you need to enforce negative constraints — regions where data should not exist.

## Use Cases

### API Response Validation

Ensure sensitive fields (`password_hash`, `internal_id`, `ssn`) never appear in public API responses. Define the forbidden set once, check every response.

### Data Pipeline Output Checking

After a transform step, verify that deprecated fields, PII columns, or staging artifacts didn't leak into production output.

### Security Boundary Enforcement

Define which network zones, file paths, or resource types are off-limits. Then check that no process, job, or user has crossed the boundary.

### Feature Flag Safety

Mark experimental or internal-only features as forbidden in production context. Detect if any code path accidentally enables them.

## API Reference

### `SpaceMap<K, V>`

| Method | Returns | Description |
|--------|---------|-------------|
| `new()` | `Self` | Create an empty map |
| `occupy(key, value)` | `()` | Mark a region as having output |
| `forbid(key)` | `()` | Mark a region as forbidden |
| `check_intrusions()` | `Vec<K>` | Find occupied regions that are forbidden |
| `negative_space_ratio()` | `f64` | % of forbidden space still clean (0.0–100.0) |
| `is_clean()` | `bool` | No intrusions at all |
| `audit()` | `AuditReport<K>` | Detailed report with counts, ratios, intrusion details |
| `boundaries()` | `HashSet<K>` | Occupied keys not in forbidden set (early warning) |
| `merge(other)` | `()` | Combine two space maps |
| `vacate(&key)` | `Option<V>` | Remove from occupied set |
| `permit(&key)` | `bool` | Remove from forbidden set |
| `is_occupied(&key)` | `bool` | Check if key is occupied |
| `is_forbidden(&key)` | `bool` | Check if key is forbidden |
| `is_intrusion(&key)` | `bool` | Check if key is both occupied and forbidden |
| `get(&key)` | `Option<&V>` | Get value for an occupied key |
| `occupied_len()` | `usize` | Number of occupied regions |
| `forbidden_len()` | `usize` | Number of forbidden regions |
| `is_empty()` | `bool` | No occupied or forbidden regions |
| `clear()` | `()` | Remove all data |

### `AuditReport<K>`

| Field | Type | Description |
|-------|------|-------------|
| `occupied_count` | `usize` | Total occupied regions |
| `forbidden_count` | `usize` | Total forbidden regions |
| `intrusions` | `Vec<K>` | Keys that are both occupied and forbidden |
| `intrusion_count` | `usize` | Number of intrusions |
| `negative_space_ratio` | `f64` | % of forbidden space still clean |
| `is_clean` | `bool` | Whether no intrusions exist |
| `boundaries` | `HashSet<K>` | Occupied keys not in forbidden set |

## Design

- **Zero dependencies** — only uses `std`
- **`#![deny(unsafe_code)]`** — no unsafe code
- **Generic** — works with any `K: Eq + Hash + Clone` and any `V`
- **Clone, Debug** — `SpaceMap` and `AuditReport` derive both

## Installation

```toml
[dependencies]
forbidden-zones = "0.1"
```

## License

MIT
