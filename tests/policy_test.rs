use std::path::Path;

use toolcage::policy::{
    Decision, MountMode, Policy, UnlistedMode, DEFAULT_FUEL, DEFAULT_MEMORY_MAX_MB,
    DEFAULT_OUTPUT_MAX_KB, DEFAULT_TIMEOUT_MS,
};

fn load(yaml: &str) -> Policy {
    Policy::from_yaml_str(yaml, Path::new("/base"), None).expect("policy should parse")
}

fn load_err(yaml: &str) -> String {
    match Policy::from_yaml_str(yaml, Path::new("/base"), None) {
        Ok(_) => panic!("expected policy to be rejected:\n{}", yaml),
        Err(e) => format!("{:#}", e),
    }
}

#[test]
fn minimal_policy_gets_defaults_and_default_deny() {
    let p = load("version: 1\n");
    assert_eq!(p.unlisted, UnlistedMode::Deny);
    assert_eq!(p.defaults.limits.timeout_ms, DEFAULT_TIMEOUT_MS);
    assert_eq!(p.defaults.limits.fuel, DEFAULT_FUEL);
    assert_eq!(p.defaults.limits.memory_max_mb, DEFAULT_MEMORY_MAX_MB);
    assert_eq!(p.defaults.limits.output_max_kb, DEFAULT_OUTPUT_MAX_KB);
    assert!(p.defaults.env.is_empty());
    assert!(p.defaults.mounts.is_empty());
    match p.decide("anything") {
        Decision::Deny { listed, .. } => assert!(!listed),
        other => panic!("expected deny, got {:?}", other),
    }
}

#[test]
fn unlisted_defaults_mode_allows_with_defaults() {
    let p = load("version: 1\nunlisted_tools: defaults\n");
    match p.decide("anything") {
        Decision::Allow(g) => {
            assert!(g.mounts.is_empty());
            assert!(g.env.is_empty());
        }
        other => panic!("expected allow, got {:?}", other),
    }
}

#[test]
fn null_tool_entry_means_allow_with_defaults() {
    let p = load("version: 1\ntools:\n  echo:\n");
    assert!(p.is_listed("echo"));
    match p.decide("echo") {
        Decision::Allow(g) => assert!(g.mounts.is_empty()),
        other => panic!("expected allow, got {:?}", other),
    }
}

#[test]
fn empty_object_tool_entry_means_allow_with_defaults() {
    let p = load("version: 1\ntools:\n  echo: {}\n");
    match p.decide("echo") {
        Decision::Allow(_) => {}
        other => panic!("expected allow, got {:?}", other),
    }
}

#[test]
fn denied_tool() {
    let p = load("version: 1\ntools:\n  danger:\n    deny: true\n");
    match p.decide("danger") {
        Decision::Deny { listed, reason } => {
            assert!(listed);
            assert!(reason.contains("danger"));
        }
        other => panic!("expected deny, got {:?}", other),
    }
    assert!(!p.visible("danger"));
}

#[test]
fn deny_combined_with_grants_is_rejected() {
    let err = load_err(
        "version: 1\ntools:\n  danger:\n    deny: true\n    fs:\n      /data: { host: d, mode: ro }\n",
    );
    assert!(err.contains("cannot be combined"));
}

#[test]
fn per_tool_limits_override_only_named_fields() {
    let p = load(
        "version: 1\ndefaults:\n  timeout_ms: 10000\n  fuel: 5000\ntools:\n  slow:\n    timeout_ms: 60000\n",
    );
    match p.decide("slow") {
        Decision::Allow(g) => {
            assert_eq!(g.limits.timeout_ms, 60000);
            assert_eq!(g.limits.fuel, 5000);
            assert_eq!(g.limits.memory_max_mb, DEFAULT_MEMORY_MAX_MB);
        }
        other => panic!("expected allow, got {:?}", other),
    }
}

#[test]
fn env_merges_with_tool_winning() {
    let p = load(
        "version: 1\ndefaults:\n  env:\n    A: base\n    B: base\ntools:\n  t:\n    env:\n      B: tool\n      C: tool\n",
    );
    match p.decide("t") {
        Decision::Allow(g) => {
            let mut env = g.env.clone();
            env.sort();
            assert_eq!(
                env,
                vec![
                    ("A".to_string(), "base".to_string()),
                    ("B".to_string(), "tool".to_string()),
                    ("C".to_string(), "tool".to_string()),
                ]
            );
        }
        other => panic!("expected allow, got {:?}", other),
    }
}

#[test]
fn mounts_merge_and_tool_overrides_same_guest_path() {
    let p = load(
        "version: 1\ndefaults:\n  fs:\n    /shared: { host: /srv/shared, mode: ro }\ntools:\n  w:\n    fs:\n      /shared: { host: /srv/other, mode: rw }\n      /out: { host: out, mode: rw }\n",
    );
    match p.decide("w") {
        Decision::Allow(g) => {
            assert_eq!(g.mounts.len(), 2);
            let shared = g.mounts.iter().find(|m| m.guest_path == "/shared").unwrap();
            assert_eq!(shared.host_path, Path::new("/srv/other"));
            assert_eq!(shared.mode, MountMode::ReadWrite);
            let out = g.mounts.iter().find(|m| m.guest_path == "/out").unwrap();
            // relative host resolved against the policy file's directory
            assert_eq!(out.host_path, Path::new("/base/out"));
        }
        other => panic!("expected allow, got {:?}", other),
    }
}

#[test]
fn unlisted_tool_with_listed_neighbors_is_denied_by_default() {
    let p = load("version: 1\ntools:\n  a:\n");
    match p.decide("b") {
        Decision::Deny { listed, .. } => assert!(!listed),
        other => panic!("expected deny, got {:?}", other),
    }
    assert!(p.visible("a"));
    assert!(!p.visible("b"));
}

#[test]
fn permissive_vacuum_allows_everything_capability_free() {
    let p = Policy::permissive_vacuum();
    match p.decide("whatever") {
        Decision::Allow(g) => {
            assert!(g.mounts.is_empty());
            assert!(g.env.is_empty());
            assert_eq!(g.limits.timeout_ms, DEFAULT_TIMEOUT_MS);
        }
        other => panic!("expected allow, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

#[test]
fn rejects_wrong_version() {
    assert!(load_err("version: 2\n").contains("version"));
}

#[test]
fn rejects_unknown_top_level_field() {
    assert!(load_err("version: 1\nbogus: true\n").contains("bogus"));
}

#[test]
fn rejects_unknown_tool_field() {
    let err = load_err("version: 1\ntools:\n  t:\n    network: allow\n");
    assert!(err.contains("network"));
}

#[test]
fn rejects_bad_mount_mode() {
    let err = load_err("version: 1\ntools:\n  t:\n    fs:\n      /d: { host: d, mode: rwx }\n");
    assert!(err.contains("rwx"));
}

#[test]
fn rejects_relative_guest_path() {
    let err = load_err("version: 1\ntools:\n  t:\n    fs:\n      data: { host: d, mode: ro }\n");
    assert!(err.contains("absolute"));
}

#[test]
fn rejects_root_guest_path() {
    let err = load_err("version: 1\ntools:\n  t:\n    fs:\n      /: { host: d, mode: ro }\n");
    assert!(err.contains("subdirectory"));
}

#[test]
fn rejects_dotdot_guest_path() {
    let err =
        load_err("version: 1\ntools:\n  t:\n    fs:\n      /d/../e: { host: d, mode: ro }\n");
    assert!(err.contains(".."));
}

#[test]
fn rejects_env_name_with_equals() {
    let err = load_err("version: 1\ntools:\n  t:\n    env:\n      \"A=B\": x\n");
    assert!(err.contains('='));
}

#[test]
fn rejects_out_of_range_limits() {
    assert!(load_err("version: 1\ndefaults:\n  timeout_ms: 0\n").contains("timeout_ms"));
    assert!(load_err("version: 1\ndefaults:\n  timeout_ms: 999999999\n").contains("timeout_ms"));
    assert!(load_err("version: 1\ndefaults:\n  fuel: 1\n").contains("fuel"));
    assert!(load_err("version: 1\ndefaults:\n  memory_max_mb: 0\n").contains("memory_max_mb"));
    assert!(load_err("version: 1\ndefaults:\n  output_max_kb: 0\n").contains("output_max_kb"));
}

#[test]
fn rejects_bad_unlisted_value() {
    assert!(load_err("version: 1\nunlisted_tools: maybe\n").contains("maybe"));
}

#[test]
fn listed_tools_reports_allow_and_deny() {
    let p = load("version: 1\ntools:\n  a:\n  b:\n    deny: true\n");
    let mut listed = p.listed_tools();
    listed.sort();
    assert_eq!(listed, vec![("a", true), ("b", false)]);
}
