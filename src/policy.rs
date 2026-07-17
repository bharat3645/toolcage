//! Policy: what each tool may see (filesystem, env) and spend (time, fuel, memory, output).
//!
//! YAML shape:
//!
//! ```yaml
//! version: 1
//! defaults:
//!   timeout_ms: 30000
//!   fuel: 2000000000
//!   memory_max_mb: 256
//!   output_max_kb: 4096
//! unlisted_tools: deny        # deny | defaults
//! tools:
//!   echo: {}                  # allowed, defaults only (no filesystem, no env)
//!   read_file:
//!     fs:
//!       /data: { host: ./data, mode: ro }
//!   danger:
//!     deny: true
//! ```
//!
//! Relative `host` paths are resolved against the directory containing the
//! policy file. Merging: a tool entry overrides `defaults` per field; `env`
//! and `fs` are merged key-by-key with the tool entry winning.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_FUEL: u64 = 2_000_000_000;
pub const DEFAULT_MEMORY_MAX_MB: u64 = 256;
pub const DEFAULT_OUTPUT_MAX_KB: u64 = 4_096;

pub const MAX_TIMEOUT_MS: u64 = 600_000;
pub const MAX_MEMORY_MAX_MB: u64 = 4_096;
pub const MAX_OUTPUT_MAX_KB: u64 = 1_048_576;
pub const MIN_FUEL: u64 = 1_000;

// ---------------------------------------------------------------------------
// Raw serde shapes (file format, strict: unknown fields rejected)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: u32,
    #[serde(default)]
    defaults: RawGrant,
    #[serde(default)]
    unlisted_tools: Option<String>,
    #[serde(default)]
    tools: BTreeMap<String, Option<RawTool>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGrant {
    timeout_ms: Option<u64>,
    fuel: Option<u64>,
    memory_max_mb: Option<u64>,
    output_max_kb: Option<u64>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    fs: BTreeMap<String, RawMount>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTool {
    #[serde(default)]
    deny: bool,
    timeout_ms: Option<u64>,
    fuel: Option<u64>,
    memory_max_mb: Option<u64>,
    output_max_kb: Option<u64>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    fs: BTreeMap<String, RawMount>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMount {
    host: String,
    mode: String,
}

// ---------------------------------------------------------------------------
// Public model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

impl MountMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MountMode::ReadOnly => "ro",
            MountMode::ReadWrite => "rw",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Mount {
    pub guest_path: String,
    pub host_path: PathBuf,
    pub mode: MountMode,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub timeout_ms: u64,
    pub fuel: u64,
    pub memory_max_mb: u64,
    pub output_max_kb: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            fuel: DEFAULT_FUEL,
            memory_max_mb: DEFAULT_MEMORY_MAX_MB,
            output_max_kb: DEFAULT_OUTPUT_MAX_KB,
        }
    }
}

/// Everything a single tool call is granted: budgets, env vars, mounts.
#[derive(Debug, Clone, Default)]
pub struct Grant {
    pub limits: Limits,
    pub env: Vec<(String, String)>,
    pub mounts: Vec<Mount>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlistedMode {
    Deny,
    Defaults,
}

#[derive(Debug, Clone)]
enum ToolRule {
    Deny,
    Allow(Box<Grant>),
}

#[derive(Debug, Clone)]
pub enum Decision {
    Deny { reason: String, listed: bool },
    Allow(Grant),
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub source: Option<PathBuf>,
    pub defaults: Grant,
    pub unlisted: UnlistedMode,
    tools: BTreeMap<String, ToolRule>,
}

impl Policy {
    /// The no-policy-file mode: every tool runs, but in a capability vacuum
    /// (no filesystem, no env, default budgets).
    pub fn permissive_vacuum() -> Policy {
        Policy {
            source: None,
            defaults: Grant::default(),
            unlisted: UnlistedMode::Defaults,
            tools: BTreeMap::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Policy> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file {}", path.display()))?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Policy::from_yaml_str(&text, base_dir, Some(path.to_path_buf()))
    }

    pub fn from_yaml_str(text: &str, base_dir: &Path, source: Option<PathBuf>) -> Result<Policy> {
        let raw: RawPolicy = serde_yaml::from_str(text).context("invalid policy YAML")?;
        if raw.version != 1 {
            bail!("unsupported policy version {} (expected 1)", raw.version);
        }
        let unlisted = match raw.unlisted_tools.as_deref() {
            None | Some("deny") => UnlistedMode::Deny,
            Some("defaults") => UnlistedMode::Defaults,
            Some(other) => bail!(
                "unlisted_tools must be \"deny\" or \"defaults\", got {:?}",
                other
            ),
        };

        let defaults = build_grant(
            &Limits::default(),
            raw.defaults.timeout_ms,
            raw.defaults.fuel,
            raw.defaults.memory_max_mb,
            raw.defaults.output_max_kb,
            &BTreeMap::new(),
            &raw.defaults.env,
            &[],
            &raw.defaults.fs,
            base_dir,
        )
        .context("in defaults section")?;

        let mut tools = BTreeMap::new();
        for (name, entry) in &raw.tools {
            if name.is_empty() {
                bail!("tool names must be non-empty");
            }
            let rule = match entry {
                None => ToolRule::Allow(Box::new(defaults.clone())),
                Some(t) if t.deny => {
                    if t.timeout_ms.is_some()
                        || t.fuel.is_some()
                        || t.memory_max_mb.is_some()
                        || t.output_max_kb.is_some()
                        || !t.env.is_empty()
                        || !t.fs.is_empty()
                    {
                        bail!("tool {:?}: deny: true cannot be combined with grants", name);
                    }
                    ToolRule::Deny
                }
                Some(t) => {
                    let g = build_grant(
                        &defaults.limits,
                        t.timeout_ms,
                        t.fuel,
                        t.memory_max_mb,
                        t.output_max_kb,
                        &to_map(&defaults.env),
                        &t.env,
                        &defaults.mounts,
                        &t.fs,
                        base_dir,
                    )
                    .with_context(|| format!("in tool {:?}", name))?;
                    ToolRule::Allow(Box::new(g))
                }
            };
            tools.insert(name.clone(), rule);
        }

        Ok(Policy {
            source,
            defaults,
            unlisted,
            tools,
        })
    }

    pub fn decide(&self, tool: &str) -> Decision {
        match self.tools.get(tool) {
            Some(ToolRule::Deny) => Decision::Deny {
                reason: format!("tool {:?} is denied by policy", tool),
                listed: true,
            },
            Some(ToolRule::Allow(g)) => Decision::Allow((**g).clone()),
            None => match self.unlisted {
                UnlistedMode::Defaults => Decision::Allow(self.defaults.clone()),
                UnlistedMode::Deny => Decision::Deny {
                    reason: format!("tool {:?} is not listed in the policy (default deny)", tool),
                    listed: false,
                },
            },
        }
    }

    pub fn is_listed(&self, tool: &str) -> bool {
        self.tools.contains_key(tool)
    }

    /// Should this tool appear in tools/list output?
    pub fn visible(&self, tool: &str) -> bool {
        !matches!(self.decide(tool), Decision::Deny { .. })
    }

    pub fn listed_tools(&self) -> Vec<(&str, bool)> {
        self.tools
            .iter()
            .map(|(name, rule)| (name.as_str(), !matches!(rule, ToolRule::Deny)))
            .collect()
    }
}

fn to_map(pairs: &[(String, String)]) -> BTreeMap<String, String> {
    pairs.iter().cloned().collect()
}

#[allow(clippy::too_many_arguments)]
fn build_grant(
    base: &Limits,
    timeout_ms: Option<u64>,
    fuel: Option<u64>,
    memory_max_mb: Option<u64>,
    output_max_kb: Option<u64>,
    base_env: &BTreeMap<String, String>,
    env: &BTreeMap<String, String>,
    base_mounts: &[Mount],
    fs: &BTreeMap<String, RawMount>,
    base_dir: &Path,
) -> Result<Grant> {
    let limits = Limits {
        timeout_ms: timeout_ms.unwrap_or(base.timeout_ms),
        fuel: fuel.unwrap_or(base.fuel),
        memory_max_mb: memory_max_mb.unwrap_or(base.memory_max_mb),
        output_max_kb: output_max_kb.unwrap_or(base.output_max_kb),
    };
    validate_limits(&limits)?;

    let mut merged_env = base_env.clone();
    for (k, v) in env {
        validate_env_key(k)?;
        merged_env.insert(k.clone(), v.clone());
    }
    let env_vec: Vec<(String, String)> = merged_env.into_iter().collect();

    let mut merged: BTreeMap<String, Mount> = base_mounts
        .iter()
        .map(|m| (m.guest_path.clone(), m.clone()))
        .collect();
    for (guest_path, raw) in fs {
        let mount = build_mount(guest_path, raw, base_dir)?;
        merged.insert(guest_path.clone(), mount);
    }

    Ok(Grant {
        limits,
        env: env_vec,
        mounts: merged.into_values().collect(),
    })
}

fn build_mount(guest_path: &str, raw: &RawMount, base_dir: &Path) -> Result<Mount> {
    if !guest_path.starts_with('/') {
        bail!("guest path {:?} must be absolute (start with /)", guest_path);
    }
    if guest_path == "/" {
        bail!("guest path / is not allowed; mount a subdirectory like /data");
    }
    if guest_path.split('/').any(|seg| seg == "..") {
        bail!("guest path {:?} must not contain ..", guest_path);
    }
    if raw.host.is_empty() {
        bail!("guest path {:?}: host must be non-empty", guest_path);
    }
    let mode = match raw.mode.as_str() {
        "ro" => MountMode::ReadOnly,
        "rw" => MountMode::ReadWrite,
        other => bail!(
            "guest path {:?}: mode must be \"ro\" or \"rw\", got {:?}",
            guest_path,
            other
        ),
    };
    let host = Path::new(&raw.host);
    let host_path = if host.is_absolute() {
        host.to_path_buf()
    } else {
        base_dir.join(host)
    };
    Ok(Mount {
        guest_path: guest_path.to_string(),
        host_path,
        mode,
    })
}

fn validate_limits(l: &Limits) -> Result<()> {
    if l.timeout_ms == 0 || l.timeout_ms > MAX_TIMEOUT_MS {
        bail!(
            "timeout_ms must be in 1..={}, got {}",
            MAX_TIMEOUT_MS,
            l.timeout_ms
        );
    }
    if l.fuel < MIN_FUEL {
        bail!("fuel must be at least {}, got {}", MIN_FUEL, l.fuel);
    }
    if l.memory_max_mb == 0 || l.memory_max_mb > MAX_MEMORY_MAX_MB {
        bail!(
            "memory_max_mb must be in 1..={}, got {}",
            MAX_MEMORY_MAX_MB,
            l.memory_max_mb
        );
    }
    if l.output_max_kb == 0 || l.output_max_kb > MAX_OUTPUT_MAX_KB {
        bail!(
            "output_max_kb must be in 1..={}, got {}",
            MAX_OUTPUT_MAX_KB,
            l.output_max_kb
        );
    }
    Ok(())
}

fn validate_env_key(k: &str) -> Result<()> {
    if k.is_empty() {
        bail!("env variable names must be non-empty");
    }
    if k.contains('=') {
        bail!("env variable name {:?} must not contain =", k);
    }
    Ok(())
}
