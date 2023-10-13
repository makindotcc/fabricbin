use crate::sigscan::find_pattern;
use anyhow::Context;
use serde::{Deserialize, Deserializer, Serialize};
use std::fs;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let config: Config = {
        let config_bytes = fs::read("config.yaml").context("Could not read config file")?;
        serde_yaml::from_slice(&config_bytes).context("Could not parse config file")?
    };
    println!("Config: {config:?}");
    apply_patches(&Path::new(&config.file), config.patches)
        .context("Could not apply patch to file")?;
    println!("Patched file successfully.");
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    file: String,
    #[serde(rename = "patch")]
    patches: Vec<PatchConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PatchConfig {
    name: Option<String>,
    sig: String,
    #[serde(deserialize_with = "deserialize_bytes")]
    with: Vec<u8>,
    with_offset: Option<isize>,
}

fn deserialize_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
{
    let lines: Vec<String> = Deserialize::deserialize(deserializer)?;
    lines
        .join(" ")
        .split(" ")
        .map(|byte| u8::from_str_radix(byte, 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(serde::de::Error::custom)
}

fn apply_patches(path: &Path, patches: Vec<PatchConfig>) -> anyhow::Result<()> {
    let backup_path = {
        let mut buf = path.to_path_buf();
        buf.pop();
        buf.join("chrome.dll.bak")
    };
    let mut chrome_bin = fs::read(path).context("Could not read chrome lib")?;
    for patch in patches {
        let patch_name = patch.name.as_deref().unwrap_or_else(|| &patch.sig);
        println!("Patching signature: {}", patch_name);
        apply_patch(
            &mut chrome_bin,
            &patch.sig,
            patch.with,
            patch.with_offset.unwrap_or(0),
        )
        .with_context(|| format!("Could not apply patch {}", patch_name))?;
    }
    fs::rename(path, &backup_path).context("Could not create backup file!")?;
    fs::write(path, chrome_bin).context("Could not write patched chrome")?;
    Ok(())
}

fn apply_patch(
    target: &mut Vec<u8>,
    sig: &str,
    with: Vec<u8>,
    with_offset: isize,
) -> anyhow::Result<()> {
    let pattern_offset = find_pattern(&target, &sig).context("Could not find pattern")?;
    println!("  Pattern found at {pattern_offset:x}");
    let patch_offset = pattern_offset
        .checked_add_signed(with_offset)
        .context("Patch offset overflowed")?;
    target.splice(patch_offset..(patch_offset + with.len()), with);
    Ok(())
}

/// Proudly borrowed from:
/// https://github.com/frk1/hazedumper-rs/blob/master/src/memlib/findpattern.rs
mod sigscan {
    use regex::bytes::Regex;

    /// Enables the user to generate a byte regex out of the normal signature
    /// format.
    fn generate_regex(raw: &str) -> Option<Regex> {
        let mut res = raw
            .to_string()
            .split_whitespace()
            .map(|x| match &x {
                &"?" => ".".to_string(),
                x => format!("\\x{}", x),
            })
            .collect::<Vec<_>>()
            .join("");
        res.insert_str(0, "(?s-u)");
        Regex::new(&res).ok()
    }

    /// Find pattern.
    pub fn find_pattern(data: &[u8], pattern: &str) -> Option<usize> {
        generate_regex(pattern)
            .and_then(|r| r.find(data))
            .and_then(|m| Some(m.start()))
    }
}
