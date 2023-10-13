use crate::sigscan::find_pattern;
use anyhow::Context;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> anyhow::Result<()> {
    let chrome_libs = find_chrome_dlls().context("Could not find chrome lib files")?;
    println!(
        "Patching chrome.dll from following path(s):\n{}",
        chrome_libs
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join("\n")
    );

    for chrome_lib in chrome_libs {
        patch_chrome_lib(&chrome_lib).expect("essa");
    }

    Ok(())
}

fn find_chrome_dlls() -> anyhow::Result<Vec<PathBuf>> {
    const CHROME_PATH: &str = r#"./chrome"#;

    let paths = fs::read_dir(CHROME_PATH)
        .with_context(|| format!("Could not read chrome directory: {CHROME_PATH}"))?
        .filter_map(Result::ok)
        .filter(|file| file.file_type().is_ok_and(|file_type| file_type.is_dir()))
        .map(|dir| dir.path().join("chrome.dll"))
        .filter(|chrome_dll| chrome_dll.exists())
        .collect();
    Ok(paths)
}

fn patch_chrome_lib(path: &Path) -> anyhow::Result<()> {
    let backup_path = {
        let mut buf = path.to_path_buf();
        buf.pop();
        buf.join("chrome.dll.bak")
    };
    let mut chrome_bin = fs::read(path).context("Could not read chrome lib")?;

    let pattern_found = find_pattern(
        &chrome_bin,
        "53 48 83 EC ? 48 8B ? ? ? ? ? 48 ? ? 48 ? ? ? 28 B3 01 80 3D ? ? ? ? 00 74 ? 48 8b ? ? ?",
    )
    .context("Could not find Navigator@webdriver function pattern")?;
    println!("pattern found: {pattern_found}");
    let patch_data = [
        0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x00
        0xc3, // ret
    ];
    chrome_bin.splice(
        pattern_found..(pattern_found + patch_data.len()),
        patch_data,
    );
    fs::rename(path, &backup_path).context("Could not create backup file!")?;
    fs::write(path, chrome_bin).context("Could not write patched chrome")?;
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
