//! Environment facts recorded alongside benchmark and verification results.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::exec;

/// CPU brand string, best effort, without `unsafe` or extra dependencies:
/// Linux `/proc/cpuinfo`, macOS `sysctl`, Windows registry via `reg query`,
/// falling back to `PROCESSOR_IDENTIFIER`.
pub fn cpu_brand() -> String {
    if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in info.lines() {
            if let Some((k, v)) = line.split_once(':')
                && k.trim() == "model name"
            {
                return v.trim().to_string();
            }
        }
    }
    let cwd = std::env::temp_dir();
    if cfg!(target_os = "macos") {
        let o = exec::run(
            &"sysctl".into(),
            &["-n", "machdep.cpu.brand_string"],
            &cwd,
            &[],
        );
        if o.success() && !o.stdout.trim().is_empty() {
            return o.stdout.trim().to_string();
        }
    }
    if cfg!(windows) {
        let o = exec::run(
            &"reg".into(),
            &[
                "query",
                r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                "/v",
                "ProcessorNameString",
            ],
            &cwd,
            &[],
        );
        if o.success() {
            for line in o.stdout.lines() {
                if let Some((_, v)) = line.split_once("REG_SZ") {
                    let v = v.trim();
                    if !v.is_empty() {
                        return v.to_string();
                    }
                }
            }
        }
    }
    std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "unknown".to_string())
}

/// Number of logical CPUs, if known.
pub fn logical_cpus() -> Option<usize> {
    std::thread::available_parallelism().ok().map(usize::from)
}

/// `rustc -vV` first line (uses `$RUSTC` if set).
pub fn rustc_version() -> String {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let o = exec::run(&rustc, &["-V"], &std::env::temp_dir(), &[]);
    if o.success() {
        o.stdout.trim().to_string()
    } else {
        "unknown".to_string()
    }
}

/// Operating system and architecture of this process.
pub fn os() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Current UTC date-time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

/// Format seconds since the Unix epoch as an ISO-8601 UTC timestamp.
pub fn format_utc(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian `(year, month, day)`
/// (H. Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Versions of `names` recorded in `Cargo.lock` (several if the lock holds
/// several versions of one crate).
pub fn locked_versions(root: &Path, names: &[&str]) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(root.join("Cargo.lock")).unwrap_or_default();
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("name = ") {
            current = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("version = ")
            && let Some(name) = current.take()
            && names.contains(&name.as_str())
        {
            out.push((name, v.trim_matches('"').to_string()));
        }
    }
    out.sort();
    out
}

/// Current git commit of `root`, if it is a git checkout.
pub fn git_commit(root: &Path) -> Option<String> {
    let o = exec::run(&"git".into(), &["rev-parse", "HEAD"], root, &[]);
    o.success().then(|| o.stdout.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(19_723 * 86_400 + 3661), "2024-01-01T01:01:01Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
    }
}
