// ═══════════════════════════════════════════════════════════════
//  VERTEX-SYS — Rust System-Level Deep Inspector
//  ELF binary scanning, entropy analysis, /proc deep dive,
//  anomaly detection, file integrity, hidden process detection
// ═══════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, BufRead};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const RED: &str = "\x1b[0;31m";
const GREEN: &str = "\x1b[0;32m";
const YELLOW: &str = "\x1b[1;33m";
const CYAN: &str = "\x1b[0;36m";
const PURPLE: &str = "\x1b[0;35m";
const BOLD: &str = "\x1b[1m";
const RST: &str = "\x1b[0m";

// ─── Entropy calculator (Shannon entropy) ────────────────────

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn entropy_verdict(entropy: f64) -> (&'static str, &'static str) {
    if entropy > 7.5 {
        (RED, "PACKED/ENCRYPTED — likely obfuscated malware")
    } else if entropy > 6.5 {
        (YELLOW, "HIGH — compressed or encoded sections")
    } else if entropy > 4.0 {
        (GREEN, "NORMAL — typical compiled binary")
    } else {
        (CYAN, "LOW — mostly text/data")
    }
}

// ─── ELF parser (minimal, no deps) ───────────────────────────

#[derive(Debug)]
struct ElfInfo {
    path: String,
    class: String,       // ELF32 or ELF64
    endian: String,
    elf_type: String,
    machine: String,
    entry_point: u64,
    entropy: f64,
    size: u64,
    suspicious: Vec<String>,
}

fn parse_elf(path: &Path) -> Option<ElfInfo> {
    let data = fs::read(path).ok()?;
    if data.len() < 64 || data[0..4] != ELF_MAGIC {
        return None;
    }

    let class = match data[4] {
        1 => "ELF32",
        2 => "ELF64",
        _ => "unknown",
    };

    let endian = match data[5] {
        1 => "little-endian",
        2 => "big-endian",
        _ => "unknown",
    };

    let is_le = data[5] == 1;

    let elf_type = if is_le {
        u16::from_le_bytes([data[16], data[17]])
    } else {
        u16::from_be_bytes([data[16], data[17]])
    };

    let elf_type_str = match elf_type {
        0 => "NONE",
        1 => "REL (relocatable)",
        2 => "EXEC (executable)",
        3 => "DYN (shared/PIE)",
        4 => "CORE",
        _ => "unknown",
    };

    let machine = if is_le {
        u16::from_le_bytes([data[18], data[19]])
    } else {
        u16::from_be_bytes([data[18], data[19]])
    };

    let machine_str = match machine {
        3 => "x86",
        40 => "ARM",
        62 => "x86_64",
        183 => "AArch64",
        _ => "other",
    };

    let entry_point = if class == "ELF64" && data.len() >= 32 {
        if is_le {
            u64::from_le_bytes([
                data[24], data[25], data[26], data[27],
                data[28], data[29], data[30], data[31],
            ])
        } else {
            u64::from_be_bytes([
                data[24], data[25], data[26], data[27],
                data[28], data[29], data[30], data[31],
            ])
        }
    } else if data.len() >= 28 {
        if is_le {
            u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as u64
        } else {
            u32::from_be_bytes([data[24], data[25], data[26], data[27]]) as u64
        }
    } else {
        0
    };

    let entropy = shannon_entropy(&data);
    let mut suspicious = Vec::new();

    // Check for suspicious strings
    let text = extract_printable(&data);
    let sus_patterns = [
        "/bin/sh", "/bin/bash", "socket", "connect", "exec",
        "passwd", "shadow", "/etc/crontab", "base64",
        "eval(", "system(", "popen", "dlopen", "ptrace",
        "LD_PRELOAD", "ld.so.preload",
    ];
    for pattern in &sus_patterns {
        if text.contains(pattern) {
            suspicious.push(format!("contains '{}'", pattern));
        }
    }

    if entropy > 7.5 {
        suspicious.push("extremely high entropy (packed/encrypted)".into());
    }
    if entry_point == 0 && elf_type == 2 {
        suspicious.push("zero entry point on executable".into());
    }

    let size = data.len() as u64;

    Some(ElfInfo {
        path: path.to_string_lossy().to_string(),
        class: class.to_string(),
        endian: endian.to_string(),
        elf_type: elf_type_str.to_string(),
        machine: machine_str.to_string(),
        entry_point,
        entropy,
        size,
        suspicious,
    })
}

fn extract_printable(data: &[u8]) -> String {
    let mut result = String::new();
    let mut current = String::new();
    for &byte in data {
        if byte >= 0x20 && byte < 0x7f {
            current.push(byte as char);
        } else {
            if current.len() >= 4 {
                result.push_str(&current);
                result.push(' ');
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        result.push_str(&current);
    }
    result
}

// ─── Directory scanner for ELF binaries ──────────────────────

fn scan_directory_for_elfs(dir: &str, max_depth: usize) -> Vec<ElfInfo> {
    let mut results = Vec::new();
    scan_dir_recursive(Path::new(dir), 0, max_depth, &mut results);
    results
}

fn scan_dir_recursive(dir: &Path, depth: usize, max_depth: usize, results: &mut Vec<ElfInfo>) {
    if depth > max_depth {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            // Skip noise directories
            if name.starts_with('.') || name == "node_modules" || name == "proc" || name == "sys" {
                continue;
            }
            scan_dir_recursive(&path, depth + 1, max_depth, results);
        } else if path.is_file() {
            // Quick check: read first 4 bytes
            if let Ok(mut f) = fs::File::open(&path) {
                let mut magic = [0u8; 4];
                if f.read_exact(&mut magic).is_ok() && magic == ELF_MAGIC {
                    if let Some(info) = parse_elf(&path) {
                        results.push(info);
                    }
                }
            }
        }
    }
}

// ─── File entropy scanner ────────────────────────────────────

fn scan_file_entropy(path: &str) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  {}[!]{} Cannot read {}: {}", RED, RST, path, e);
            return;
        }
    };

    let total_entropy = shannon_entropy(&data);
    let (color, verdict) = entropy_verdict(total_entropy);

    println!("\n{}══ ENTROPY ANALYSIS: {} ══{}", CYAN, path, RST);
    println!("  File size: {} bytes", data.len());
    println!("  Overall entropy: {}{:.4}{} bits/byte — {}{}{}",
             color, total_entropy, RST, color, verdict, RST);

    // Block-by-block entropy (4KB blocks)
    let block_size = 4096;
    let blocks: Vec<f64> = data.chunks(block_size)
        .map(|chunk| shannon_entropy(chunk))
        .collect();

    if blocks.len() > 1 {
        let avg: f64 = blocks.iter().sum::<f64>() / blocks.len() as f64;
        let max = blocks.iter().cloned().fold(f64::MIN, f64::max);
        let min = blocks.iter().cloned().fold(f64::MAX, f64::min);
        let variance: f64 = blocks.iter().map(|e| (e - avg).powi(2)).sum::<f64>() / blocks.len() as f64;

        println!("\n  {}Block analysis ({} x {} byte blocks):{}", BOLD, blocks.len(), block_size, RST);
        println!("    Average: {:.4}", avg);
        println!("    Min:     {:.4}", min);
        println!("    Max:     {:.4}", max);
        println!("    StdDev:  {:.4}", variance.sqrt());

        // Find high-entropy blocks (potential encrypted/packed sections)
        let high_blocks: Vec<(usize, f64)> = blocks.iter().enumerate()
            .filter(|(_, e)| **e > 7.5)
            .map(|(i, e)| (i, *e))
            .collect();

        if !high_blocks.is_empty() {
            println!("\n  {}[!] High-entropy blocks (>7.5 — possible encryption):{}", YELLOW, RST);
            for (idx, ent) in &high_blocks {
                let offset = idx * block_size;
                println!("    Block {} (offset 0x{:X}): {:.4}", idx, offset, ent);
            }
        }
    }

    // Byte frequency histogram (top and bottom)
    let mut freq = [0u64; 256];
    for &byte in &data {
        freq[byte as usize] += 1;
    }
    let mut sorted_freq: Vec<(u8, u64)> = freq.iter().enumerate()
        .map(|(i, &c)| (i as u8, c))
        .filter(|(_, c)| *c > 0)
        .collect();
    sorted_freq.sort_by(|a, b| b.1.cmp(&a.1));

    println!("\n  {}Byte distribution (top 10):{}", BOLD, RST);
    for &(byte, count) in sorted_freq.iter().take(10) {
        let pct = (count as f64 / data.len() as f64) * 100.0;
        let repr = if byte >= 0x20 && byte < 0x7f {
            format!("'{}' (0x{:02X})", byte as char, byte)
        } else {
            format!("    (0x{:02X})", byte)
        };
        println!("    {}: {} ({:.1}%)", repr, count, pct);
    }

    // Null byte ratio (indicator of binary vs text)
    let null_count = freq[0];
    let null_pct = (null_count as f64 / data.len() as f64) * 100.0;
    if null_pct > 30.0 {
        println!("\n  {}[!] {:.1}% null bytes — typical binary/padded file{}", YELLOW, null_pct, RST);
    }
}

// ─── Hidden process detection ────────────────────────────────

fn detect_hidden_processes() {
    println!("\n{}══ HIDDEN PROCESS DETECTION ══{}", CYAN, RST);

    let proc_pids: Vec<u32> = fs::read_dir("/proc")
        .unwrap_or_else(|_| panic!("Cannot read /proc"))
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect();

    let mut hidden = Vec::new();
    let mut suspicious_procs = Vec::new();

    for &pid in &proc_pids {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let status_path = format!("/proc/{}/status", pid);

        let cmdline = fs::read_to_string(&cmdline_path)
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        let status = fs::read_to_string(&status_path).unwrap_or_default();
        let name = status.lines()
            .find(|l| l.starts_with("Name:"))
            .map(|l| l.split_whitespace().nth(1).unwrap_or(""))
            .unwrap_or("")
            .to_string();

        let uid_line = status.lines()
            .find(|l| l.starts_with("Uid:"))
            .unwrap_or("");
        let uid: u32 = uid_line.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Check for processes with deleted exe links (classic malware)
        let exe_path = format!("/proc/{}/exe", pid);
        let exe_link = fs::read_link(&exe_path).unwrap_or_default();
        let exe_str = exe_link.to_string_lossy().to_string();

        if exe_str.contains("(deleted)") {
            suspicious_procs.push(format!(
                "PID {} ({}) — exe link points to DELETED binary: {}",
                pid, name, exe_str
            ));
        }

        // Check for processes running from /tmp or /dev/shm
        if exe_str.starts_with("/tmp") || exe_str.starts_with("/dev/shm") || exe_str.starts_with("/var/tmp") {
            suspicious_procs.push(format!(
                "PID {} ({}) — running from suspicious path: {}",
                pid, name, exe_str
            ));
        }

        // Empty cmdline on non-kernel thread (UID != 0 or name doesn't start with bracket)
        if cmdline.is_empty() && !name.starts_with('[') && uid != 0 {
            hidden.push(format!("PID {} — empty cmdline, name: {}, uid: {}", pid, name, uid));
        }
    }

    println!("\n  {}Total /proc PIDs:{} {}", BOLD, RST, proc_pids.len());

    if hidden.is_empty() {
        println!("  {}[✓] No hidden userspace processes{}", GREEN, RST);
    } else {
        println!("  {}[!] Potentially hidden processes:{}", RED, RST);
        for h in &hidden {
            println!("    {}", h);
        }
    }

    if suspicious_procs.is_empty() {
        println!("  {}[✓] No suspicious process characteristics{}", GREEN, RST);
    } else {
        println!("  {}[!] Suspicious processes:{}", RED, RST);
        for s in &suspicious_procs {
            println!("    {}", s);
        }
    }
}

// ─── File system anomaly scanner ─────────────────────────────

fn scan_filesystem_anomalies(dir: &str) {
    println!("\n{}══ FILESYSTEM ANOMALY SCAN: {} ══{}", CYAN, dir, RST);

    let mut hidden_execs = Vec::new();
    let mut recent_mods = Vec::new();
    let mut large_files = Vec::new();
    let now = SystemTime::now();

    scan_anomalies_recursive(Path::new(dir), 0, 3, &mut hidden_execs, &mut recent_mods, &mut large_files, now);

    println!("\n  {}Hidden executables (dotfiles with exec):{}", BOLD, RST);
    if hidden_execs.is_empty() {
        println!("  {}[✓] None found{}", GREEN, RST);
    } else {
        for f in &hidden_execs {
            println!("  {}[!]{} {}", RED, RST, f);
        }
    }

    println!("\n  {}Recently modified files (24h):{}", BOLD, RST);
    if recent_mods.is_empty() {
        println!("  {}[✓] None{}", GREEN, RST);
    } else {
        for f in recent_mods.iter().take(20) {
            println!("    {}", f);
        }
    }
}

fn scan_anomalies_recursive(
    dir: &Path, depth: usize, max_depth: usize,
    hidden_execs: &mut Vec<String>,
    recent_mods: &mut Vec<String>,
    _large_files: &mut Vec<String>,
    now: SystemTime,
) {
    if depth > max_depth {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if path.is_dir() && !path.is_symlink() {
            if name != "proc" && name != "sys" && name != "dev" {
                scan_anomalies_recursive(&path, depth + 1, max_depth,
                    hidden_execs, recent_mods, _large_files, now);
            }
            continue;
        }

        if !path.is_file() {
            continue;
        }

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Hidden executable
        if name.starts_with('.') {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if mode & 0o111 != 0 {
                    hidden_execs.push(format!("{} (mode: {:o}, size: {})",
                        path.display(), mode, meta.len()));
                }
            }
        }

        // Recently modified
        if let Ok(modified) = meta.modified() {
            if let Ok(duration) = now.duration_since(modified) {
                if duration.as_secs() < 86400 {
                    recent_mods.push(format!("{} ({} ago, {} bytes)",
                        path.display(),
                        humanize_duration(duration.as_secs()),
                        meta.len()));
                }
            }
        }
    }
}

fn humanize_duration(secs: u64) -> String {
    if secs < 60 { return format!("{}s", secs); }
    if secs < 3600 { return format!("{}m", secs / 60); }
    format!("{}h", secs / 3600)
}

// ─── String extraction (like `strings` command) ──────────────

fn extract_strings(path: &str, min_len: usize) {
    println!("\n{}══ STRING EXTRACTION: {} ══{}", CYAN, path, RST);

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  {}[!]{} Cannot read: {}", RED, RST, e);
            return;
        }
    };

    let sus_keywords = [
        "password", "passwd", "shadow", "token", "secret", "api_key",
        "authorization", "cookie", "session", "credential", "private_key",
        "/bin/sh", "/bin/bash", "wget ", "curl ", "nc ", "ncat",
        "base64", "eval(", "exec(", "system(", "popen",
        "reverse", "shell", "bind", "payload", "exploit",
        "C2", "beacon", "callback", "exfil", "dropper",
        "LD_PRELOAD", "ptrace", "dlopen", "mprotect",
    ];

    let mut found_strings = Vec::new();
    let mut current = String::new();
    let mut offset = 0usize;

    for (i, &byte) in data.iter().enumerate() {
        if byte >= 0x20 && byte < 0x7f {
            if current.is_empty() {
                offset = i;
            }
            current.push(byte as char);
        } else {
            if current.len() >= min_len {
                let lower = current.to_lowercase();
                let is_sus = sus_keywords.iter().any(|k| lower.contains(k));
                found_strings.push((offset, current.clone(), is_sus));
            }
            current.clear();
        }
    }

    let total = found_strings.len();
    let sus_count = found_strings.iter().filter(|(_, _, s)| *s).count();

    println!("  Total strings (>={} chars): {}", min_len, total);
    println!("  Suspicious matches: {}{}{}", if sus_count > 0 { RED } else { GREEN }, sus_count, RST);

    if sus_count > 0 {
        println!("\n  {}Suspicious strings:{}", BOLD, RST);
        for (off, s, is_sus) in &found_strings {
            if *is_sus {
                let display = if s.len() > 100 { &s[..100] } else { s.as_str() };
                println!("  {}[0x{:08X}]{} {}", YELLOW, off, RST, display);
            }
        }
    }
}

// ─── Main ────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("
{}VERTEX-SYS{} — Rust System-Level Deep Inspector

Usage:
  vertex-sys entropy <file>       Shannon entropy + block analysis
  vertex-sys elf-scan <dir>       Scan directory for ELF binaries
  vertex-sys strings <file>       Extract & flag suspicious strings
  vertex-sys proc                 Hidden process detection
  vertex-sys anomaly <dir>        Filesystem anomaly scan
  vertex-sys full                 Run all system checks

", PURPLE, RST);
        return;
    }

    match args[1].as_str() {
        "entropy" => {
            if args.len() < 3 {
                eprintln!("Usage: vertex-sys entropy <file>");
                return;
            }
            scan_file_entropy(&args[2]);
        }

        "elf-scan" => {
            let dir = if args.len() >= 3 { &args[2] } else { "/data/data/com.termux" };
            println!("\n{}══ ELF BINARY SCAN: {} ══{}", CYAN, dir, RST);

            let results = scan_directory_for_elfs(dir, 4);
            println!("  Found {} ELF binaries\n", results.len());

            let mut sus_count = 0;
            for info in &results {
                let (ent_color, _) = entropy_verdict(info.entropy);

                if !info.suspicious.is_empty() {
                    sus_count += 1;
                    println!("  {}[!]{} {}", RED, RST, info.path);
                    println!("      {} {} {} entry:0x{:X} entropy:{}{:.4}{}",
                             info.class, info.machine, info.elf_type,
                             info.entry_point, ent_color, info.entropy, RST);
                    for s in &info.suspicious {
                        println!("      {}→ {}{}", YELLOW, s, RST);
                    }
                    println!();
                }
            }

            if sus_count == 0 {
                println!("  {}[✓] No suspicious ELF binaries detected{}", GREEN, RST);
            } else {
                println!("  {}[!] {} suspicious binaries found{}", RED, sus_count, RST);
            }

            // Summary by architecture
            let mut arch_counts: HashMap<String, usize> = HashMap::new();
            for info in &results {
                *arch_counts.entry(info.machine.clone()).or_insert(0) += 1;
            }
            println!("\n  {}Architecture breakdown:{}", BOLD, RST);
            for (arch, count) in &arch_counts {
                println!("    {}: {}", arch, count);
            }
        }

        "strings" => {
            if args.len() < 3 {
                eprintln!("Usage: vertex-sys strings <file>");
                return;
            }
            let min_len = if args.len() >= 4 {
                args[3].parse().unwrap_or(6)
            } else {
                6
            };
            extract_strings(&args[2], min_len);
        }

        "proc" => {
            detect_hidden_processes();
        }

        "anomaly" => {
            let dir = if args.len() >= 3 { &args[2] } else { "/" };
            scan_filesystem_anomalies(dir);
        }

        "full" => {
            detect_hidden_processes();
            scan_filesystem_anomalies("/data/data/com.termux");
            scan_filesystem_anomalies("/sdcard");

            println!("\n{}══ ELF SCAN: Termux binaries ══{}", CYAN, RST);
            let results = scan_directory_for_elfs("/data/data/com.termux/files/usr/bin", 2);
            let sus: Vec<&ElfInfo> = results.iter().filter(|e| !e.suspicious.is_empty()).collect();
            println!("  {} binaries scanned, {} suspicious", results.len(), sus.len());
            for info in &sus {
                println!("  {}[!]{} {} — {:?}", RED, RST, info.path, info.suspicious);
            }
        }

        _ => {
            eprintln!("Unknown command: {}", args[1]);
        }
    }

    println!();
}
