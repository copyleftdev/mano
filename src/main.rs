mod extract;
mod probe;

use clap::Parser;
use futures::stream::{self, StreamExt};
use probe::ProbeResult;
use reqwest::Client;
use std::io::{self, BufRead, Write as IoWrite};
use std::time::{Duration, Instant};
use tracing::Level;

#[derive(Parser)]
#[command(
    name = "mano",
    about = "The shark — fast HTTP probe and fingerprinter",
    version
)]
struct Cli {
    /// Target URL/host (can specify multiple)
    #[arg(short = 'u', long = "target")]
    targets: Vec<String>,

    /// File containing list of targets
    #[arg(short, long)]
    list: Option<String>,

    /// Number of concurrent probes
    #[arg(short = 'c', long, default_value_t = 50)]
    threads: usize,

    /// Request timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,

    /// Follow redirects
    #[arg(short = 'L', long, default_value_t = false)]
    follow_redirects: bool,

    /// JSON output
    #[arg(long, default_value_t = false)]
    json: bool,

    /// CSV output
    #[arg(long, default_value_t = false)]
    csv: bool,

    /// Output file
    #[arg(short, long)]
    output: Option<String>,

    /// Silent — only URLs, no extras
    #[arg(short, long, default_value_t = false)]
    silent: bool,

    /// Show status code
    #[arg(long = "status-code", short = 's', default_value_t = false)]
    status_code: bool,

    /// Show page title
    #[arg(long = "title", default_value_t = false)]
    title: bool,

    /// Show server header
    #[arg(long = "server", default_value_t = false)]
    show_server: bool,

    /// Show content length
    #[arg(long = "content-length", default_value_t = false)]
    content_length: bool,

    /// Show technologies
    #[arg(long = "tech-detect", default_value_t = false)]
    tech_detect: bool,

    /// Show response time
    #[arg(long = "response-time", default_value_t = false)]
    response_time: bool,

    /// Compute body hashes (md5, sha256)
    #[arg(long = "hash", default_value_t = false)]
    hash: bool,

    /// Grab TLS certificate info
    #[arg(long = "tls-grab", default_value_t = false)]
    tls_grab: bool,

    /// Show line count
    #[arg(long = "line-count", default_value_t = false)]
    line_count: bool,

    /// Show word count
    #[arg(long = "word-count", default_value_t = false)]
    word_count: bool,

    /// Match status codes (comma-separated)
    #[arg(long = "mc")]
    match_codes: Option<String>,

    /// Filter status codes (comma-separated)
    #[arg(long = "fc")]
    filter_codes: Option<String>,

    /// Show all fields (shorthand for all display flags)
    #[arg(short = 'a', long = "all", default_value_t = false)]
    all_fields: bool,

    /// Verbose logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Don't read from stdin
    #[arg(long = "no-stdin", default_value_t = false)]
    no_stdin: bool,
}

fn parse_code_list(s: &str) -> Vec<u16> {
    s.split(',')
        .filter_map(|c| c.trim().parse::<u16>().ok())
        .collect()
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

    let level = if cli.verbose { Level::DEBUG } else { Level::WARN };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_writer(io::stderr)
        .init();

    if !cli.silent && !cli.json && !cli.csv {
        eprintln!(
            r#"
  _ __ ___   __ _ _ __   ___
 | '_ ` _ \ / _` | '_ \ / _ \
 | | | | | | (_| | | | | (_) |
 |_| |_| |_|\__,_|_| |_|\___/
  the shark — fast HTTP probe
"#
        );
    }

    // Build HTTP client — shared across all probes
    let client = Client::builder()
        .local_address(Some(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(cli.timeout))
        .timeout(Duration::from_secs(cli.timeout))
        .danger_accept_invalid_certs(true)
        .redirect(if cli.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .expect("failed to build HTTP client");

    // Collect targets from all sources
    let mut targets: Vec<String> = Vec::new();

    for t in &cli.targets {
        targets.push(t.clone());
    }

    if let Some(ref path) = cli.list {
        if let Ok(file) = std::fs::File::open(path) {
            for line in io::BufReader::new(file).lines().map_while(Result::ok) {
                let line = line.trim().to_string();
                if !line.is_empty() {
                    targets.push(line);
                }
            }
        }
    }

    // Read from stdin if no other input and not disabled
    if targets.is_empty() && !cli.no_stdin {
        let stdin = io::stdin();
        for line in stdin.lock().lines().map_while(Result::ok) {
            let line = line.trim().to_string();
            if !line.is_empty() {
                targets.push(line);
            }
        }
    }

    if targets.is_empty() {
        eprintln!("[!] No targets provided. Use -u, -l, or pipe via stdin.");
        std::process::exit(1);
    }

    // Parse filters
    let match_codes: Option<Vec<u16>> = cli.match_codes.as_deref().map(parse_code_list);
    let filter_codes: Option<Vec<u16>> = cli.filter_codes.as_deref().map(parse_code_list);

    // Shorthand: -a enables all display fields
    let show_status = cli.status_code || cli.all_fields;
    let show_title = cli.title || cli.all_fields;
    let show_server = cli.show_server || cli.all_fields;
    let show_cl = cli.content_length || cli.all_fields;
    let show_tech = cli.tech_detect || cli.all_fields;
    let show_rt = cli.response_time || cli.all_fields;
    let show_lines = cli.line_count || cli.all_fields;
    let show_words = cli.word_count || cli.all_fields;
    let do_hash = cli.hash || cli.all_fields;
    let do_tls = cli.tls_grab || cli.all_fields;

    let start = Instant::now();
    let total = targets.len();

    if !cli.silent && !cli.json && !cli.csv {
        eprintln!("[*] Probing {total} targets with {} threads", cli.threads);
    }

    // Concurrent probing via stream::buffer_unordered
    let results: Vec<ProbeResult> = stream::iter(targets)
        .map(|target| {
            let client = client.clone();
            async move {
                let mut result = probe::probe(
                    &client,
                    &target,
                    cli.follow_redirects,
                    do_hash,
                    do_tls,
                ).await;

                // TLS grab if requested and HTTPS
                if do_tls && result.scheme == "https" && !result.failed {
                    if let Some(tls_info) = extract::tls::grab_tls(&result.host, result.port).await {
                        result.tls_subject_cn = tls_info.subject_cn;
                        result.tls_subject_an = tls_info.subject_an;
                        result.tls_issuer = tls_info.issuer;
                    }
                }

                result
            }
        })
        .buffer_unordered(cli.threads)
        .collect()
        .await;

    // Setup output writer
    let mut writer: Box<dyn IoWrite> = if let Some(ref path) = cli.output {
        Box::new(io::BufWriter::new(
            std::fs::File::create(path).expect("failed to create output file"),
        ))
    } else {
        Box::new(io::BufWriter::new(io::stdout().lock()))
    };

    // Output results
    let mut alive_count = 0u32;

    for r in &results {
        if r.failed {
            continue;
        }

        // Apply status code filters
        if let Some(ref mc) = match_codes {
            if !mc.contains(&r.status_code) {
                continue;
            }
        }
        if let Some(ref fc) = filter_codes {
            if fc.contains(&r.status_code) {
                continue;
            }
        }

        alive_count += 1;

        if cli.json {
            let _ = serde_json::to_writer(&mut *writer, r);
            let _ = writer.write_all(b"\n");
            continue;
        }

        // Plain text output
        let mut parts: Vec<String> = vec![r.url.clone()];

        if show_status {
            parts.push(format!("[{}]", r.status_code));
        }
        if show_cl {
            parts.push(format!("[{}]", r.content_length));
        }
        if show_title && !r.title.is_empty() {
            parts.push(format!("[{}]", r.title));
        }
        if show_server && !r.server.is_empty() {
            parts.push(format!("[{}]", r.server));
        }
        if show_tech && !r.technologies.is_empty() {
            parts.push(format!("[{}]", r.technologies.join(",")));
        }
        if show_rt {
            parts.push(format!("[{}ms]", r.response_time_ms));
        }
        if show_lines {
            parts.push(format!("[lines:{}]", r.lines));
        }
        if show_words {
            parts.push(format!("[words:{}]", r.words));
        }
        if do_hash && !r.body_hash_md5.is_empty() {
            parts.push(format!("[md5:{}]", r.body_hash_md5));
        }
        if do_tls && !r.tls_subject_cn.is_empty() {
            parts.push(format!("[cn:{}]", r.tls_subject_cn.join(",")));
        }
        if do_tls && !r.tls_subject_an.is_empty() {
            parts.push(format!("[san:{}]", r.tls_subject_an.len()));
        }

        let _ = writeln!(writer, "{}", parts.join(" "));
    }

    let _ = writer.flush();
    let elapsed = start.elapsed();

    if !cli.silent && !cli.json && !cli.csv {
        eprintln!(
            "\n[*] {alive_count}/{total} alive in {:.2}s",
            elapsed.as_secs_f64()
        );
    }
}
