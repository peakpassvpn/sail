use std::process::exit;

use argh::FromArgs;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
const COMMIT_HASH: Option<&'static str> = option_env!("CFG_COMMIT_HASH");
const COMMIT_DATE: Option<&'static str> = option_env!("CFG_COMMIT_DATE");

fn get_version_string() -> String {
    match (VERSION, COMMIT_HASH, COMMIT_DATE) {
        (Some(ver), None, None) => ver.to_string(),
        (Some(ver), Some(hash), Some(date)) => {
            format!("{} ({} - {})", ver, hash, date)
        }
        _ => "unknown".to_string(),
    }
}

#[cfg(debug_assertions)]
fn default_thread_stack_size() -> usize {
    2 * 1024 * 1024
}

#[cfg(not(debug_assertions))]
fn default_thread_stack_size() -> usize {
    256 * 1024
}

/// The dashboard downloaded by default: Mihomo's, metacubexd.
const DEFAULT_UI: &str = "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip";

#[derive(FromArgs)]
/// A lightweight and fast proxy utility
struct Args {
    /// the configuration file
    #[argh(option, short = 'c', default = "String::from(\"config.json\")")]
    config: String,

    /// enables auto reloading when config file changes
    #[argh(switch)]
    auto_reload: bool,

    /// runs in a single thread
    #[argh(switch)]
    single_thread: bool,

    /// sets the stack size of runtime worker threads
    #[argh(option, default = "default_thread_stack_size()")]
    thread_stack_size: usize,

    /// tests the configuration and exit
    #[argh(switch, short = 'T')]
    test: bool,

    /// tests the connectivity of the specified outbound
    #[argh(option, short = 't')]
    test_outbound: Option<String>,

    /// timeout for outbound connectivity tests, in seconds
    #[argh(option, short = 'd', default = "4")]
    test_outbound_timeout: u64,

    /// tuning preset: mobile, desktop (default), server or router
    #[argh(option)]
    profile: Option<String>,

    /// overrides one tuning value, e.g. --set relay.buffer_size=32; repeatable
    #[argh(option)]
    set: Vec<String>,

    /// the directory for data files (geo.mmdb, site.dat) and relative
    /// certificate paths; defaults to the executable's directory
    #[argh(option, short = 'D')]
    data_dir: Option<String>,

    /// holds the cache file (selections, fake IPs) by default, and remote rule-sets
    #[argh(option)]
    cache_dir: Option<String>,

    /// the base URL of your own Sub-Store backend (secret path included),
    /// which sub.store, Sub-Store's address inside Surge, Loon and
    /// Quantumult X, stands for in subscription and rule-set URLs
    #[argh(option)]
    sub_store: Option<String>,

    /// the dashboard the Clash API downloads, a ZIP, into an empty
    /// external_ui when the configuration names none; empty for none
    #[argh(option, default = "String::from(DEFAULT_UI)")]
    ui_download_url: String,

    /// downloads the URLs a Surge profile includes (#!include https://...),
    /// and those they include, into the cache directory before it is read;
    /// a download that fails leaves the copy there is
    #[argh(switch)]
    fetch_includes: bool,

    /// prints version
    #[argh(switch, short = 'V')]
    version: bool,

    #[argh(subcommand)]
    command: Option<Command>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Import(Import),
    Generate(Generate),
}

#[derive(FromArgs)]
/// Generates keys and passwords for configurations
#[argh(subcommand, name = "generate")]
struct Generate {
    #[argh(subcommand)]
    kind: GenerateKind,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum GenerateKind {
    Rand(GenerateRand),
    Uuid(GenerateUuid),
    RealityKeypair(GenerateRealityKeypair),
    WgKeypair(GenerateWgKeypair),
    Ss2022(GenerateSs2022),
    Secret(GenerateSecret),
}

#[derive(FromArgs)]
/// Random bytes: raw, or with --base64 or --hex written so
#[argh(subcommand, name = "rand")]
struct GenerateRand {
    /// how many bytes
    #[argh(positional)]
    length: usize,
    /// as base64
    #[argh(switch)]
    base64: bool,
    /// as hex
    #[argh(switch)]
    hex: bool,
}

#[derive(FromArgs)]
/// A random UUID, as VLESS, VMess and TUIC users take
#[argh(subcommand, name = "uuid")]
struct GenerateUuid {}

#[derive(FromArgs)]
/// A REALITY key pair: the server's private key, the clients' public key
#[argh(subcommand, name = "reality-keypair")]
struct GenerateRealityKeypair {}

#[derive(FromArgs)]
/// A WireGuard key pair
#[argh(subcommand, name = "wg-keypair")]
struct GenerateWgKeypair {}

#[derive(FromArgs)]
/// A key for a Shadowsocks 2022 method, of the length it takes
#[argh(subcommand, name = "ss2022")]
struct GenerateSs2022 {
    /// 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm or
    /// 2022-blake3-chacha20-poly1305
    #[argh(positional)]
    method: String,
}

#[derive(FromArgs)]
/// A secret for the Clash API (clash_api.secret)
#[argh(subcommand, name = "secret")]
struct GenerateSecret {}

/// Prints what `generate` asks for, and exits.
fn generate(generate: Generate) -> ! {
    use sail::generate as g;
    match generate.kind {
        GenerateKind::Rand(r) => {
            let bytes = g::random(r.length);
            match (r.base64, r.hex) {
                (true, true) => {
                    eprintln!("--base64 or --hex, not both");
                    exit(1);
                }
                (true, false) => println!("{}", g::base64(&bytes, g::Alphabet::Standard)),
                (false, true) => println!("{}", g::hex(&bytes)),
                (false, false) => {
                    use std::io::Write;
                    let _ = std::io::stdout().write_all(&bytes);
                }
            }
        }
        GenerateKind::Uuid(_) => println!("{}", g::uuid()),
        GenerateKind::RealityKeypair(_) => {
            let (private, public) = g::reality_keypair();
            println!("PrivateKey: {}\nPublicKey: {}", private, public);
        }
        GenerateKind::WgKeypair(_) => {
            let (private, public) = g::wireguard_keypair();
            println!("PrivateKey: {}\nPublicKey: {}", private, public);
        }
        GenerateKind::Ss2022(s) => match g::ss2022_key(&s.method) {
            Ok(key) => println!("{}", key),
            Err(e) => {
                eprintln!("{}", e);
                exit(1);
            }
        },
        GenerateKind::Secret(_) => println!("{}", g::secret()),
    }
    exit(0);
}

#[derive(FromArgs)]
/// Reads share links (ss://, trojan://, vless://, vmess://, hy2://, tuic://,
/// anytls://) into sing-box outbounds, printed as JSON; lines that are not
/// read are reported on stderr
#[argh(subcommand, name = "import")]
struct Import {
    /// a share link, or a subscription file (base64, or one link to a
    /// line); standard input when not given
    #[argh(positional)]
    input: Option<String>,
}

/// Prints the outbounds `import.input` reads into, and exits.
fn import(import: Import) -> ! {
    let body = match import.input {
        Some(link) if link.contains("://") => link,
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(body) => body,
            Err(e) => {
                eprintln!("cannot read {}: {}", path, e);
                exit(1);
            }
        },
        None => {
            let mut body = String::new();
            if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut body) {
                eprintln!("cannot read standard input: {}", e);
                exit(1);
            }
            body
        }
    };
    let (outbounds, warnings) = sail::config::share_link::parse_subscription(&body);
    for warning in &warnings {
        eprintln!("{}", warning);
    }
    if outbounds.is_empty() {
        eprintln!("no share link read");
        exit(1);
    }
    let json = serde_json::json!({ "outbounds": outbounds });
    println!(
        "{}",
        serde_json::to_string_pretty(&json).expect("a JSON value serializes")
    );
    exit(0);
}

/// Downloads the URLs the Surge profile `config` includes, and those they
/// include, where sail reads them: the includes directory in `cache_dir`.
/// One that fails keeps the copy there is; without one, it is an error.
fn fetch_includes(config: &str, cache_dir: Option<&str>) -> Result<(), String> {
    use sail::config::surge::{include_path, includes_dir, remote_includes};

    if sail::config::Format::of_file(config).ok() != Some(sail::config::Format::Surge) {
        return Err(format!(
            "{}: only a Surge profile (.conf) includes URLs",
            config
        ));
    }
    let cache_dir = cache_dir.ok_or("the copies are kept in --cache-dir, which is not given")?;
    let dir = includes_dir(std::path::Path::new(cache_dir));
    let text = std::fs::read_to_string(config).map_err(|e| format!("{}: {}", config, e))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start a runtime: {}", e))?;
    let mut queue: std::collections::VecDeque<String> = remote_includes(&text).into();
    let mut seen = std::collections::HashSet::new();
    while let Some(url) = queue.pop_front() {
        if !seen.insert(url.clone()) {
            continue;
        }
        let path = include_path(&dir, &url);
        let fetched = rt.block_on(sail::fetch::fetch(&url, &Default::default()));
        let body = match fetched {
            Ok(body) => {
                sail::fetch::write_atomically(&path, &body)
                    .map_err(|e| format!("{}: {}", path.display(), e))?;
                println!("fetched {}: {} bytes", url, body.len());
                body
            }
            Err(e) if path.is_file() => {
                println!("{}: {:#}; the copy kept is read", url, e);
                std::fs::read(&path).map_err(|e| format!("{}: {}", path.display(), e))?
            }
            Err(e) => return Err(format!("{}: {:#}", url, e)),
        };
        queue.extend(remote_includes(&String::from_utf8_lossy(&body)));
    }
    Ok(())
}

fn main() {
    let args: Args = argh::from_env();

    if args.version {
        println!("{}", get_version_string());
        exit(0);
    }

    match args.command {
        Some(Command::Import(i)) => import(i),
        Some(Command::Generate(g)) => generate(g),
        None => {}
    }

    let settings = sail::runtime::StartSettings {
        profile: args.profile,
        set: args.set,
        data_dir: args.data_dir.map(Into::into),
        cache_dir: args.cache_dir.clone().map(Into::into),
        sub_store: args.sub_store.map(sail::runtime::SubStore),
        ui_download_url: Some(args.ui_download_url).filter(|u| !u.is_empty()),
        ..Default::default()
    };
    let (runtime, host) = match settings.resolve() {
        Ok(v) => v,
        Err(e) => {
            println!("{}", e);
            exit(1);
        }
    };
    let env = sail::runtime::RuntimeEnv {
        options: runtime.clone(),
        host: host.clone(),
        ..Default::default()
    };

    if args.fetch_includes {
        if let Err(e) = fetch_includes(&args.config, args.cache_dir.as_deref()) {
            println!("fetching includes failed: {}", e);
            exit(1);
        }
    }

    if args.test {
        if let Err(e) = sail::test_config_with(&args.config, &env) {
            println!("{}", e);
            exit(1);
        } else {
            println!("ok");
            exit(0);
        }
    }

    if let Some(tag) = args.test_outbound {
        let config = match sail::config::from_file_for(&args.config, &host) {
            Ok(config) => config,
            Err(e) => {
                println!("{}", e);
                exit(1);
            }
        };
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                println!("cannot start a runtime: {}", e);
                exit(1);
            }
        };
        match rt.block_on(sail::util::test_outbound(
            &tag,
            &config,
            Some(std::time::Duration::from_secs(args.test_outbound_timeout)),
            &env,
        )) {
            Err(e) => {
                println!("test outbound failed: {}", e);
                exit(1);
            }
            Ok((tcp_res, udp_res)) => {
                match tcp_res {
                    Ok(duration) => println!("TCP ok in {}ms", duration.as_millis()),
                    Err(e) => println!("TCP failed: {}", e),
                }
                match udp_res {
                    Ok(duration) => println!("UDP ok in {}ms", duration.as_millis()),
                    Err(e) => println!("UDP failed: {}", e),
                }
                exit(0);
            }
        }
    }

    if let Err(e) = sail::util::run_with_options(
        0,
        args.config,
        args.auto_reload,
        !args.single_thread,
        true,
        0, // auto_threads is true, this value no longer matters
        args.thread_stack_size,
        runtime,
        host,
    ) {
        println!("start sail failed: {}", e);
        exit(1);
    }
}
