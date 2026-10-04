use std::process::exit;

use argh::FromArgs;

const COMMIT_DATE: Option<&'static str> = option_env!("CFG_COMMIT_DATE");

/// The release and the commit, as `sail::embed::BUILD` tells them, with
/// the commit's date when the release build gives it.
fn get_version_string() -> String {
    let build = sail::embed::BUILD;
    match COMMIT_DATE {
        Some(date) => format!("{} ({} - {})", build.version, build.commit, date),
        None => format!("{} ({})", build.version, build.commit),
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

    /// where changes to the system a kill would leave (ip rules, nftables)
    /// are written down, for the next start to undo; /run/sail on Linux by
    /// default
    #[argh(option)]
    run_dir: Option<String>,

    /// keep no such record, and sweep nothing at start
    #[argh(switch)]
    no_run_dir: bool,

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

    /// downloads the assets the configuration reads that are missing (asn.mmdb,
    /// geo.mmdb, site.dat, ...) into the data directory before it starts
    #[argh(switch)]
    fetch_assets: bool,

    /// where an asset is downloaded from, as name=url, instead of the
    /// default; repeatable
    #[argh(option)]
    asset_source: Vec<String>,

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
    Assets(Assets),
}

#[derive(FromArgs)]
/// Lists the data files (assets) a configuration reads: asn.mmdb, geo.mmdb,
/// site.dat, or files it names; downloads them with --fetch or --update
#[argh(subcommand, name = "assets")]
struct Assets {
    /// the configuration file; that of -c when not given
    #[argh(positional)]
    config: Option<String>,
    /// downloads the missing ones
    #[argh(switch)]
    fetch: bool,
    /// downloads them all again
    #[argh(switch)]
    update: bool,
    /// where an asset is downloaded from, as name=url, instead of the
    /// default; repeatable
    #[argh(option)]
    source: Vec<String>,
}

/// Where assets are downloaded from by default, by name. The core names
/// no URL: these are sail-cli's.
const ASSET_SOURCES: &[(&str, &str)] = &[
    // Mihomo's (config/config.go, GeoXUrl.ASN): GeoLite2-ASN.
    (
        "asn.mmdb",
        "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
    ),
    // GeoLite2-Country's format, which geoip reads.
    (
        "geo.mmdb",
        "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb",
    ),
    // V2Ray's site lists, domain-list-community and more.
    (
        "site.dat",
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    ),
];

/// `sources`, with `overrides` (name=url) in their place.
fn with_sources(
    mut sources: std::collections::BTreeMap<String, String>,
    overrides: &[String],
) -> Result<std::collections::BTreeMap<String, String>, String> {
    for source in overrides {
        match source.split_once('=') {
            Some((name, url)) if !name.is_empty() && url.contains("://") => {
                sources.insert(name.to_string(), url.to_string());
            }
            _ => return Err(format!("{}: expected name=url", source)),
        }
    }
    Ok(sources)
}

/// The default sources, with `overrides` (name=url) in their place.
fn asset_sources(
    overrides: &[String],
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let defaults = ASSET_SOURCES
        .iter()
        .map(|(name, url)| (name.to_string(), url.to_string()))
        .collect();
    with_sources(defaults, overrides)
}

/// Downloads the assets `config` reads with `env` that are missing, or
/// with `all` every one, from `sources`; one without a source is an error
/// that says how to give one. Returns the assets as they are after.
fn fetch_assets(
    config: &str,
    env: &sail::runtime::RuntimeEnv,
    sources: &std::collections::BTreeMap<String, String>,
    all: bool,
) -> Result<Vec<sail::assets::Asset>, String> {
    let parsed =
        sail::config::from_file_for(config, &env.host).map_err(|e| format!("{}: {}", config, e))?;
    let assets = sail::assets::required(&parsed, env);
    let due: Vec<_> = assets.iter().filter(|a| all || !a.present).collect();
    if due.is_empty() {
        return Ok(assets);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start a runtime: {}", e))?;
    for asset in due {
        let url = sources.get(&asset.name).ok_or_else(|| {
            format!(
                "{}: no source to download it from; give one with --source {}=<url> \
                 (sail --asset-source when starting), or place the file at {}",
                asset.name, asset.name, asset.path
            )
        })?;
        let size = rt
            .block_on(sail::assets::download(asset, url))
            .map_err(|e| format!("{:#}", e))?;
        println!("fetched {} into {}: {} bytes", asset.name, asset.path, size);
    }
    let parsed =
        sail::config::from_file_for(config, &env.host).map_err(|e| format!("{}: {}", config, e))?;
    Ok(sail::assets::required(&parsed, env))
}

/// Prints the assets, a line each: name, present, path, what reads it.
fn print_assets(assets: &[sail::assets::Asset]) {
    if assets.is_empty() {
        println!("the configuration reads no asset");
        return;
    }
    let width = assets.iter().map(|a| a.name.len()).max().unwrap_or(0);
    for asset in assets {
        println!(
            "{:width$}  {:7}  {}  {}",
            asset.name,
            if asset.present { "present" } else { "missing" },
            asset.path,
            asset.used_by.join(", "),
            width = width
        );
    }
}

/// Lists, or fetches, what `sail assets` asks for, and exits.
fn assets(args: Assets, config: &str, env: &sail::runtime::RuntimeEnv) -> ! {
    let config = args.config.as_deref().unwrap_or(config);
    let listed = if args.fetch || args.update {
        with_sources(env.host.asset_sources.clone(), &args.source)
            .and_then(|sources| fetch_assets(config, env, &sources, args.update))
    } else if !args.source.is_empty() {
        Err("--source is for --fetch or --update".to_string())
    } else {
        sail::config::from_file_for(config, &env.host)
            .map(|parsed| sail::assets::required(&parsed, env))
            .map_err(|e| format!("{}: {}", config, e))
    };
    match listed {
        Ok(list) => {
            print_assets(&list);
            exit(0);
        }
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    }
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
                println!(
                    "fetched {}: {} bytes",
                    sail::common::redact::url(&url),
                    body.len()
                );
                body
            }
            Err(e) if path.is_file() => {
                println!(
                    "{}: {:#}; the copy kept is read",
                    sail::common::redact::url(&url),
                    e
                );
                std::fs::read(&path).map_err(|e| format!("{}: {}", path.display(), e))?
            }
            Err(e) => return Err(format!("{}: {:#}", sail::common::redact::url(&url), e)),
        };
        queue.extend(remote_includes(&String::from_utf8_lossy(&body)));
    }
    Ok(())
}

#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOC: sail::alloc_stats::Counting = sail::alloc_stats::Counting;

// musl's mallocng is slow under the mux's per-frame allocations: a mux
// upload measured 1336 Mbit/s with it and 2248 with mimalloc. A router
// build goes without the mimalloc feature: mallocng holds less (after a
// 30,000-line profile, a load's peak 59 MiB against 75, after a reload 78
// against 88; x86_64). The library crates leave the allocator to the
// binary; alloc-stats replaces this one.
#[cfg(all(
    feature = "mimalloc",
    target_env = "musl",
    not(any(target_arch = "mips", target_arch = "mips64")),
    not(feature = "alloc-stats")
))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// mimalloc gives freed memory back lazily, as later allocations run, and
/// an idle process after a load makes none: without this it would keep a
/// load's peak for good. (mallocng gives it back as it is freed: without
/// mimalloc nothing is registered.) Run where sail says a load's memory was freed
/// (sail::runtime::memory): on the task that loaded it, which a reload on
/// a multi-thread runtime may have resumed on another worker; mi_collect
/// gives back the calling thread's free pages and the segments threads
/// abandoned. Measured on the router profile's runtime, at start and
/// reload.
#[cfg(all(
    feature = "mimalloc",
    target_env = "musl",
    not(any(target_arch = "mips", target_arch = "mips64")),
    not(feature = "alloc-stats")
))]
fn give_memory_back() {
    extern "C" {
        // mimalloc.h's `void mi_collect(bool force)`, unchanged since 1.0,
        // in the libmimalloc the mimalloc crate links.
        fn mi_collect(force: bool);
    }
    // SAFETY: it takes and returns nothing to uphold, and mimalloc is the
    // global allocator.
    unsafe { mi_collect(true) }
}

fn main() {
    #[cfg(all(
        feature = "mimalloc",
        target_env = "musl",
        not(any(target_arch = "mips", target_arch = "mips64")),
        not(feature = "alloc-stats")
    ))]
    sail::runtime::memory::on_memory_freed(give_memory_back);
    #[cfg(feature = "alloc-stats")]
    if let Some(path) = std::env::var_os("SAIL_ALLOC_STATS") {
        sail::alloc_stats::write_every(path.into(), std::time::Duration::from_millis(100));
    }
    #[cfg(unix)]
    raise_file_limit();

    let args: Args = argh::from_env();

    if args.version {
        println!("{}", get_version_string());
        exit(0);
    }

    let assets_command = match args.command {
        Some(Command::Import(i)) => import(i),
        Some(Command::Generate(g)) => generate(g),
        Some(Command::Assets(a)) => Some(a),
        None => None,
    };

    let asset_sources = match asset_sources(&args.asset_source) {
        Ok(sources) => sources,
        Err(e) => {
            println!("--asset-source {}", e);
            exit(1);
        }
    };
    let settings = sail::runtime::StartSettings {
        profile: args.profile,
        set: args.set,
        data_dir: args.data_dir.map(Into::into),
        cache_dir: args.cache_dir.clone().map(Into::into),
        sub_store: args.sub_store.map(sail::runtime::SubStore),
        ui_download_url: Some(args.ui_download_url).filter(|u| !u.is_empty()),
        asset_sources,
        run_dir: if args.no_run_dir {
            Some(sail::runtime::RunDirSetting::Off)
        } else {
            args.run_dir
                .map(|dir| sail::runtime::RunDirSetting::Dir(dir.into()))
        },
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

    if let Some(a) = assets_command {
        assets(a, &args.config, &env);
    }

    if args.fetch_assets {
        match fetch_assets(&args.config, &env, &host.asset_sources, false) {
            Ok(list) => {
                if let Some(missing) = list.iter().find(|a| !a.present) {
                    println!("fetching assets failed: {} is still missing", missing.path);
                    exit(1);
                }
            }
            Err(e) => {
                println!("fetching assets failed: {}", e);
                exit(1);
            }
        }
    }

    if args.test {
        match sail::test_config_with_warnings(&args.config, &env) {
            Err(e) => {
                println!("{:#}", e);
                exit(1);
            }
            Ok(warnings) => {
                // As sing-box check: warnings on standard error, and the
                // check passes.
                for warning in &warnings {
                    eprintln!("warning: {}", warning);
                }
                println!("ok");
                exit(0);
            }
        }
    }

    if let Some(tag) = args.test_outbound {
        let config = match sail::config::from_file_for(&args.config, &host) {
            Ok(config) => config,
            Err(e) => {
                println!("{:#}", e);
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
        sail::flush_log();
        println!("start sail failed: {:#}", e);
        exit(1);
    }
    // The last lines, such as how a stop went, are written before exiting.
    sail::flush_log();
}

/// Raises the soft limit on open files to the hard one, as Go does at
/// start (`syscall/rlimit.go`, since Go 1.19): a proxy holds two
/// descriptors a connection, and the soft limit systems give, 1024 or
/// 256, runs out long before the system does. On macOS no higher than
/// `kern.maxfilesperproc`, past which setrlimit fails
/// (`syscall/rlimit_darwin.go`). The core leaves the limit to its host
/// and logs the one it starts with; a failure here leaves it as it was.
#[cfg(unix)]
fn raise_file_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct it is given, nothing else.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return;
    }
    let target = file_limit_target(limit.rlim_max);
    if limit.rlim_cur >= target {
        return;
    }
    limit.rlim_cur = target;
    // SAFETY: setrlimit reads the struct it is given, nothing else.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
}

/// The soft limit to raise to under `hard`.
#[cfg(all(unix, not(target_os = "macos")))]
fn file_limit_target(hard: libc::rlim_t) -> libc::rlim_t {
    hard
}

#[cfg(target_os = "macos")]
fn file_limit_target(hard: libc::rlim_t) -> libc::rlim_t {
    let mut max: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL-terminated, and the value is written to an
    // int of the size given, which is what this sysctl holds.
    let got = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut max as *mut libc::c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    match libc::rlim_t::try_from(max) {
        Ok(max) if got == 0 && max > 0 => hard.min(max),
        _ => hard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// give_memory_back declares mimalloc's mi_collect by hand, which no
    /// compiler checks against the C library: it was checked against
    /// mimalloc.h in libmimalloc-sys 0.1.49. Another version fails here
    /// until its mi_collect is checked again and this updated.
    #[test]
    fn mi_collect_is_declared_as_the_locked_mimalloc_has_it() {
        let lock = include_str!("../../Cargo.lock");
        let version = lock
            .split("[[package]]")
            .find(|p| p.contains("name = \"libmimalloc-sys\""))
            .and_then(|p| p.lines().find_map(|l| l.strip_prefix("version = ")))
            .map(|v| v.trim_matches('"'));
        assert_eq!(
            version,
            Some("0.1.49"),
            "libmimalloc-sys changed: check mi_collect in its mimalloc.h against give_memory_back"
        );
    }

    /// A router build goes without mimalloc, the default feature: what a
    /// release builds for one is in build-cli.sh.
    #[test]
    fn a_router_build_has_musl_allocator() {
        let script = include_str!("../../scripts/release/build-cli.sh");
        let router = script
            .split("\nrouter)\n")
            .nth(1)
            .and_then(|rest| rest.split(";;").next())
            .expect("build-cli.sh has a router variant");
        assert!(router.contains("features=(--no-default-features)"));
        assert!(script.contains(r#"-p sail-cli ${features[@]+"${features[@]}"}"#));
    }

    #[cfg(unix)]
    #[test]
    fn file_limit_is_raised_to_the_hard_one() {
        raise_file_limit();
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        // Never lowered, should it be higher already.
        assert!(limit.rlim_cur >= file_limit_target(limit.rlim_max));
    }

    /// An include that cannot be fetched is told of by its host alone: a
    /// subscription's path and query carry its token.
    #[test]
    fn an_include_not_fetched_names_no_path() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let dir = std::env::temp_dir().join(format!("sail-cli-include-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let profile = dir.join("a.conf");
        std::fs::write(
            &profile,
            format!(
                "[Proxy]\n#!include http://127.0.0.1:{}/sub/s3cret?token=t0ken\n[Rule]\nFINAL,DIRECT\n",
                port
            ),
        )
        .unwrap();
        let err =
            fetch_includes(profile.to_str().unwrap(), Some(dir.to_str().unwrap())).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(err.contains("127.0.0.1") && err.contains("404"), "{}", err);
        assert!(!err.contains("s3cret") && !err.contains("t0ken"), "{}", err);
    }

    #[test]
    fn assets_takes_a_configuration_and_sources() {
        let args = Args::from_args(
            &["sail"],
            &[
                "-D",
                "/data",
                "assets",
                "c.json",
                "--fetch",
                "--source",
                "asn.mmdb=https://example.com/asn.mmdb",
            ],
        )
        .unwrap();
        assert_eq!(args.data_dir.as_deref(), Some("/data"));
        let Some(Command::Assets(a)) = args.command else {
            panic!("not assets");
        };
        assert_eq!(a.config.as_deref(), Some("c.json"));
        assert!(a.fetch && !a.update);
        assert_eq!(a.source, ["asn.mmdb=https://example.com/asn.mmdb"]);

        let args = Args::from_args(
            &["sail"],
            &[
                "--fetch-assets",
                "--asset-source",
                "site.dat=https://e/s.dat",
            ],
        )
        .unwrap();
        assert!(args.fetch_assets && args.command.is_none());
        let sources = asset_sources(&args.asset_source).unwrap();
        assert_eq!(sources["site.dat"], "https://e/s.dat");
        assert!(sources["asn.mmdb"].starts_with("https://"));
    }

    #[test]
    fn a_source_is_a_name_and_a_url() {
        for bad in ["asn.mmdb", "=https://e/a", "asn.mmdb=e/a"] {
            assert!(asset_sources(&[bad.to_string()]).is_err(), "{}", bad);
        }
        // Every default is an asset core knows by that name.
        for (name, url) in ASSET_SOURCES {
            assert!(["asn.mmdb", "geo.mmdb", "site.dat"].contains(name));
            assert!(url.starts_with("https://"));
        }
    }
}
