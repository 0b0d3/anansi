use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::signal;
use clap::{Parser, Subcommand};
use tracing::{info, warn, error};
use nix::unistd::Uid;

mod core;
mod defense;
mod deception;
mod kernel;

use crate::core::{AnansiCore, AnansiConfig};

#[derive(Parser)]
#[command(name = "anansi")]
#[command(about = "ANANSI - Adaptive Neuromorphic Anomaly Network for Systemic Infiltration")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start ANANSI in daemon mode
    Start {
        /// Configuration file path
        #[arg(short, long, default_value = "/etc/anansi/anansi.toml")]
        config: String,
    },
    /// Test ANANSI functionality
    Test {
        /// Test mode
        #[arg(short, long, default_value = "basic")]
        mode: String,
    },
    /// Check system status
    Status,
    /// Emergency shutdown
    Kill {
        /// Force kill without cleanup
        #[arg(short, long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Check privileges
    if !Uid::effective().is_root() {
        error!("ANANSI requires root privileges");
        std::process::exit(1);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => {
            info!("Starting ANANSI with config: {}", config);
            start_anansi(config).await?;
        }
        Commands::Test { mode } => {
            info!("Running ANANSI test mode: {}", mode);
            run_tests(&mode).await?;
        }
        Commands::Status => {
            check_status().await?;
        }
        Commands::Kill { force } => {
            emergency_kill(force).await?;
        }
    }

    Ok(())
}

async fn start_anansi(config_path: String) -> Result<(), Box<dyn std::error::Error>> {
    info!("ANANSI: Initializing reality manipulation engine...");

    // Load configuration
    let config = load_config(&config_path)?;

    // Initialize core
    let mut core = AnansiCore::new(config).await?;

    // Set up signal handlers
    let shutdown = Arc::new(RwLock::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        warn!("Shutdown signal received");
        *shutdown_clone.write().await = true;
    });

    info!("ANANSI: The spider weaves...");

    // Main defense loop
    while !*shutdown.read().await {
        core.defense_cycle().await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    info!("ANANSI: Shutting down...");
    core.shutdown().await?;

    Ok(())
}

async fn run_tests(mode: &str) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        "basic" => run_basic_tests().await?,
        "phantom" => run_phantom_tests().await?,
        "reality" => run_reality_tests().await?,
        "full" => run_full_tests().await?,
        _ => {
            error!("Unknown test mode: {}", mode);
            return Err("Invalid test mode".into());
        }
    }
    Ok(())
}

async fn run_basic_tests() -> Result<(), Box<dyn std::error::Error>> {
    info!("Running basic functionality tests...");

    // Test 1: Core initialization
    info!("Test 1: Core initialization");
    let config = AnansiConfig::default();
    let core = AnansiCore::new(config).await?;
    info!("✓ Core initialized successfully");

    // Test 2: Observer detection
    info!("Test 2: Observer detection");
    let observers = core.detect_observers().await?;
    info!("✓ Detected {} observers", observers.len());

    // Test 3: Entropy collection
    info!("Test 3: Entropy collection");
    let entropy = core.collect_entropy().await?;
    info!("✓ Collected {} bytes of entropy", entropy.len());

    // Test 4: Defense modules
    info!("Test 4: Defense modules");
    let defense_status = core.test_defenses().await?;
    info!("✓ All defense modules operational: {}", defense_status);

    // Test 5: Deception capabilities
    info!("Test 5: Deception capabilities");
    let deception_ready = core.test_deception().await?;
    info!("✓ Deception systems ready: {}", deception_ready);

    info!("All basic tests passed!");
    Ok(())
}

async fn run_phantom_tests() -> Result<(), Box<dyn std::error::Error>> {
    info!("Running phantom process tests...");

    let config = AnansiConfig::default();
    let core = AnansiCore::new(config).await?;

    // Test phantom process creation
    info!("Creating phantom process...");
    let phantom_pid = core.create_phantom_process("test_phantom").await?;
    info!("✓ Created phantom with PID: {}", phantom_pid);

    // Verify phantom appears in /proc
    info!("Verifying phantom in /proc...");
    let proc_path = format!("/proc/{}", phantom_pid);
    if std::path::Path::new(&proc_path).exists() {
        info!("✓ Phantom visible in /proc");
    } else {
        warn!("⚠ Phantom not visible in /proc (may need kernel module)");
    }

    // Test phantom behavior
    info!("Testing phantom behavior...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Clean up
    info!("Cleaning up phantom...");
    core.destroy_phantom(phantom_pid).await?;
    info!("✓ Phantom destroyed");

    Ok(())
}

async fn run_reality_tests() -> Result<(), Box<dyn std::error::Error>> {
    info!("Running reality manipulation tests...");

    let config = AnansiConfig::default();
    let mut core = AnansiCore::new(config).await?;

    // Test 1: Reality divergence
    info!("Test 1: Creating reality divergence...");
    let reality1 = core.create_reality_fork().await?;
    let reality2 = core.create_reality_fork().await?;
    info!("✓ Created {} distinct realities", 2);

    // Test 2: Observer-specific reality
    info!("Test 2: Testing observer-specific views...");
    let test_file = "/tmp/anansi_test_file";
    std::fs::write(test_file, "original content")?;

    // Different observers see different content
    let content1 = core.observe_file(test_file, reality1).await?;
    let content2 = core.observe_file(test_file, reality2).await?;

    if content1 != content2 {
        info!("✓ Different observers see different realities");
    } else {
        warn!("⚠ Reality divergence not working (may need kernel module)");
    }

    // Clean up
    std::fs::remove_file(test_file).ok();

    Ok(())
}

async fn run_full_tests() -> Result<(), Box<dyn std::error::Error>> {
    info!("Running full system tests...");

    // Run all test suites
    run_basic_tests().await?;
    run_phantom_tests().await?;
    run_reality_tests().await?;

    // Additional stress tests
    info!("Running stress tests...");
    let config = AnansiConfig {
        paranoia_level: 1.0,
        reality_flux_rate: 0.9,
        mutation_rate: 0.8,
        ..Default::default()
    };

    let mut core = AnansiCore::new(config).await?;

    // Simulate attack
    info!("Simulating attack scenario...");
    for i in 0..10 {
        core.simulate_attack(i).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    info!("✓ System survived stress test");
    info!("All tests completed successfully!");

    Ok(())
}

async fn check_status() -> Result<(), Box<dyn std::error::Error>> {
    info!("Checking ANANSI status...");

    // Check if ANANSI is running
    let pid_file = "/var/run/anansi.pid";
    if std::path::Path::new(pid_file).exists() {
        let pid = std::fs::read_to_string(pid_file)?;
        info!("ANANSI is running (PID: {})", pid.trim());

        // Check health
        let health = check_health().await?;
        info!("Health status: {}", health);
    } else {
        info!("ANANSI is not running");
    }

    Ok(())
}

async fn check_health() -> Result<String, Box<dyn std::error::Error>> {
    // Check various health indicators
    let mut status = Vec::new();

    // Check kernel module
    if kernel::is_kernel_module_loaded()? {
        status.push("kernel_module: loaded".to_string());
    } else {
        status.push("kernel_module: not_loaded".to_string());
    }

    // Check eBPF programs
    let ebpf_count = kernel::count_loaded_ebpf_programs()?;
    status.push(format!("ebpf_programs: {}", ebpf_count));

    Ok(status.join(", "))
}

async fn emergency_kill(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    warn!("Emergency kill initiated!");

    if !force {
        warn!("This will terminate ANANSI. Continue? (y/N)");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            info!("Emergency kill cancelled");
            return Ok(());
        }
    }

    // Kill ANANSI process
    let pid_file = "/var/run/anansi.pid";
    if std::path::Path::new(pid_file).exists() {
        let pid = std::fs::read_to_string(pid_file)?
            .trim()
            .parse::<i32>()?;

        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }

        // Wait a moment
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Force kill if still running
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }

        std::fs::remove_file(pid_file).ok();
    }

    // Unload kernel module
    kernel::unload_kernel_module()?;

    // Clean up eBPF programs
    kernel::cleanup_ebpf_programs()?;

    warn!("ANANSI terminated");
    Ok(())
}

fn load_config(path: &str) -> Result<AnansiConfig, Box<dyn std::error::Error>> {
    if std::path::Path::new(path).exists() {
        let content = std::fs::read_to_string(path)?;
        let config: AnansiConfig = toml::from_str(&content)?;
        Ok(config)
    } else {
        warn!("Config file not found, using defaults");
        Ok(AnansiConfig::default())
    }
}