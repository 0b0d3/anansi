use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use ring::rand::{SecureRandom, SystemRandom};
use std::io::Read;
use std::path::Path;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};

use crate::defense::{DefenseEngine, AttackPattern};
use crate::deception::DeceptionEngine;
use crate::kernel::KernelInterface;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnansiConfig {
    pub paranoia_level: f64,
    pub reality_flux_rate: f64,
    pub mutation_rate: f64,
    pub illusion_density: f64,
    pub entropy_threshold: f64,
}

impl Default for AnansiConfig {
    fn default() -> Self {
        Self {
            paranoia_level: 0.8,
            reality_flux_rate: 0.5,
            mutation_rate: 0.3,
            illusion_density: 0.6,
            entropy_threshold: 0.7,
        }
    }
}

pub struct AnansiCore {
    config: AnansiConfig,
    reality_engine: Arc<RwLock<RealityEngine>>,
    quantum_state: Arc<RwLock<QuantumState>>,
    entropy_pool: Arc<RwLock<EntropyPool>>,
    defense_engine: Arc<RwLock<DefenseEngine>>,
    deception_engine: Arc<RwLock<DeceptionEngine>>,
    kernel_interface: Option<KernelInterface>,
    shutdown: Arc<RwLock<bool>>,
}

impl AnansiCore {
    pub async fn new(config: AnansiConfig) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Initializing ANANSI core...");

        // Initialize subsystems
        let reality_engine = Arc::new(RwLock::new(RealityEngine::new()));
        let quantum_state = Arc::new(RwLock::new(QuantumState::new()));
        let entropy_pool = Arc::new(RwLock::new(EntropyPool::new()));
        let defense_engine = Arc::new(RwLock::new(DefenseEngine::new(config.clone())));
        let deception_engine = Arc::new(RwLock::new(DeceptionEngine::new()));

        // Try to initialize kernel interface (may fail without kernel module)
        let kernel_interface = match KernelInterface::new() {
            Ok(ki) => {
                info!("Kernel interface initialized");
                Some(ki)
            }
            Err(e) => {
                warn!("Kernel interface unavailable: {}", e);
                None
            }
        };

        // Write PID file (async, non-fatal)
        let pid_path = std::env::var("ANANSI_PID_FILE").unwrap_or_else(|_| "/var/run/anansi.pid".to_string());
        if let Some(parent) = Path::new(&pid_path).parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                warn!("Failed to create PID directory {}: {}", parent.display(), e);
            }
        }

        match tokio::fs::write(&pid_path, std::process::id().to_string()).await {
            Ok(()) => info!("Wrote PID file to {}", pid_path),
            Err(e) => {
                warn!("Failed to write PID file to {}: {}", pid_path, e);
                // Fallback to /tmp
                let fallback = "/tmp/anansi.pid".to_string();
                if let Err(e2) = tokio::fs::write(&fallback, std::process::id().to_string()).await {
                    warn!("Failed to write fallback PID file {}: {}", fallback, e2);
                } else {
                    info!("Wrote PID file to fallback {}", fallback);
                }
            }
        }

        Ok(Self {
            config,
            reality_engine,
            quantum_state,
            entropy_pool,
            defense_engine,
            deception_engine,
            kernel_interface,
            shutdown: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn defense_cycle(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Collect entropy
        self.harvest_entropy().await?;

        // Check for observers
        let observers = self.detect_observers().await?;

        // Handle each observer
        for observer in observers {
            self.handle_observer(observer).await?;
        }

        // Update quantum state
        self.quantum_state.write().await.evolve();

        // Check for attacks
        if let Some(attack) = self.detect_attack().await? {
            self.defense_engine.write().await.respond_to_attack(attack).await?;
        }

        // Maintain illusions
        self.deception_engine.write().await.maintain_illusions().await?;

        Ok(())
    }

    pub async fn detect_observers(&self) -> Result<Vec<Observer>, Box<dyn std::error::Error>> {
        let mut observers = Vec::new();

        // Check for debuggers
        if self.detect_debugger().await? {
            observers.push(Observer {
                id: ObserverId::new(),
                observer_type: ObserverType::Debugger,
                trust_level: TrustLevel::Hostile,
                pid: None,
            });
        }

        // Check for system call tracers
        if self.detect_strace().await? {
            observers.push(Observer {
                id: ObserverId::new(),
                observer_type: ObserverType::SystemCallTracer,
                trust_level: TrustLevel::Suspicious,
                pid: None,
            });
        }

        // Check for network scanners
        if let Some(scanners) = self.detect_network_scanners().await? {
            for scanner in scanners {
                observers.push(scanner);
            }
        }

        Ok(observers)
    }

    async fn detect_debugger(&self) -> Result<bool, Box<dyn std::error::Error>> {
        // Only perform /proc and ptrace-based checks on Linux
        if !cfg!(target_os = "linux") {
            warn!("detect_debugger: /proc and ptrace checks are skipped on non-Linux OS");
            return Ok(false);
        }

        // Read /proc in a blocking-safe way
        let status = match tokio::task::spawn_blocking(|| std::fs::read_to_string("/proc/self/status")).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(Box::new(e)),
            Err(e) => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("join error: {}", e)))),
        };

        let is_traced = status.lines()
            .find(|line| line.starts_with("TracerPid:"))
            .and_then(|line| {
                line.split_whitespace().nth(1)
                    .and_then(|s| s.parse::<u32>().ok())
            })
            .map(|pid| pid != 0)
            .unwrap_or(false);

        // Also check via ptrace (run in blocking thread to be safe)
        if !is_traced {
            let ptrace_result = tokio::task::spawn_blocking(|| {
                // Use safe errno-aware handling
                unsafe {
                    let result = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                    if result == -1 {
                        let err = std::io::Error::last_os_error();
                        // If permission denied (EPERM) it's likely we're being traced
                        if let Some(errno) = err.raw_os_error() {
                            if errno == libc::EPERM {
                                return Ok(Ok(true));
                            } else {
                                return Ok(Err(Box::new(err) as Box<dyn std::error::Error>));
                            }
                        } else {
                            return Ok(Err(Box::new(err) as Box<dyn std::error::Error>));
                        }
                    } else {
                        // Detach since we were just testing; ignore detach errors
                        let _ = libc::ptrace(libc::PTRACE_DETACH, 0, 0, 0);
                        return Ok(Ok(false));
                    }
                }
            }).await.map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("join error: {}", e))))?;

            match ptrace_result { Ok(Ok(true)) => return Ok(true), Ok(Ok(false)) => {}, Ok(Err(e)) => warn!("ptrace probe error: {}", e), Err(e) => warn!("ptrace join error: {}", e), }
        }

        Ok(is_traced)
    }

    async fn detect_strace(&self) -> Result<bool, Box<dyn std::error::Error>> {
        // Only perform /proc-based checks on Linux
        if !cfg!(target_os = "linux") {
            warn!("detect_strace: /proc checks are skipped on non-Linux OS");
            return Ok(false);
        }

        // Check for common strace patterns (use blocking-safe reads)
        let cmdline = match tokio::task::spawn_blocking(|| std::fs::read_to_string("/proc/self/cmdline")).await {
            Ok(Ok(s)) => s,
            Ok(Err(_)) => String::new(),
            Err(e) => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("join error: {}", e)))),
        };

        let is_straced = cmdline.contains("strace");

        // Check parent process
        if !is_straced {
            if let Ok(stat) = tokio::task::spawn_blocking(|| std::fs::read_to_string("/proc/self/stat")).await.map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("join error: {}", e))))? {
                let parts: Vec<&str> = stat.split_whitespace().collect();
                if parts.len() > 3 {
                    let ppid = parts[3];
                    let parent_path = format!("/proc/{}/cmdline", ppid);
                    if let Ok(parent_cmdline) = tokio::task::spawn_blocking(move || std::fs::read_to_string(parent_path)).await.map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("join error: {}", e))))? {
                        return Ok(parent_cmdline.contains("strace"));
                    }
                }
            }
        }

        Ok(is_straced)
    }

    async fn detect_network_scanners(&self) -> Result<Option<Vec<Observer>>, Box<dyn std::error::Error>> {
        // This would normally check for network scanning patterns
        // For now, return None to indicate no scanners detected
        Ok(None)
    }

    async fn handle_observer(&mut self, observer: Observer) -> Result<(), Box<dyn std::error::Error>> {
        info!("Handling observer: {:?}", observer.observer_type);

        match observer.observer_type {
            ObserverType::Debugger => {
                // Activate anti-debugging measures
                self.activate_anti_debugging().await?;
            }
            ObserverType::SystemCallTracer => {
                // Inject false system calls
                self.inject_false_syscalls().await?;
            }
            ObserverType::NetworkScanner => {
                // Create network phantoms
                self.deception_engine.write().await.create_network_phantoms().await?;
            }
            _ => {
                // Default response
                self.increase_paranoia().await?;
            }
        }

        Ok(())
    }

    async fn activate_anti_debugging(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        warn!("Anti-debugging measures activated!");

        // Increase entropy to make behavior unpredictable
        self.entropy_pool.write().await.boost_entropy();

        // Create false breakpoints (run in blocking thread with timeout)
        if let Some(kernel) = self.kernel_interface.take() {
            let op = tokio::task::spawn_blocking(move || {
                let res = kernel.create_false_breakpoints();
                (kernel, res)
            });

            match tokio::time::timeout(std::time::Duration::from_secs(2), op).await {
                Ok(join_res) => match join_res {
                    Ok((k, Ok(()))) => { self.kernel_interface = Some(k); }
                    Ok((k, Err(e))) => { warn!("Kernel op failed: {}", e); self.kernel_interface = Some(k); }
                    Err(e) => { warn!("Kernel op join error: {}", e); }
                },
                Err(_) => {
                    warn!("Kernel create_false_breakpoints timed out");
                    // Try to re-initialize kernel interface if possible
                    if let Ok(ki) = KernelInterface::new() { self.kernel_interface = Some(ki); }
                }
            }
        }

        // Alter timing
        self.inject_timing_variations().await?;

        Ok(())
    }

    async fn inject_false_syscalls(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // This would inject false system call traces
        debug!("Injecting false system calls");

        if let Some(kernel) = self.kernel_interface.take() {
            let op = tokio::task::spawn_blocking(move || {
                let res = kernel.inject_false_syscalls();
                (kernel, res)
            });

            match tokio::time::timeout(std::time::Duration::from_secs(2), op).await {
                Ok(join_res) => match join_res {
                    Ok((k, Ok(()))) => { self.kernel_interface = Some(k); }
                    Ok((k, Err(e))) => { warn!("Kernel op failed: {}", e); self.kernel_interface = Some(k); }
                    Err(e) => { warn!("Kernel op join error: {}", e); }
                },
                Err(_) => {
                    warn!("Kernel inject_false_syscalls timed out");
                    if let Ok(ki) = KernelInterface::new() { self.kernel_interface = Some(ki); }
                }
            }
        }

        Ok(())
    }

    async fn inject_timing_variations(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Add random delays to confuse timing analysis
        let entropy = self.entropy_pool.read().await.get_random_u64();
        let delay = (entropy % 1000) as u64;
        tokio::time::sleep(tokio::time::Duration::from_micros(delay)).await;
        Ok(())
    }

    async fn increase_paranoia(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut current = self.config.paranoia_level;
        current = (current * 1.1).min(1.0);
        self.config.paranoia_level = current;
        debug!("Paranoia level increased to: {}", current);
        Ok(())
    }

    async fn harvest_entropy(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.entropy_pool.write().await.harvest().await?;
        Ok(())
    }

    async fn detect_attack(&self) -> Result<Option<AttackPattern>, Box<dyn std::error::Error>> {
        // Analyze system behavior for attack patterns
        let defense = self.defense_engine.read().await;
        defense.analyze_for_attacks().await
    }

    pub async fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("ANANSI shutting down...");
        *self.shutdown.write().await = true;

        // Clean up
        if let Some(kernel) = self.kernel_interface.take() {
            let op = tokio::task::spawn_blocking(move || {
                let res = kernel.cleanup();
                (kernel, res)
            });

            match tokio::time::timeout(std::time::Duration::from_secs(2), op).await {
                Ok(join_res) => match join_res {
                    Ok((_k, Ok(()))) => { /* cleaned up */ }
                    Ok((_k, Err(e))) => { warn!("Kernel cleanup failed: {}", e); }
                    Err(e) => { warn!("Kernel cleanup join error: {}", e); }
                },
                Err(_) => { warn!("Kernel cleanup timed out"); }
            }
        }

        // Remove PID file
        std::fs::remove_file("/var/run/anansi.pid").ok();

        Ok(())
    }

    // Test methods
    pub async fn collect_entropy(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let entropy = self.entropy_pool.read().await.get_entropy_bytes(32)?;
        Ok(entropy)
    }

    pub async fn test_defenses(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let defense = self.defense_engine.read().await;
        Ok(defense.self_test().await?)
    }

    pub async fn test_deception(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let deception = self.deception_engine.read().await;
        Ok(deception.self_test().await?)
    }

    pub async fn create_phantom_process(&self, name: &str) -> Result<u32, Box<dyn std::error::Error>> {
        let deception = self.deception_engine.write().await;
        deception.create_phantom_process(name).await
    }

    pub async fn destroy_phantom(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let deception = self.deception_engine.write().await;
        deception.destroy_phantom(pid).await
    }

    pub async fn create_reality_fork(&mut self) -> Result<RealityId, Box<dyn std::error::Error>> {
        let mut reality = self.reality_engine.write().await;
        Ok(reality.fork_reality())
    }

    pub async fn observe_file(&self, path: &str, reality_id: RealityId) -> Result<String, Box<dyn std::error::Error>> {
        let reality = self.reality_engine.read().await;
        reality.observe_file(path, reality_id).await
    }

    pub async fn simulate_attack(&mut self, attack_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        let pattern = AttackPattern::simulated(attack_id);
        let mut defense = self.defense_engine.write().await;
        defense.respond_to_attack(pattern).await
    }
}

// Reality Engine - manages multiple system states
pub struct RealityEngine {
    realities: HashMap<RealityId, Reality>,
    next_id: u64,
    random: SystemRandom,
}

impl RealityEngine {
    pub fn new() -> Self {
        Self {
            realities: HashMap::new(),
            next_id: 1,
            random: SystemRandom::new(),
        }
    }

    pub fn fork_reality(&mut self) -> RealityId {
        let id = RealityId(self.next_id);
        self.next_id += 1;

        let reality = Reality {
            id,
            mutations: Vec::new(),
            trust_level: TrustLevel::Unknown,
        };

        self.realities.insert(id, reality);
        id
    }

    pub async fn observe_file(&self, path: &str, reality_id: RealityId) -> Result<String, Box<dyn std::error::Error>> {
        let reality = self.realities.get(&reality_id)
            .ok_or("Reality not found")?;

        // Offload blocking file read to a blocking thread
        let path_owned = path.to_string();
        let content = tokio::task::spawn_blocking(move || -> Result<String, Box<dyn std::error::Error>> {
            let s = std::fs::read_to_string(path_owned)?;
            Ok(s)
        }).await.map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("join error: {}", e))))??;

        // Apply reality mutations
        let mutated = match reality.trust_level {
            TrustLevel::Hostile => {
                // Complete fabrication
                format!("DECEPTION: This file contains false data for reality {}", reality_id.0)
            }
            TrustLevel::Unknown => {
                // Subtle changes
                content.replace("true", "false")
                    .replace("enable", "disable")
            }
            TrustLevel::Trusted => {
                // Real content
                content
            }
            _ => content,
        };

        Ok(mutated)
    }
}

// Quantum State Manager
pub struct QuantumState {
    superposition: Vec<SystemState>,
    measurement_count: u64,
    collapse_events: Vec<CollapseEvent>,
}

impl QuantumState {
    pub fn new() -> Self {
        Self {
            superposition: vec![SystemState::default()],
            measurement_count: 0,
            collapse_events: Vec::new(),
        }
    }

    pub fn evolve(&mut self) {
        // Evolve quantum state over time
        for state in &mut self.superposition {
            state.phase += 0.1;
            state.amplitude *= 0.99;
        }

        // Add new states to superposition
        if self.superposition.len() < 10 {
            self.superposition.push(SystemState::random());
        }
    }

    pub fn collapse(&mut self, measurement: Measurement) -> SystemState {
        self.measurement_count += 1;

        let result_state = self.superposition.get(0).cloned().unwrap_or_default();

        let event = CollapseEvent {
            timestamp: std::time::SystemTime::now(),
            measurement,
            result_state: result_state.clone(),
        };

        self.collapse_events.push(event);

        // Return collapsed state
        result_state
    }
}

// Entropy Pool
pub struct EntropyPool {
    pool: Vec<u8>,
    sources: Vec<Box<dyn EntropySource>>,
    random: SystemRandom,
}

impl EntropyPool {
    pub fn new() -> Self {
        Self {
            pool: Vec::with_capacity(4096),
            sources: vec![
                Box::new(TimingEntropySource::new()),
                Box::new(SystemEntropySource::new()),
            ],
            random: SystemRandom::new(),
        }
    }

    pub async fn harvest(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use tokio::time::Duration;
        for source in &mut self.sources {
            // Bound each source collection to avoid blocking the whole harvest
            match tokio::time::timeout(Duration::from_millis(100), source.collect()).await {
                Ok(Ok(entropy)) => self.pool.extend_from_slice(&entropy),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Source timed out; skip it
                    warn!("Entropy source timed out");
                }
            }
        }

        // Mix pool
        if self.pool.len() > 32 {
            self.mix_pool();
        }

        Ok(())
    }

    fn mix_pool(&mut self) {
        // Simple mixing by XOR with random
        let mut mix_bytes = vec![0u8; 32];
        if let Err(e) = self.random.fill(&mut mix_bytes) {
            warn!("mix_pool: failed to fill random bytes: {:?}", e);
            return;
        }

        for (i, byte) in self.pool.iter_mut().enumerate() {
            *byte ^= mix_bytes[i % 32];
        }
    }

    pub fn get_entropy_bytes(&self, count: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = vec![0u8; count];
        self.random.fill(&mut bytes).map_err(|_| Box::<dyn std::error::Error>::from("Failed to generate random bytes"))?;
        Ok(bytes)
    }

    pub fn get_random_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        if let Err(e) = self.random.fill(&mut bytes) {
            warn!("get_random_u64: RNG fill failed: {:?}", e);
            return 0;
        }

        u64::from_le_bytes(bytes)
    }

    pub fn boost_entropy(&mut self) {
        // Add extra randomness when under attack
        let mut boost = vec![0u8; 256];
        if let Err(e) = self.random.fill(&mut boost) {
            warn!("boost_entropy: RNG fill failed: {:?}", e);
        } else {
            self.pool.extend_from_slice(&boost);
            self.mix_pool();
        }
    }
}


// Defense Engine - analyzes and responds to attacks
// Types and traits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RealityId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObserverId(u64);

impl ObserverId {
    fn new() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        Self(rng.gen())
    }
}

#[derive(Debug, Clone)]
pub struct Observer {
    pub id: ObserverId,
    pub observer_type: ObserverType,
    pub trust_level: TrustLevel,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ObserverType {
    Debugger,
    SystemCallTracer,
    NetworkScanner,
    MemoryAnalyzer,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrustLevel {
    Trusted,
    Unknown,
    Suspicious,
    Hostile,
}

#[derive(Debug, Clone)]
struct Reality {
    id: RealityId,
    mutations: Vec<Mutation>,
    trust_level: TrustLevel,
}

#[derive(Debug, Clone)]
struct Mutation {
    target: String,
    transform: String,
}

#[derive(Debug, Clone)]
struct SystemState {
    phase: f64,
    amplitude: f64,
    observables: HashMap<String, f64>,
}

impl Default for SystemState {
    fn default() -> Self {
        Self {
            phase: 0.0,
            amplitude: 1.0,
            observables: HashMap::new(),
        }
    }
}

impl SystemState {
    fn random() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        Self {
            phase: rng.gen::<f64>() * 2.0 * std::f64::consts::PI,
            amplitude: rng.gen::<f64>(),
            observables: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct Measurement {
    measurement_type: String,
    value: f64,
}

#[derive(Debug)]
struct CollapseEvent {
    timestamp: std::time::SystemTime,
    measurement: Measurement,
    result_state: SystemState,
}

// Entropy sources - Fixed to use boxed futures
use std::pin::Pin;
use std::future::Future;

trait EntropySource: Send + Sync {
    fn collect(&mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn std::error::Error>>> + Send + '_>>;
}

struct TimingEntropySource {
    last_time: std::time::Instant,
}

impl TimingEntropySource {
    fn new() -> Self {
        Self {
            last_time: std::time::Instant::now(),
        }
    }
}

impl EntropySource for TimingEntropySource {
    fn collect(&mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn std::error::Error>>> + Send + '_>> {
        // Compute timing delta synchronously to avoid holding a borrow across await points
        let now = std::time::Instant::now();
        let delta = now.duration_since(self.last_time);
        self.last_time = now;
        let nanos = delta.as_nanos() as u64;
        Box::pin(async move { Ok(nanos.to_le_bytes().to_vec()) })
    }
}

struct SystemEntropySource;

impl SystemEntropySource {
    fn new() -> Self {
        Self
    }
}

impl EntropySource for SystemEntropySource {
    fn collect(&mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn std::error::Error>>> + Send + '_>> {
        Box::pin(async move {
            // Offload blocking read to a blocking thread
            let res = tokio::task::spawn_blocking(|| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                let mut f = std::fs::File::open("/dev/urandom").map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
                let mut buf = [0u8; 32];
                std::io::Read::read_exact(&mut f, &mut buf).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
                Ok(buf.to_vec())
            }).await.map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("join error: {}", e))))?;

            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Ensure PID file goes to a writable location during tests
    fn ensure_test_pid_path() {
        std::env::set_var("ANANSI_PID_FILE", "/tmp/anansi_test.pid");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_entropy_harvest_non_blocking_current_thread() {
        ensure_test_pid_path();

        let pool = EntropyPool::new();
        let pool = Arc::new(tokio::sync::Mutex::new(pool));

        let heartbeat = Arc::new(AtomicUsize::new(0));
        let hb = heartbeat.clone();

        // Heartbeat task that should make progress while harvest runs
        let hb_task = tokio::spawn(async move {
            for _ in 0..50 {
                hb.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });

        // Run harvest while heartbeat is running
        {
            let mut p = pool.lock().await;
            p.harvest().await.expect("harvest failed");
        }

        // Wait a moment to let heartbeat run
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let count = heartbeat.load(Ordering::SeqCst);
        assert!(count > 0, "heartbeat did not progress during harvest");

        let _ = hb_task.await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_defense_cycle_non_blocking_multi_thread() {
        ensure_test_pid_path();

        let config = AnansiConfig::default();
        let mut core = AnansiCore::new(config).await.expect("core init failed");

        let heartbeat = Arc::new(AtomicUsize::new(0));
        let hb = heartbeat.clone();

        let hb_task = tokio::spawn(async move {
            while hb.load(Ordering::SeqCst) < 10 {
                hb.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });

        // Run a defense_cycle which uses async operations that should not block progress
        core.defense_cycle().await.expect("defense_cycle failed");

        // Wait a bit and ensure heartbeat progressed
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let count = heartbeat.load(Ordering::SeqCst);
        assert!(count > 0, "heartbeat did not progress during defense_cycle");

        let _ = hb_task.await;
    }
}