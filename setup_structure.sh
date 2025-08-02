#!/bin/bash

echo "[+] Creating folders..."
mkdir -p src
mkdir -p bpf
mkdir -p scripts

echo "[+] Creating Rust source files..."
touch src/core.rs
touch src/defense.rs
touch src/deception.rs
touch src/kernel.rs

echo "[+] Creating eBPF C source files..."
touch bpf/hide.bpf.c
touch bpf/intercept.bpf.c

echo "[+] Creating scripts..."
touch scripts/install.sh
chmod +x scripts/install.sh
echo '#!/bin/bash' > scripts/install.sh
echo 'echo "[*] Installing Anansi system..."' >> scripts/install.sh

touch scripts/emergency_kill.sh
chmod +x scripts/emergency_kill.sh
echo '#!/bin/bash' > scripts/emergency_kill.sh
echo 'echo "[!] EMERGENCY KILL SWITCH ACTIVATED!"' >> scripts/emergency_kill.sh

echo "[+] Creating config files..."
touch anansi.toml
touch README.md
touch build.rs

echo "[✓] Project structure is ready."
