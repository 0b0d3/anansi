#!/bin/bash
# ANANSI Installation Script

set -e

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}=== ANANSI Installation ===${NC}"
echo "Adaptive Neuromorphic Anomaly Network for Systemic Infiltration"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This installation requires root privileges${NC}"
    exit 1
fi

# Check system requirements
echo "Checking system requirements..."

# Check for Rust
if ! command -v rustc &> /dev/null; then
    echo -e "${RED}Error: Rust is not installed${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

# Check kernel version (need 5.x for eBPF)
KERNEL_VERSION=$(uname -r | cut -d. -f1)
if [ "$KERNEL_VERSION" -lt 5 ]; then
    echo -e "${YELLOW}Warning: Kernel version < 5.0, some features may not work${NC}"
fi

# Create directories
echo "Creating directories..."
mkdir -p /etc/anansi
mkdir -p /var/log/anansi
mkdir -p /var/run/anansi
mkdir -p /lib/modules/anansi

# Build ANANSI
echo "Building ANANSI..."
cargo build --release

# Install binary
echo "Installing binary..."
cp target/release/anansi /usr/local/bin/
chmod +x /usr/local/bin/anansi

# Install configuration
echo "Installing configuration..."
cp anansi.toml /etc/anansi/

# Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/anansi.service << EOF
[Unit]
Description=ANANSI Security System
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/anansi start
ExecStop=/usr/local/bin/anansi kill --force
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Build kernel module (if source exists)
if [ -d "kernel/kmod" ]; then
    echo "Building kernel module..."
    cd kernel/kmod
    make
    cp anansi_kmod.ko /lib/modules/anansi/
    cd ../..
else
    echo -e "${YELLOW}Warning: Kernel module source not found, skipping${NC}"
fi

# Set up eBPF mount
if ! mountpoint -q /sys/fs/bpf; then
    echo "Mounting BPF filesystem..."
    mount -t bpf none /sys/fs/bpf
    echo "none /sys/fs/bpf bpf defaults 0 0" >> /etc/fstab
fi

echo
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo
echo "To start ANANSI:"
echo "  systemctl start anansi"
echo
echo "To enable at boot:"
echo "  systemctl enable anansi"
echo
echo "To test installation:"
echo "  anansi test"
echo
echo -e "${YELLOW}WARNING: ANANSI is a powerful security system.${NC}"
echo -e "${YELLOW}Use with caution and only on authorized systems.${NC}"