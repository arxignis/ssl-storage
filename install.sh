#!/bin/sh

VERSION=0.0.3
BRANCH=main

# Install dependencies
echo "Installing dependencies..."
apt-get update -qq
apt-get install -yqq curl sed

# Install ssl-storage
echo "Installing ssl-storage ${VERSION} for $(arch)..."
curl -fSL https://github.com/arxignis/ssl-storage/releases/download/v${VERSION}/ssl-storage-$(arch)-unknown-linux-gnu.tar.gz -o /tmp/ssl-storage-$(arch)-unknown-linux-gnu.tar.gz
tar -C /usr/local/bin -xzf /tmp/ssl-storage-$(arch)-unknown-linux-gnu.tar.gz

# Install service
echo "Installing service..."
curl -fSL https://raw.githubusercontent.com/arxignis/ssl-storage/refs/heads/${BRANCH}/others/systemd/ssl-storage.service -o /etc/systemd/system/ssl-storage.service
systemctl daemon-reload

# Create directories
echo "Creating directories..."
mkdir -p /var/log/ssl-storage /var/run/ssl-storage /var/lib/ssl-storage /etc/ssl-storage

# Create config file
echo "Creating config file..."
curl -fSL https://raw.githubusercontent.com/arxignis/ssl-storage/refs/heads/${BRANCH}/config_example.yaml -o /etc/ssl-storage/config.yaml
chmod 644 /etc/ssl-storage/config.yaml

# Enable and start service
echo "Enabling and starting service..."
systemctl enable ssl-storage

echo "Then run 'systemctl start ssl-storage' to start the service."
