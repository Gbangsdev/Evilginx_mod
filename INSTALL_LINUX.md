# Installation Guide for Ubuntu/Linux

Follow these steps to set up and build this modified version of Evilginx2 on an Ubuntu or Debian-based system.

## 1. Update System
```bash
sudo apt update && sudo apt upgrade -y
```

## 2. Install Dependencies
Install essential build tools and networking utilities:
```bash
sudo apt install -y git build-essential wget
```

## 3. Install Go (Golang)
Evilginx2 requires Go (1.20 or higher recommended).
```bash
# Download Go
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz

# Remove any old version and extract
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz

# Add Go to your PATH
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.profile
source ~/.profile

# Verify installation
go version
```

## 4. Clone and Build
Use the specific repository provided:
```bash
git clone https://github.com/Gbangsdev/Evilginx_mod.git
cd Evilginx_mod

# Build the binary
go build -v -o evilginx2 .
```

## 5. Post-Installation (First Run)
To start Evilginx2, you usually need root privileges for binding to ports 80, 443, and 53:
```bash
sudo ./evilginx2
```

### Note on Configuration
After the first run, the configuration files are typically located in `~/.evilginx/`. You can edit `config.json` there to set up your Telegram notifications as described in the README.

## 6. Permissions (Optional)
If you want to run it without sudo (not recommended for DNS/HTTP binding), you can use `setcap`:
```bash
sudo setcap 'cap_net_bind_service=+ep' ./evilginx2
```
