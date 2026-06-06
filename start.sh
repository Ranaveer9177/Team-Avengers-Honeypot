#!/bin/bash

set -euo pipefail  # VULN-028 FIX: Fail-fast before any code runs

# Cross-platform Linux compatibility script for Honeypot System
# Supports: Ubuntu, Debian, CentOS, RHEL, Fedora, Arch, SUSE, Kali, and others

# Check if boot menu should be shown (VULN-028 FIX: use ${1:-} for set -u safety)
if [ "${1:-}" != "--skip-menu" ]; then
    # Show boot menu
    if command -v python3 >/dev/null 2>&1; then
        python3 boot_menu.py
    elif command -v python >/dev/null 2>&1; then
        python boot_menu.py
    else
        echo "Python not found. Boot menu not available, starting honeypot directly..."
    fi
    # Exit after menu (menu will handle starting services if needed)
    exit 0
fi

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to print colored status messages
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Detect available commands with fallbacks
detect_command() {
    local cmd=$1
    local fallback=$2
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "$cmd"
    elif [ -n "$fallback" ] && command -v "$fallback" >/dev/null 2>&1; then
        echo "$fallback"
    else
        echo ""
    fi
}

# Detect Python interpreter
detect_python() {
    if command -v python3 >/dev/null 2>&1; then
        echo "python3"
    elif command -v python >/dev/null 2>&1; then
        local version=$(python --version 2>&1 | grep -oP '\d+' | head -1)
        if [ "$version" -ge 3 ]; then
            echo "python"
        else
            print_error "Python 3.x is required but only Python 2.x found"
            exit 1
        fi
    else
        print_error "Python 3.x is required but not found"
        exit 1
    fi
}

# Detect pip — prioritize virtualenv pip over system pip (PEP 668 / Ubuntu 24+)
detect_pip() {
    local PYTHON_CMD
    PYTHON_CMD=$(detect_python)

    # 1. If a virtualenv is active, use its pip directly
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        if [ -x "$VIRTUAL_ENV/bin/pip" ]; then
            echo "$VIRTUAL_ENV/bin/pip"
            return
        elif [ -x "$VIRTUAL_ENV/bin/pip3" ]; then
            echo "$VIRTUAL_ENV/bin/pip3"
            return
        fi
    fi

    # 2. Check for a local .venv pip (not yet activated but present)
    if [ -x ".venv/bin/pip" ]; then
        echo ".venv/bin/pip"
        return
    fi

    # 3. Use python -m pip (always matches the active interpreter)
    if $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
        echo "$PYTHON_CMD -m pip"
        return
    fi

    # 4. Fall back to system pip (may fail on PEP 668 distros)
    if command -v pip3 >/dev/null 2>&1; then
        echo "pip3"
    elif command -v pip >/dev/null 2>&1; then
        echo "pip"
    else
        print_error "pip is required but not found"
        exit 1
    fi
}

# Detect port checking tool
detect_port_checker() {
    if command -v lsof >/dev/null 2>&1; then
        echo "lsof"
    elif command -v ss >/dev/null 2>&1; then
        echo "ss"
    elif command -v netstat >/dev/null 2>&1; then
        echo "netstat"
    else
        echo ""
    fi
}

# Detect IP address command
get_ip_address() {
    # Try multiple methods to get IP address
    if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
        hostname -I | awk '{print $1}'
    elif command -v ip >/dev/null 2>&1; then
        ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || \
        ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | head -1
    elif [ -f /etc/hostname ]; then
        # Fallback: try to get from interface
        ifconfig 2>/dev/null | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | head -1 || echo "localhost"
    else
        echo "localhost"
    fi
}

# Setup and activate virtual environment
setup_venv() {
    local PYTHON_CMD=$(detect_python)
    local VENV_DIR=".venv"

    # Skip if already inside a virtual environment
    # VULN-033 FIX: Use ${VIRTUAL_ENV:-} to avoid crash under set -u
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        print_success "Already inside virtual environment: $VIRTUAL_ENV"
        return 0
    fi

    # Create venv if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        print_status "Creating virtual environment (.venv)..."
        if $PYTHON_CMD -m venv "$VENV_DIR" 2>/dev/null; then
            print_success "Virtual environment created"
        else
            # Try installing python3-venv package first (Debian/Ubuntu)
            print_warning "venv module missing, attempting to install python3-venv..."
            if command -v apt-get >/dev/null 2>&1; then
                sudo apt-get install -y python3-venv 2>/dev/null
            fi
            if $PYTHON_CMD -m venv "$VENV_DIR" 2>/dev/null; then
                print_success "Virtual environment created (after installing python3-venv)"
            else
                print_warning "Could not create virtual environment — will try global pip with --break-system-packages"
                return 1
            fi
        fi
    else
        print_success "Using existing virtual environment (.venv)"
    fi

    # Activate the virtual environment
    if [ -f "$VENV_DIR/bin/activate" ]; then
        # shellcheck disable=SC1091
        source "$VENV_DIR/bin/activate"
        print_success "Virtual environment activated"
        return 0
    else
        print_warning "Virtual environment activation script not found"
        return 1
    fi
}

# Initialize detected commands
PYTHON_CMD=$(detect_python)
PIP_CMD=$(detect_pip)
PORT_CHECKER=$(detect_port_checker)

# Setup venv (must come after detect_python so we have a Python to create it with)
USE_VENV=true
if setup_venv; then
    # Re-detect commands inside the venv
    PYTHON_CMD=$(detect_python)
    PIP_CMD=$(detect_pip)
    print_status "Using venv Python: $(which $PYTHON_CMD)"
else
    USE_VENV=false
    print_warning "Running without virtual environment"
fi

# Function to check if a Python package is installed
# VULN-032 FIX: Validate package name to prevent code injection
check_package() {
    local pkg_name="$1"
    if ! echo "$pkg_name" | grep -qE '^[a-zA-Z_][a-zA-Z0-9_]*$'; then
        print_error "Invalid package name: $pkg_name"
        return 1
    fi
    $PYTHON_CMD -c "__import__('$pkg_name')" 2>/dev/null
    return $?
}

# Function to check if port is in use (cross-platform)
check_port() {
    local port=$1
    if [ -z "$PORT_CHECKER" ]; then
        # If no port checker available, skip check
        return 1
    fi
    
    case "$PORT_CHECKER" in
        lsof)
            lsof -i:"$port" >/dev/null 2>&1
            ;;
        ss)
            ss -tuln | grep -q ":$port "
            ;;
        netstat)
            netstat -tuln 2>/dev/null | grep -q ":$port "
            ;;
        *)
            return 1
            ;;
    esac
}

# Function to free up required ports
free_ports() {
    local ports=(2222 5000 5001 8080 8443 2121 3306)
    
    if [ -z "$PORT_CHECKER" ]; then
        print_warning "No port checking tool found (lsof/ss/netstat). Skipping port check."
        return 0
    fi
    
    for port in "${ports[@]}"; do
        if check_port "$port"; then
            print_warning "Found process using port $port. Attempting to free it..."
            
            # VULN-031 FIX: Only kill Python/honeypot processes, not unrelated services
            case "$PORT_CHECKER" in
                lsof)
                    local pids=$(lsof -ti:"$port" 2>/dev/null || true)
                    if [ -n "$pids" ]; then
                        for pid in $pids; do
                            local proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || true)
                            if echo "$proc_name" | grep -qiE 'python|honeypot|flask|unified'; then
                                sudo kill -9 "$pid" 2>/dev/null || true
                            else
                                print_warning "Port $port: skipping non-honeypot process $proc_name (PID $pid)"
                            fi
                        done
                    fi
                    ;;
                ss|netstat)
                    # For ss/netstat, we need to find the PID differently
                    if command -v fuser >/dev/null 2>&1; then
                        # Get PIDs from fuser, filter for honeypot processes only
                        local fuser_pids=$(fuser "$port/tcp" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$' || true)
                        for pid in $fuser_pids; do
                            local proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || true)
                            if echo "$proc_name" | grep -qiE 'python|honeypot|flask|unified'; then
                                sudo kill -9 "$pid" 2>/dev/null || true
                            else
                                print_warning "Port $port: skipping non-honeypot process $proc_name (PID $pid)"
                            fi
                        done
                    fi
                    ;;
            esac
            
            sleep 2
            if check_port "$port"; then
                print_error "Failed to free port $port"
                return 1
            else
                print_success "Successfully freed port $port"
            fi
        fi
    done
    return 0
}

# Function to verify ports are free
verify_ports() {
    local ports=(2222 5000 5001 8080 8443 2121 3306)
    
    if [ -z "$PORT_CHECKER" ]; then
        return 0
    fi
    
    for port in "${ports[@]}"; do
        if check_port "$port"; then
            print_error "Error: Port $port is still in use"
            return 1
        fi
    done
    return 0
}

# Function to test ports and services (optional, graceful if tools unavailable)
test_honeypot() {
    print_status "Testing Honeypot Services..."
    echo "----------------------------------------"

    local ports=(2222 8080 8443 2121 3306 5001)
    local services=("SSH" "HTTP" "HTTPS" "FTP" "MySQL" "Dashboard")

    # Test ports
    local nc_cmd=$(detect_command "nc" "netcat")
    if [ -n "$nc_cmd" ]; then
        for i in "${!ports[@]}"; do
            echo -n "Testing ${services[$i]} on port ${ports[$i]}... "
            if $nc_cmd -zv localhost "${ports[$i]}" 2>/dev/null; then
                print_success "Available"
            else
                print_error "Not available"
            fi
        done
    else
        print_warning "netcat not found, skipping port tests"
    fi

    # Test SSH (if ssh client available)
    if command -v ssh >/dev/null 2>&1; then
        local timeout_cmd=$(detect_command "timeout" "gtimeout")
        echo -n "Testing SSH honeypot response... "
        if [ -n "$timeout_cmd" ]; then
            if $timeout_cmd 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p 2222 fakeuser@localhost 2>&1 | grep -q "Permission denied"; then
                print_success "Working correctly"
            else
                print_error "Unexpected response"
            fi
        else
            print_warning "timeout command not found, skipping SSH test"
        fi
    fi

    # Test HTTP service (if curl available)
    if command -v curl >/dev/null 2>&1; then
        echo -n "Testing HTTP honeypot... "
        if curl -s -m 5 http://localhost:8080 >/dev/null 2>&1; then
            print_success "Responding"
        else
            print_error "Not responding"
        fi

        echo -n "Testing Dashboard... "
        if curl -s -m 5 http://localhost:5001 >/dev/null 2>&1; then
            print_success "Accessible"
        else
            print_error "Not accessible"
        fi
    else
        print_warning "curl not found, skipping HTTP tests"
    fi

    echo -e "\nNetwork Information:"
    echo "----------------------------------------"
}

# Configure firewall rules automatically
configure_firewall() {
    print_status "Configuring firewall rules..."

    # Required ports: honeypot services + dashboard
    local HONEYPOT_PORTS=(2222 8080 8443 2121 3306)
    local DASHBOARD_PORT=5001

    # Detect firewall tool
    if command -v ufw >/dev/null 2>&1; then
        print_status "Detected firewall: UFW"

        # Ensure UFW is enabled
        if ! sudo ufw status | grep -q "Status: active"; then
            print_warning "UFW is inactive. Enabling..."
            sudo ufw --force enable 2>/dev/null || true
        fi

        # Open honeypot ports (public — to attract attackers)
        for port in "${HONEYPOT_PORTS[@]}"; do
            sudo ufw allow "$port/tcp" comment "Honeypot service" 2>/dev/null
            print_success "UFW: Opened port $port/tcp (honeypot)"
        done

        # Open dashboard port (consider restricting to your IP)
        sudo ufw allow "$DASHBOARD_PORT/tcp" comment "Honeypot Dashboard" 2>/dev/null
        print_success "UFW: Opened port $DASHBOARD_PORT/tcp (dashboard)"

        # Reload
        sudo ufw reload 2>/dev/null || true
        print_success "UFW firewall configured"

    elif command -v firewall-cmd >/dev/null 2>&1; then
        print_status "Detected firewall: firewalld"

        # Open honeypot ports
        for port in "${HONEYPOT_PORTS[@]}"; do
            sudo firewall-cmd --permanent --add-port="$port/tcp" 2>/dev/null
            print_success "firewalld: Opened port $port/tcp (honeypot)"
        done

        # Open dashboard port
        sudo firewall-cmd --permanent --add-port="$DASHBOARD_PORT/tcp" 2>/dev/null
        print_success "firewalld: Opened port $DASHBOARD_PORT/tcp (dashboard)"

        # Reload
        sudo firewall-cmd --reload 2>/dev/null
        print_success "firewalld configured"

    elif command -v iptables >/dev/null 2>&1; then
        print_status "Detected firewall: iptables"

        # Open honeypot ports
        for port in "${HONEYPOT_PORTS[@]}"; do
            # Check if rule already exists before adding
            if ! sudo iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
                sudo iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
                print_success "iptables: Opened port $port/tcp (honeypot)"
            else
                print_success "iptables: Port $port/tcp already open"
            fi
        done

        # Open dashboard port
        if ! sudo iptables -C INPUT -p tcp --dport "$DASHBOARD_PORT" -j ACCEPT 2>/dev/null; then
            sudo iptables -I INPUT -p tcp --dport "$DASHBOARD_PORT" -j ACCEPT
            print_success "iptables: Opened port $DASHBOARD_PORT/tcp (dashboard)"
        else
            print_success "iptables: Port $DASHBOARD_PORT/tcp already open"
        fi

        # Try to persist rules
        if command -v iptables-save >/dev/null 2>&1; then
            sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        print_success "iptables configured"

    else
        print_warning "No firewall detected (ufw/firewalld/iptables). Skipping firewall setup."
        print_warning "Make sure ports 2222, 5001, 8080, 8443, 2121, 3306 are accessible."
    fi

    echo ""
}

# Clean up function
cleanup() {
    print_status "Shutting down honeypot services..."
    pkill -f "$PYTHON_CMD unified_honeypot.py" 2>/dev/null || true
    pkill -f "$PYTHON_CMD app.py" 2>/dev/null || true
    exit 0
}

# Set up trap for cleanup on script termination
trap cleanup SIGINT SIGTERM

# Main script starts here
print_status "Setting up Honeypot..."
print_status "Detected Python: $PYTHON_CMD"
print_status "Detected pip: $PIP_CMD"
[ -n "$PORT_CHECKER" ] && print_status "Port checker: $PORT_CHECKER" || print_warning "No port checker available"
echo "----------------------------------------"

# Check and free required ports
print_status "Checking and freeing required ports..."
if ! free_ports; then
    print_error "Failed to free all required ports. Please check running processes manually."
    exit 1
fi

# Verify ports are free
if ! verify_ports; then
    print_error "Some ports are still in use. Please check running processes manually."
    exit 1
fi

# Configure firewall BEFORE starting services
configure_firewall

# Create necessary directories with proper permissions (preserve existing keys/certs)
print_status "Setting up directories..."
sudo mkdir -p ssh_keys certs logs config pcaps
sudo chmod 700 ssh_keys certs  # BUG-010 FIX: Restrict access to sensitive key/cert dirs
sudo chmod 755 logs config pcaps

# SSH host key will be generated automatically by unified_honeypot.py if missing
print_status "SSH host key will be managed by unified_honeypot.py"

# Generate SSL certificates for HTTPS only if missing
if [ ! -f certs/server.key ] || [ ! -f certs/server.crt ]; then
    if command -v openssl >/dev/null 2>&1; then
        print_status "Generating SSL certificates..."
        openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
        sudo chmod 600 certs/server.key  # VULN-011 FIX: Owner-only access for private key
        sudo chmod 644 certs/server.crt
    else
        print_error "openssl not found. SSL certificates cannot be generated."
        print_warning "HTTPS service may not work without certificates."
    fi
else
    print_success "Using existing SSL certificates"
fi

# Install required packages
REQUIRED_PACKAGES=("paramiko" "flask" "requests" "cryptography" "markupsafe")  # VULN-038 FIX: markupsafe needed by app.py
print_status "Checking and installing required packages..."
for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! check_package "$package"; then
        print_status "Installing $package..."
        if [ "$USE_VENV" = true ]; then
            # Inside venv — normal pip install works fine
            $PIP_CMD install "$package"
        else
            # No venv — use --break-system-packages as last resort (Ubuntu 24+)
            $PIP_CMD install "$package" --break-system-packages 2>/dev/null || \
            $PIP_CMD install "$package" 2>/dev/null || \
            { print_error "Failed to install $package. Please create a venv manually:"; \
              print_error "  python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"; \
              exit 1; }
        fi
    else
        print_success "$package already installed"
    fi
done

# Also install from requirements.txt if it exists (catches all deps)
if [ -f "requirements.txt" ]; then
    print_status "Installing all dependencies from requirements.txt..."
    if [ "$USE_VENV" = true ]; then
        $PIP_CMD install -r requirements.txt 2>/dev/null || true
    else
        $PIP_CMD install -r requirements.txt --break-system-packages 2>/dev/null || \
        $PIP_CMD install -r requirements.txt 2>/dev/null || true
    fi
    print_success "Dependencies installed"
fi

# Start services
print_status "Starting Unified Honeypot..."
$PYTHON_CMD unified_honeypot.py &
sleep 2

print_status "Starting Dashboard..."
export FLASK_RUN_PORT=5001
export DASHBOARD_USERNAME=${DASHBOARD_USERNAME:-admin}
export DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD:-Honeypot@9177}
export ATTACKS_LOG=${ATTACKS_LOG:-logs/attacks.json}
export GEOCACHE_FILE=${GEOCACHE_FILE:-logs/geocache.json}
$PYTHON_CMD app.py &
sleep 2

print_success "All services started successfully!"

# Display service information
print_status "Network Information:"
echo "----------------------------------------"
IP_ADDRESS=$(get_ip_address)
echo "Internal IP: $IP_ADDRESS"
echo -e "\nServices running on:"
echo "Dashboard: http://$IP_ADDRESS:5001"
echo "  Username: $DASHBOARD_USERNAME"
echo "  Password: $DASHBOARD_PASSWORD"
echo "SSH:      ssh -p 2222 admin@$IP_ADDRESS"
echo "HTTP:     http://$IP_ADDRESS:8080"
echo "HTTPS:    https://$IP_ADDRESS:8443"
echo "FTP:      ftp -P 2121 $IP_ADDRESS"
echo "MySQL:    mysql -h $IP_ADDRESS -P 3306"
echo "----------------------------------------"

# Test the honeypot services (optional)
print_status "Running tests..."
sleep 5  # Wait for services to fully start
test_honeypot

print_status "Honeypot is running and ready for connections"
print_status "Press Ctrl+C to stop all services"

# Keep the script running
while true; do
    sleep 1
done
