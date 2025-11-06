#!/bin/bash

# Cross-platform Linux compatibility script for Honeypot System
# Supports: Ubuntu, Debian, CentOS, RHEL, Fedora, Arch, SUSE, Kali, and others

set -euo pipefail

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

# Detect pip
detect_pip() {
    PYTHON_CMD=$(detect_python)
    if command -v pip3 >/dev/null 2>&1; then
        echo "pip3"
    elif command -v pip >/dev/null 2>&1; then
        echo "pip"
    elif $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
        echo "$PYTHON_CMD -m pip"
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

# Initialize detected commands
PYTHON_CMD=$(detect_python)
PIP_CMD=$(detect_pip)
PORT_CHECKER=$(detect_port_checker)

# Function to check if a Python package is installed
check_package() {
    $PYTHON_CMD -c "import $1" 2>/dev/null
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
            
            case "$PORT_CHECKER" in
                lsof)
                    local pids=$(lsof -ti:"$port" 2>/dev/null || true)
                    if [ -n "$pids" ]; then
                        echo "$pids" | xargs sudo kill -9 2>/dev/null || true
                    fi
                    ;;
                ss|netstat)
                    # For ss/netstat, we need to find the PID differently
                    if command -v fuser >/dev/null 2>&1; then
                        sudo fuser -k "$port/tcp" 2>/dev/null || true
                    elif command -v lsof >/dev/null 2>&1; then
                        local pids=$(lsof -ti:"$port" 2>/dev/null || true)
                        if [ -n "$pids" ]; then
                            echo "$pids" | xargs sudo kill -9 2>/dev/null || true
                        fi
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

# Create necessary directories with proper permissions (preserve existing keys/certs)
print_status "Setting up directories..."
sudo mkdir -p ssh_keys certs logs config pcaps
sudo chmod 777 ssh_keys certs logs config pcaps

# SSH host key will be generated automatically by unified_honeypot.py if missing
print_status "SSH host key will be managed by unified_honeypot.py"

# Generate SSL certificates for HTTPS only if missing
if [ ! -f certs/server.key ] || [ ! -f certs/server.crt ]; then
    if command -v openssl >/dev/null 2>&1; then
        print_status "Generating SSL certificates..."
        openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
        sudo chmod 666 certs/server.key certs/server.crt
    else
        print_error "openssl not found. SSL certificates cannot be generated."
        print_warning "HTTPS service may not work without certificates."
    fi
else
    print_success "Using existing SSL certificates"
fi

# Install required packages
REQUIRED_PACKAGES=("paramiko" "flask" "requests")
print_status "Checking and installing required packages..."
for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! check_package "$package"; then
        print_status "Installing $package..."
        $PIP_CMD install "$package"
    else
        print_success "$package already installed"
    fi
done

# Start services
print_status "Starting Unified Honeypot..."
$PYTHON_CMD unified_honeypot.py &
sleep 2

print_status "Starting Dashboard..."
export FLASK_RUN_PORT=5001
export DASHBOARD_USERNAME=${DASHBOARD_USERNAME:-admin}
export DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD:-honeypot@91771}
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
