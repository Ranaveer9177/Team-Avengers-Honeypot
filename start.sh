#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
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

# Function to check if a Python package is installed
check_package() {
    python3 -c "import $1" 2>/dev/null
    return $?
}

# Function to free up required ports
free_ports() {
    local ports=(2222 5000 5001 8080 8443 2121 3306)
    for port in "${ports[@]}"; do
        if lsof -i:"$port" >/dev/null 2>&1; then
            echo "Found process using port $port. Attempting to free it..."
            sudo lsof -ti:"$port" | xargs sudo kill -9 2>/dev/null
            sleep 2
            if lsof -i:"$port" >/dev/null 2>&1; then
                echo "Failed to free port $port"
                return 1
            fi
            echo "Successfully freed port $port"
        fi
    done
    return 0
}

# Function to verify ports are free
verify_ports() {
    local ports=(2222 5000 5001 8080 8443 2121 3306)
    for port in "${ports[@]}"; do
        if lsof -i:"$port" >/dev/null 2>&1; then
            echo "Error: Port $port is still in use after attempting to free it"
            return 1
        fi
    done
    return 0
}

# Function to test ports and services
test_honeypot() {
    print_status "Testing Honeypot Services..."
    echo "----------------------------------------"

    # Test ports
    local ports=(2222 8080 8443 2121 3306 5001)
    local services=("SSH" "HTTP" "HTTPS" "FTP" "MySQL" "Dashboard")

    for i in "${!ports[@]}"; do
        echo -n "Testing ${services[$i]} on port ${ports[$i]}... "
        if nc -zv localhost "${ports[$i]}" 2>/dev/null; then
            print_success "Available"
        else
            print_error "Not available"
        fi
    done

    # Test SSH with invalid credentials
    echo -n "Testing SSH honeypot response... "
    if timeout 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p 2222 fakeuser@localhost 2>&1 | grep -q "Permission denied"; then
        print_success "Working correctly (Authentication failed as expected)"
    else
        print_error "Unexpected response"
    fi

    # Test HTTP service
    echo -n "Testing HTTP honeypot... "
    if curl -s -m 5 http://localhost:8080 &>/dev/null; then
        print_success "Responding"
    else
        print_error "Not responding"
    fi

    # Test Dashboard
    echo -n "Testing Dashboard... "
    if curl -s -m 5 http://localhost:5001 &>/dev/null; then
        print_success "Accessible"
    else
        print_error "Not accessible"
    fi

    # Show network information
    echo -e "\nNetwork Information:"
    echo "----------------------------------------"
}

# Clean up function
cleanup() {
    print_status "Shutting down honeypot services..."
    pkill -f "python3 unified_honeypot.py"
    pkill -f "python3 unified_dashboard.py"
    exit 0
}

# Set up trap for cleanup on script termination
trap cleanup SIGINT SIGTERM

# Main script starts here
print_status "Setting up Honeypot..."
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
# This ensures the same key file is used by both start.sh and the Python server
print_status "SSH host key will be managed by unified_honeypot.py"

# Generate SSL certificates for HTTPS only if missing
if [ ! -f certs/server.key ] || [ ! -f certs/server.crt ]; then
    print_status "Generating SSL certificates..."
    openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
    sudo chmod 666 certs/server.key certs/server.crt
else
    print_success "Using existing SSL certificates (certs/server.key, certs/server.crt)"
fi

# Install required packages
REQUIRED_PACKAGES=("paramiko" "flask")
print_status "Checking and installing required packages..."
for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! check_package "$package"; then
        print_status "Installing $package..."
        pip install "$package"
    else
        print_success "$package already installed"
    fi
done

# Start services
print_status "Starting Unified Honeypot..."
python3 unified_honeypot.py &
sleep 2

print_status "Starting Dashboard..."
export FLASK_RUN_PORT=5001
python3 unified_dashboard.py &
sleep 2

print_success "All services started successfully!"

# Display service information
print_status "Network Information:"
echo "----------------------------------------"
echo "Internal IP: $(hostname -I | awk '{print $1}')"
echo -e "\nServices running on:"
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):5001"
echo "SSH:      ssh -p 2222 user@$(hostname -I | awk '{print $1}')"
echo "HTTP:     http://$(hostname -I | awk '{print $1}'):8080"
echo "HTTPS:    https://$(hostname -I | awk '{print $1}'):8443"
echo "FTP:      ftp -P 2121 $(hostname -I | awk '{print $1}')"
echo "MySQL:    mysql -h $(hostname -I | awk '{print $1}') -P 3306"
echo "----------------------------------------"

# Test the honeypot services
print_status "Running tests..."
sleep 5  # Wait for services to fully start
test_honeypot

print_status "Honeypot is running and ready for connections"
print_status "Press Ctrl+C to stop all services"

# Keep the script running
while true; do
    sleep 1
done
