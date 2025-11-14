# VirtualBox Network Setup for Honeypot

## Option 1: Host-Only Network (Recommended - No WiFi Needed)

### Step 1: Create Host-Only Adapter in VirtualBox
1. Open VirtualBox Manager
2. Go to **File → Host Network Manager**
3. Click **Create** to create a new host-only adapter
4. Note the IP range (usually `192.168.56.1/24`)
5. Click **OK**

### Step 2: Configure VM Network
1. Right-click your Kali Linux VM
2. Go to **Settings → Network**
3. **Adapter 1**: Enable **Host-Only Adapter**
4. Select the adapter you just created (usually `VirtualBox Host-Only Ethernet Adapter`)
5. Click **OK**

### Step 3: Configure Kali Linux Network
In your Kali Linux VM terminal:
```bash
# Check available network interfaces
ip addr show

# Configure the host-only interface (usually eth1 or enp0s8)
sudo ip addr add 192.168.56.10/24 dev eth1
sudo ip link set eth1 up

# Or use DHCP (if VirtualBox DHCP is enabled)
sudo dhclient eth1

# Check IP address
ip addr show eth1
```

### Step 4: Connect from Windows Host
From your Windows machine:
```powershell
ssh -p 2222 admin@192.168.56.10
```

---

## Option 2: NAT with Port Forwarding

### Step 1: Configure VM Network
1. Right-click your Kali Linux VM
2. Go to **Settings → Network**
3. **Adapter 1**: Enable **NAT**
4. Click **Advanced → Port Forwarding**
5. Add rule:
   - **Name**: SSH Honeypot
   - **Protocol**: TCP
   - **Host IP**: 127.0.0.1
   - **Host Port**: 2222
   - **Guest IP**: (leave empty)
   - **Guest Port**: 2222
6. Click **OK**

### Step 2: Connect from Windows Host
```powershell
ssh -p 2222 admin@127.0.0.1
```

---

## Option 3: Internal Network (VM to VM)

### Step 1: Configure VM Network
1. Right-click your Kali Linux VM
2. Go to **Settings → Network**
3. **Adapter 1**: Enable **Internal Network**
4. Name: `honeypot-network` (or any name)
5. Click **OK**

### Step 2: Configure IP in Kali
```bash
sudo ip addr add 192.168.100.10/24 dev eth0
sudo ip link set eth0 up
```

### Step 3: Connect from Another VM
If you have another VM on the same internal network:
```bash
ssh -p 2222 admin@192.168.100.10
```

---

## Quick Check Script for Kali Linux

Create this script in your Kali VM to check network status:

```bash
#!/bin/bash
echo "=== Network Interfaces ==="
ip addr show

echo ""
echo "=== SSH Service Status ==="
systemctl status ssh 2>/dev/null || netstat -tlnp | grep 2222

echo ""
echo "=== Honeypot Process ==="
ps aux | grep -E "unified_honeypot|python.*honeypot" | grep -v grep

echo ""
echo "=== Connection Test ==="
echo "From Windows host, use:"
echo "  ssh -p 2222 admin@<KALI_IP>"
```

---

## Troubleshooting

### Check if honeypot is running in Kali:
```bash
# Check if port 2222 is listening
sudo netstat -tlnp | grep 2222

# Check honeypot process
ps aux | grep unified_honeypot

# Check logs
tail -f logs/unified_honeypot.log
```

### Check network connectivity from Windows:
```powershell
# Ping the VM
ping 192.168.56.10

# Test SSH port
Test-NetConnection -ComputerName 192.168.56.10 -Port 2222
```

### Common Issues:
1. **Can't ping VM**: Check VirtualBox network adapter settings
2. **Port 2222 not accessible**: Check firewall in Kali Linux
3. **Connection refused**: Honeypot might not be running

