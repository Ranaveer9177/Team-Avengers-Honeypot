# Security Configuration Guide

## ⚠️ IMPORTANT WARNING

By default, the honeypot binds to `0.0.0.0`, which makes it accessible from **ANYWHERE** if your machine has a public IP address.

## 🔒 Option 1: Make Honeypot Local-Only (RECOMMENDED)

### Change Network Binding to Localhost

**Edit `unified_honeypot.py`:**
```python
# Line 962 - Change from:
server_socket.bind(('0.0.0.0', port))
# To:
server_socket.bind(('127.0.0.1', port))  # Localhost only
```

**Edit `app.py`:**
```python
# Line 1003 - Change from:
app.run(host='0.0.0.0', port=FLASK_RUN_PORT, debug=False, threaded=True)
# To:
app.run(host='127.0.0.1', port=FLASK_RUN_PORT, debug=False, threaded=True)  # Localhost only
```

### Result:
- ✅ Only accessible from your local machine
- ✅ No one from internet can connect
- ✅ Safe for testing and development

---

## 🛡️ Option 2: Use Firewall Rules (For Public Honeypot)

If you want to keep it public but restrict access:

### Windows Firewall:
```powershell
# Allow only from specific IP (e.g., your home IP: 203.0.113.1)
New-NetFirewallRule -DisplayName "SSH Honeypot" -Direction Inbound -LocalPort 2222 -Protocol TCP -RemoteAddress 203.0.113.1 -Action Allow

# Block all other access
New-NetFirewallRule -DisplayName "SSH Honeypot Block" -Direction Inbound -LocalPort 2222 -Protocol TCP -Action Block
```

### Linux Firewall (iptables):
```bash
# Allow only from specific IP
sudo iptables -A INPUT -p tcp --dport 2222 -s 203.0.113.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 2222 -j DROP

# For dashboard (port 5001)
sudo iptables -A INPUT -p tcp --dport 5001 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5001 -j DROP
```

### Linux Firewall (ufw):
```bash
# Allow only from specific IP
sudo ufw allow from 203.0.113.1 to any port 2222
sudo ufw deny 2222

# Dashboard local only
sudo ufw allow from 127.0.0.1 to any port 5001
sudo ufw deny 5001
```

---

## 🔐 Option 3: VPN-Only Access

1. Set up a VPN server
2. Connect clients through VPN
3. Bind honeypot to VPN interface IP only

### Example (WireGuard VPN):
```python
# Bind to VPN interface IP (e.g., 10.0.0.1)
server_socket.bind(('10.0.0.1', port))
```

---

## 🌐 Option 4: Specific Network Interface

Bind to a specific network interface IP:

### Find Your Network Interface:
**Windows:**
```powershell
ipconfig
# Note the IP address of your desired interface (e.g., 192.168.1.100)
```

**Linux:**
```bash
ip addr show
# Note the IP address of your desired interface (e.g., 192.168.1.100)
```

### Edit Code:
```python
# Bind to specific IP address
server_socket.bind(('192.168.1.100', port))
```

---

## 📊 Current Configuration Check

### Check What's Listening:
**Windows:**
```powershell
netstat -ano | findstr :2222
netstat -ano | findstr :5001
```

**Linux:**
```bash
sudo netstat -tlnp | grep :2222
sudo netstat -tlnp | grep :5001
```

### Check Your Public IP:
```bash
curl ifconfig.me
# or visit: https://whatismyipaddress.com/
```

---

## ⚠️ Security Recommendations

1. **Dashboard Security:**
   - ✅ Change default password in `app.py`
   - ✅ Use HTTPS (not HTTP) for dashboard
   - ✅ Bind dashboard to `127.0.0.1` only
   - ✅ Use SSH tunneling: `ssh -L 5001:127.0.0.1:5001 user@server`

2. **Honeypot Security:**
   - ✅ Use firewall to restrict access
   - ✅ Monitor logs for suspicious activity
   - ✅ Don't run on production systems
   - ✅ Isolate honeypot on separate network segment

3. **Network Isolation:**
   - ✅ Use separate VLAN for honeypot
   - ✅ Use VirtualBox Host-Only network (for VM)
   - ✅ Don't expose honeypot on same network as production

---

## 🔧 Quick Fix: Make Everything Local-Only

Run this script to change all bindings to localhost:

**Windows:**
```powershell
# PowerShell script to change 0.0.0.0 to 127.0.0.1
(Get-Content unified_honeypot.py) -replace "bind\(('0\.0\.0\.0'|`"0\.0\.0\.0`")", "bind(('127.0.0.1'" | Set-Content unified_honeypot.py
(Get-Content app.py) -replace "host='0\.0\.0\.0'", "host='127.0.0.1'" | Set-Content app.py
```

**Linux/Mac:**
```bash
sed -i "s/bind(('0\.0\.0\.0'/bind(('127.0.0.1'/g" unified_honeypot.py
sed -i "s/host='0\.0\.0\.0'/host='127.0.0.1'/g" app.py
```

---

## ✅ Verification

After making changes, verify the binding:

1. Start honeypot
2. Check what's listening:
   ```bash
   # Should show 127.0.0.1:2222 (not 0.0.0.0:2222)
   netstat -ano | findstr :2222  # Windows
   netstat -tlnp | grep :2222    # Linux
   ```
3. Try connecting from another machine (should fail)
4. Try connecting from localhost (should work)

---

## 🆘 Need Help?

- **Isolation**: Use VirtualBox Host-Only network (see `VIRTUALBOX_NETWORK_SETUP.md`)
- **VPN**: Set up WireGuard or OpenVPN
- **Firewall**: Use Windows Firewall or Linux iptables/ufw
- **SSH Tunnel**: Access dashboard securely via SSH tunnel

---

**Remember:** A honeypot is DESIGNED to attract attackers, but you should control WHO can access it!

