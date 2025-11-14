# Connection Guide - How Others Can Connect to Your SSH Honeypot

## 🔍 Step 1: Find Your Public IP Address

### For You (Honeypot Owner):

**Windows PowerShell:**
```powershell
(Invoke-WebRequest -Uri "https://ifconfig.me" -UseBasicParsing).Content.Trim()
```

**Command Prompt:**
```cmd
curl ifconfig.me
```

**Or visit these websites:**
- https://whatismyipaddress.com/
- https://ifconfig.me
- https://icanhazip.com

**Note your Public IP:** `YOUR_PUBLIC_IP` (example: `203.0.113.45`)

---

## 📡 Step 2: Configure Your Firewall (IMPORTANT!)

### Windows Firewall - Allow Incoming Connections

**Allow SSH Honeypot Port (2222):**
```powershell
# Run PowerShell as Administrator
New-NetFirewallRule -DisplayName "SSH Honeypot" -Direction Inbound -LocalPort 2222 -Protocol TCP -Action Allow

# Allow Dashboard Port (5001)
New-NetFirewallRule -DisplayName "Honeypot Dashboard" -Direction Inbound -LocalPort 5001 -Protocol TCP -Action Allow

# Allow HTTP/HTTPS Honeypot Ports
New-NetFirewallRule -DisplayName "HTTP Honeypot" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "HTTPS Honeypot" -Direction Inbound -LocalPort 8443 -Protocol TCP -Action Allow
```

**Or use Windows Firewall GUI:**
1. Open "Windows Defender Firewall with Advanced Security"
2. Click "Inbound Rules" → "New Rule"
3. Select "Port" → Next
4. Select "TCP" → Enter port `2222` → Next
5. Select "Allow the connection" → Next
6. Check all profiles → Next
7. Name: "SSH Honeypot" → Finish

### Router Configuration (Port Forwarding)

**If you're behind a router, you need to forward ports:**

1. **Access Router Admin Panel:**
   - Open browser → Go to `http://192.168.1.1` (or check router label)
   - Login with admin credentials

2. **Find Port Forwarding/Virtual Server:**
   - Look for "Port Forwarding", "Virtual Server", or "NAT"
   - Usually under "Advanced" or "Firewall" section

3. **Add Port Forwarding Rules:**
   ```
   Service Name: SSH Honeypot
   External Port: 2222
   Internal Port: 2222
   Internal IP: [Your computer's local IP, e.g., 192.168.1.100]
   Protocol: TCP
   
   Service Name: Honeypot Dashboard
   External Port: 5001
   Internal Port: 5001
   Internal IP: [Your computer's local IP]
   Protocol: TCP
   ```

4. **Find Your Local IP:**
   ```powershell
   ipconfig
   # Look for "IPv4 Address" under your active network adapter
   # Example: 192.168.1.100
   ```

5. **Save and Restart Router** (if needed)

---

## 🌐 Step 3: Share Connection Information

### Information to Share with Others:

**SSH Honeypot:**
```
Host: YOUR_PUBLIC_IP
Port: 2222
Username: admin
Password: ANY (all passwords work!)
```

**HTTP Honeypot:**
```
URL: http://YOUR_PUBLIC_IP:8080
Example: http://10.0.2.15:8080
Open in web browser - no credentials needed
```

**HTTPS Honeypot:**
```
URL: https://YOUR_PUBLIC_IP:8443
Example: https://10.0.2.15:8443
Open in web browser - SSL certificate warning is normal (self-signed)
```

**FTP Honeypot:**
```
Command: ftp -P 2121 YOUR_PUBLIC_IP
Example: ftp -P 2121 10.0.2.15

Or use FTP client:
  Host: YOUR_PUBLIC_IP
  Port: 2121
  Username: (any)
  Password: (any)
```

**MySQL Honeypot:**
```
Command: mysql -h YOUR_PUBLIC_IP -P 3306
Example: mysql -h 10.0.2.15 -P 3306

Or use MySQL client:
  Host: YOUR_PUBLIC_IP
  Port: 3306
  Username: (any)
  Password: (any)
```

**Dashboard:**
```
URL: http://YOUR_PUBLIC_IP:5001
Username: admin (or check app.py for your credentials)
Password: [your dashboard password]
```

---

## 💻 Step 4: How Others Can Connect

### From Different State/Location:

#### **Option 1: SSH Connection (Command Line)**

**Windows (PowerShell/CMD):**
```cmd
ssh -p 2222 admin@YOUR_PUBLIC_IP
```

**Linux/Mac:**
```bash
ssh -p 2222 admin@YOUR_PUBLIC_IP
```

**Example:**
```bash
ssh -p 2222 admin@203.0.113.45
```

#### **Option 2: Using SSH Client (GUI)**

**Windows - PuTTY:**
1. Download PuTTY: https://www.putty.org/
2. Open PuTTY
3. Enter:
   - Host: `YOUR_PUBLIC_IP`
   - Port: `2222`
   - Connection Type: SSH
4. Click "Open"
5. Login: `admin`
6. Password: `Honeypot@XXXXX`

**Windows - Windows Terminal/Command Prompt:**
```cmd
ssh -p 2222 admin@YOUR_PUBLIC_IP
```

**Mac/Linux - Terminal:**
```bash
ssh -p 2222 admin@YOUR_PUBLIC_IP
```

#### **Option 3: HTTP/HTTPS Honeypot Access (Web Browser)**

**HTTP Honeypot:**
```
http://YOUR_PUBLIC_IP:8080
```
Example: `http://10.0.2.15:8080`

**HTTPS Honeypot:**
```
https://YOUR_PUBLIC_IP:8443
```
Example: `https://10.0.2.15:8443`

**Features:**
- Open in any web browser
- Simulates realistic web server with login forms
- SSL/TLS encryption (HTTPS)
- All requests logged and analyzed
- No credentials needed to access
- Browser may show SSL warning (normal - self-signed certificate)

#### **Option 4: FTP Honeypot Access**

**Command Line:**
```bash
ftp -P 2121 YOUR_PUBLIC_IP
```

Example: `ftp -P 2121 10.0.2.15`

**Using FTP Client (FileZilla, WinSCP, etc.):**
- Host: `YOUR_PUBLIC_IP`
- Port: `2121`
- Username: Any (all usernames accepted)
- Password: Any (all passwords accepted)

#### **Option 5: MySQL Honeypot Access**

**Command Line:**
```bash
mysql -h YOUR_PUBLIC_IP -P 3306
```

Example: `mysql -h 10.0.2.15 -P 3306`

**Using MySQL Client (MySQL Workbench, phpMyAdmin, etc.):**
- Host: `YOUR_PUBLIC_IP`
- Port: `3306`
- Username: Any (all usernames accepted)
- Password: Any (all passwords accepted)

#### **Option 6: Dashboard Access (Web Browser)**

Anyone can access your dashboard:
```
http://YOUR_PUBLIC_IP:5001
```

Example: `http://203.0.113.45:5001`

---

## 🔑 Step 5: SSH Password Information

**✅ Easy Connection:** SSH now accepts **ANY password** for the `admin` user!

**How to Connect:**
```bash
ssh -p 2222 admin@YOUR_PUBLIC_IP
```

**When prompted for password:**
- Enter **ANY password** - all passwords are accepted!
- Examples: `password`, `123`, `admin`, `test`, etc.
- No need to ask for or share passwords!

**Authentication:**
- **Username:** `admin` (required)
- **Password:** ANY (doesn't matter what you enter)

---

## 🔧 Step 6: Troubleshooting

### Connection Issues?

#### **"Connection Refused" or "Connection Timeout"**

**Check 1: Is Honeypot Running?**
```powershell
# Check if Python is running
Get-Process python

# Check if port is listening
netstat -ano | findstr :2222
```

**Check 2: Windows Firewall**
```powershell
# Check firewall rules
Get-NetFirewallRule -DisplayName "*Honeypot*"

# If not found, add rules (see Step 2 above)
```

**Check 3: Router Port Forwarding**
- Verify port forwarding is configured
- Check internal IP matches your computer's IP
- Try restarting router

**Check 4: ISP/Internet Provider**
- Some ISPs block incoming connections
- Check if you have a static or dynamic IP
- Some ISPs require you to request port unblocking

**Check 5: Antivirus/Firewall Software**
- Disable antivirus temporarily to test
- Check if third-party firewall is blocking

#### **"Permission Denied" or Authentication Issues**

**Check Password:**
- SSH accepts ANY password for `admin` user
- Make sure username is `admin`
- Any password will work - try again if connection fails

**Check Username:**
- Default username is: `admin`
- Make sure username is correct

#### **Test Connection from Your Own Network First:**

**Test locally before sharing:**
```cmd
# From your computer (localhost)
ssh -p 2222 admin@127.0.0.1

# From another device on same network
ssh -p 2222 admin@192.168.1.100  # Your local IP
```

If local connection works but external doesn't → Router/Firewall issue

---

## 📋 Quick Reference Card for Others

**Share this with people who want to connect:**

```
=== SSH Honeypot Connection ===

Command:
  ssh -p 2222 admin@YOUR_PUBLIC_IP

Username: admin
Password: ANY (enter any password - all passwords work!)

=== HTTP/HTTPS Honeypot Access ===

HTTP:
  http://YOUR_PUBLIC_IP:8080
  Example: http://10.0.2.15:8080

HTTPS:
  https://YOUR_PUBLIC_IP:8443
  Example: https://10.0.2.15:8443

Open in web browser - no credentials needed!

=== FTP Honeypot Connection ===

Command:
  ftp -P 2121 YOUR_PUBLIC_IP

Example:
  ftp -P 2121 10.0.2.15

Username: ANY
Password: ANY

=== MySQL Honeypot Connection ===

Command:
  mysql -h YOUR_PUBLIC_IP -P 3306

Example:
  mysql -h 10.0.2.15 -P 3306

Username: ANY
Password: ANY

=== Dashboard Access ===

URL: http://YOUR_PUBLIC_IP:5001
Username: admin
Password: [ask owner]

=== Troubleshooting ===

If connection fails:
1. Verify YOUR_PUBLIC_IP is correct
2. Check if honeypot is running
3. Ask owner to check firewall/router settings
4. Make sure username is "admin" (password can be anything)
5. For HTTPS, ignore SSL certificate warning (self-signed is normal)
```

---

## 🎯 Testing Connection

### Test from Different Locations:

**Test 1: Same Network (Local)**
```cmd
ssh -p 2222 admin@192.168.1.100  # Your local IP
```

**Test 2: Different Network (Internet)**
```cmd
ssh -p 2222 admin@YOUR_PUBLIC_IP
```

**Test 3: Using Online Tools**
- Visit: https://www.yougetsignal.com/tools/open-ports/
- Enter your public IP and port 2222
- Click "Check" to verify port is open

---

## ⚠️ Important Notes

1. **Dynamic IP:** If your IP changes (dynamic IP), you'll need to share new IP each time
   - Solution: Use Dynamic DNS (DDNS) service (e.g., No-IP, DuckDNS)

2. **ISP Restrictions:** Some ISPs block incoming connections on residential connections
   - Business connections usually allow it
   - Contact ISP if blocked

3. **Security:** Remember, this is a HONEYPOT designed to attract attackers
   - Don't use production systems
   - Monitor logs regularly
   - Change dashboard password

4. **Bandwidth:** Honeypots can attract heavy traffic
   - Monitor bandwidth usage
   - Be prepared for potential DDoS

---

## 📞 Quick Setup Checklist

- [ ] Honeypot is running (`python unified_honeypot.py`)
- [ ] Found your public IP address
- [ ] Windows Firewall allows port 2222 (inbound)
- [ ] Router port forwarding configured (if behind router)
- [ ] Tested local connection (works)
- [ ] Tested external connection (works)
- [ ] Shared connection info with others
- [ ] Dashboard accessible at http://YOUR_PUBLIC_IP:5001

---

## 🔗 Useful Commands Reference

**Find Public IP:**
```powershell
(Invoke-WebRequest -Uri "https://ifconfig.me" -UseBasicParsing).Content.Trim()
```

**Check if Port is Listening:**
```powershell
netstat -ano | findstr :2222
```

**Check Firewall Rules:**
```powershell
Get-NetFirewallRule -DisplayName "*Honeypot*"
```

**Allow Port in Firewall:**
```powershell
New-NetFirewallRule -DisplayName "SSH Honeypot" -Direction Inbound -LocalPort 2222 -Protocol TCP -Action Allow
```

---

**Need Help?** Check logs in `logs/unified_honeypot.log` for connection attempts and errors.

