# All Honeypot Services - Public Access

## 🌐 Complete Service List

All honeypot services are **PUBLICLY ACCESSIBLE** and ready to accept connections from anywhere.

---

## 🔐 SSH Honeypot (Port 2222)

**Connection:**
```bash
ssh -p 2222 admin@YOUR_PUBLIC_IP
```

**Example:**
```bash
ssh -p 2222 admin@10.0.2.15
```

**Credentials:**
- Username: `admin`
- Password: **ANY** (all passwords work!)

**Features:**
- Full SSH server simulation
- Interactive shell simulation
- Command execution logging
- Persistent host keys

---

## 🌐 HTTP Honeypot (Port 8080)

**Connection:**
```
http://YOUR_PUBLIC_IP:8080
```

**Example:**
```
http://10.0.2.15:8080
```

**Access:**
- Open in any web browser
- No credentials needed
- Simulates realistic web server
- Login form simulation

**Features:**
- Realistic web server responses
- Request logging and analysis
- Attack pattern detection

---

## 🔒 HTTPS Honeypot (Port 8443)

**Connection:**
```
https://YOUR_PUBLIC_IP:8443
```

**Example:**
```
https://10.0.2.15:8443
```

**Access:**
- Open in any web browser
- No credentials needed
- SSL/TLS encryption
- **Note:** Browser will show SSL warning (normal - self-signed certificate)

**Features:**
- SSL/TLS encryption
- Realistic web server responses
- Request logging and analysis
- Attack pattern detection

---

## 📁 FTP Honeypot (Port 2121)

**Connection:**
```bash
ftp -P 2121 YOUR_PUBLIC_IP
```

**Example:**
```bash
ftp -P 2121 10.0.2.15
```

**Using FTP Client (FileZilla, WinSCP, etc.):**
- Host: `YOUR_PUBLIC_IP`
- Port: `2121`
- Username: **ANY** (all usernames accepted)
- Password: **ANY** (all passwords accepted)

**Features:**
- Standard FTP protocol simulation
- Authentication tracking
- Connection logging

---

## 🗄️ MySQL Honeypot (Port 3306)

**Connection:**
```bash
mysql -h YOUR_PUBLIC_IP -P 3306
```

**Example:**
```bash
mysql -h 10.0.2.15 -P 3306
```

**Using MySQL Client (MySQL Workbench, phpMyAdmin, etc.):**
- Host: `YOUR_PUBLIC_IP`
- Port: `3306`
- Username: **ANY** (all usernames accepted)
- Password: **ANY** (all passwords accepted)

**Features:**
- Database server simulation
- SQL injection detection
- Connection attempt logging

---

## 📊 Dashboard (Port 5001)

**Connection:**
```
http://YOUR_PUBLIC_IP:5001
```

**Example:**
```
http://10.0.2.15:5001
```

**Credentials:**
- Username: `admin` (or configured username)
- Password: (ask owner for password)

**Features:**
- Real-time attack monitoring
- Interactive world map
- Statistics and charts
- Alert notifications
- Data export

---

## 📋 Quick Reference

| Service | Port | Command/URL | Credentials |
|---------|------|-------------|-------------|
| **SSH** | 2222 | `ssh -p 2222 admin@IP` | admin / ANY |
| **HTTP** | 8080 | `http://IP:8080` | None needed |
| **HTTPS** | 8443 | `https://IP:8443` | None needed |
| **FTP** | 2121 | `ftp -P 2121 IP` | ANY / ANY |
| **MySQL** | 3306 | `mysql -h IP -P 3306` | ANY / ANY |
| **Dashboard** | 5001 | `http://IP:5001` | admin / (ask owner) |

---

## 🔧 Connection Examples

### From Windows:

**SSH:**
```cmd
ssh -p 2222 admin@10.0.2.15
```

**HTTP/HTTPS:**
- Open browser: `http://10.0.2.15:8080`
- Open browser: `https://10.0.2.15:8443`

**FTP:**
```cmd
ftp -P 2121 10.0.2.15
```

**MySQL:**
```cmd
mysql -h 10.0.2.15 -P 3306
```

### From Linux/Mac:

**SSH:**
```bash
ssh -p 2222 admin@10.0.2.15
```

**HTTP/HTTPS:**
```bash
curl http://10.0.2.15:8080
curl -k https://10.0.2.15:8443  # -k ignores SSL certificate
```

**FTP:**
```bash
ftp -P 2121 10.0.2.15
```

**MySQL:**
```bash
mysql -h 10.0.2.15 -P 3306
```

---

## ⚠️ Important Notes

1. **All services are PUBLIC** - Accessible from the internet
2. **Firewall Configuration** - Make sure ports are open in Windows Firewall
3. **Router Port Forwarding** - Configure if behind router
4. **SSL Warnings** - HTTPS will show certificate warning (normal for self-signed)
5. **Any Credentials Work** - SSH, FTP, and MySQL accept any username/password
6. **All Connections Logged** - Every connection attempt is logged and monitored

---

## 🛡️ Security Reminders

- This is a **HONEYPOT** - designed to attract attackers
- Do **NOT** use on production systems
- Monitor logs regularly
- All connections are logged for analysis
- Use firewall rules to restrict access if needed

---

## 📞 Need Help?

See detailed guides:
- `CONNECTION_GUIDE.md` - Complete connection instructions
- `SECURITY_SETUP.md` - Security configuration
- `SHARE_THIS.txt` - Quick shareable instructions

