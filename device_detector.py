class DeviceDetector:
    @staticmethod
    def detect_device(data, service_type='unknown'):
        """
        Detects device information from various service data
        Args:
            data (str): String containing client information
            service_type (str): Type of service ('ssh', 'http', 'https', 'ftp', 'mysql')
        Returns:
            str: Device name and version
        """
        data_str = str(data)
        device_name = "Unknown Device"

        if service_type == 'ssh':
            # SSH client detection
            if 'OpenSSH' in data_str:
                parts = data_str.split('_')
                if len(parts) >= 2 and parts[1]:
                    device_name = f"OpenSSH {parts[1]}"
            elif 'PuTTY' in data_str:
                device_name = "PuTTY Client"
            elif 'WinSCP' in data_str:
                device_name = "WinSCP"
            elif 'Bitvise' in data_str:
                device_name = "Bitvise SSH Client"

        elif service_type in ['http', 'https']:
            # Web client detection
            if 'User-Agent:' in data_str:
                ua_line = [line for line in data_str.split('\\r\\n') if 'User-Agent:' in line]
                if ua_line:
                    ua = ua_line[0].split('User-Agent:', 1)[1].strip()
                    device_name = DeviceDetector._parse_user_agent(ua)

        elif service_type == 'ftp':
            # FTP client detection
            if 'FileZilla' in data_str:
                device_name = "FileZilla FTP Client"
            elif 'WinSCP' in data_str:
                device_name = "WinSCP"
            elif 'curl' in data_str.lower():
                device_name = "curl FTP"

        elif service_type == 'mysql':
            # MySQL client detection
            if 'mysql' in data_str.lower():
                device_name = "MySQL Client"
            elif 'HeidiSQL' in data_str:
                device_name = "HeidiSQL"
            elif 'DBeaver' in data_str:
                device_name = "DBeaver"

        return device_name

    @staticmethod
    def _parse_user_agent(ua):
        """Parse User-Agent string to extract device information"""
        device_name = "Unknown Browser"
        
        # Browser detection with bounds checking
        if 'Firefox/' in ua:
            parts = ua.split('Firefox/')
            if len(parts) > 1 and parts[1]:
                version = parts[1].split()[0] if parts[1].split() else 'Unknown'
                device_name = f"Firefox {version}"
        elif 'Chrome/' in ua:
            parts = ua.split('Chrome/')
            if len(parts) > 1 and parts[1]:
                version = parts[1].split()[0] if parts[1].split() else 'Unknown'
                device_name = f"Chrome {version}"
        elif 'Safari/' in ua and 'Chrome/' not in ua:  # Safari check after Chrome
            if 'Version/' in ua:
                parts = ua.split('Version/')
                if len(parts) > 1 and parts[1]:
                    version = parts[1].split()[0] if parts[1].split() else 'Unknown'
                    device_name = f"Safari {version}"
            else:
                parts = ua.split('Safari/')
                if len(parts) > 1 and parts[1]:
                    version = parts[1].split()[0] if parts[1].split() else 'Unknown'
                    device_name = f"Safari {version}"
        elif 'Edge/' in ua:
            parts = ua.split('Edge/')
            if len(parts) > 1 and parts[1]:
                version = parts[1].split()[0] if parts[1].split() else 'Unknown'
                device_name = f"Edge {version}"
        elif 'OPR/' in ua:
            parts = ua.split('OPR/')
            if len(parts) > 1 and parts[1]:
                version = parts[1].split()[0] if parts[1].split() else 'Unknown'
                device_name = f"Opera {version}"
        elif 'Opera/' in ua:
            parts = ua.split('Opera/')
            if len(parts) > 1 and parts[1]:
                version = parts[1].split()[0] if parts[1].split() else 'Unknown'
                device_name = f"Opera {version}"
        elif 'curl/' in ua.lower():
            parts = ua.lower().split('curl/')
            if len(parts) > 1 and parts[1]:
                version = parts[1].split()[0] if parts[1].split() else 'Unknown'
                device_name = f"curl {version}"
        elif 'Postman' in ua:
            device_name = "Postman"
        elif 'wget/' in ua.lower():
            parts = ua.lower().split('wget/')
            if len(parts) > 1 and parts[1]:
                version = parts[1].split()[0] if parts[1].split() else 'Unknown'
                device_name = f"wget {version}"
        
        # OS detection
        os_name = None
        if 'Windows' in ua:
            os_name = "Windows"
        elif 'Mac OS X' in ua:
            os_name = "macOS"
        elif 'Linux' in ua:
            os_name = "Linux"
        elif 'Android' in ua:
            os_name = "Android"
        elif 'iOS' in ua:
            os_name = "iOS"
        
        # Combine browser and OS info
        if os_name and device_name != "Unknown Browser":
            device_name = f"{device_name} ({os_name})"
            
        return device_name