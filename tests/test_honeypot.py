"""Tests for honeypot functionality"""
import sys
import os
import tempfile
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unified_honeypot import FakeFileSystem, UnifiedHoneypotServer


def test_fake_filesystem_navigation():
    """Test fake filesystem navigation"""
    fs = FakeFileSystem()
    
    # Test initial directory
    assert fs.current_dir == '/home/admin'
    
    # Test directory listing
    items = fs.list_directory('.')
    assert items is not None
    assert 'Documents/' in items
    assert '.bashrc' in items
    
    # Test change directory
    assert fs.change_directory('Documents')
    assert fs.current_dir == '/home/admin/Documents'
    
    # Test go to home
    assert fs.change_directory('~')
    assert fs.current_dir == '/home/admin'


def test_fake_filesystem_file_reading():
    """Test fake filesystem file reading"""
    fs = FakeFileSystem()
    
    # Read a file
    content = fs.read_file('.bashrc')
    assert content is not None
    assert 'bash' in content.lower()
    
    # Test non-existent file
    content = fs.read_file('nonexistent.txt')
    assert content is None


def test_honeypot_config_loading(tmp_path):
    """Test honeypot configuration loading"""
    os.chdir(tmp_path)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    
    # Create SSH keys directory
    ssh_dir = tmp_path / "ssh_keys"
    ssh_dir.mkdir()
    
    # Create certs directory
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    
    # Create logs directory
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    
    config_file = config_dir / "unified_honeypot.json"
    config = {
        'ssh_port': 2222,
        'http_port': 8080,
        'https_port': 8443,
        'ftp_port': 2121,
        'mysql_port': 3306,
        'log_dir': 'logs',
        'ssh_key_dir': 'ssh_keys',
        'cert_dir': 'certs',
        'pcap_dir': 'pcaps',
        'pcap_enabled': False,  # Disable for testing
        'initial_payload_max_bytes': 512,
        'banners': {
            'ssh_version': 'SSH-2.0-OpenSSH_7.4',
            'http_server': 'Apache/2.4.41 (Ubuntu)'
        }
    }
    
    with open(config_file, 'w') as f:
        json.dump(config, f)
    
    server = UnifiedHoneypotServer(config_file=str(config_file))
    
    assert server.config['ssh_port'] == 2222
    assert server.config['pcap_enabled'] is False
    assert 'banners' in server.config


def test_tool_detection():
    """Test attack tool detection"""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chdir(tmpdir)
        
        # Create required directories
        for d in ['config', 'logs', 'ssh_keys', 'certs', 'pcaps']:
            os.makedirs(d, exist_ok=True)
        
        config_file = os.path.join('config', 'test_config.json')
        config = {
            'ssh_port': 2222,
            'http_port': 8080,
            'https_port': 8443,
            'ftp_port': 2121,
            'mysql_port': 3306,
            'log_dir': 'logs',
            'ssh_key_dir': 'ssh_keys',
            'cert_dir': 'certs',
            'pcap_dir': 'pcaps',
            'pcap_enabled': False
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f)
        
        server = UnifiedHoneypotServer(config_file=config_file)
        
        # Test nmap detection
        data = "GET / HTTP/1.1\r\nUser-Agent: Nmap Scripting Engine\r\n"
        tools = server.detect_tools(data)
        assert 'nmap' in tools
        
        # Test sqlmap detection
        data = "POST /login HTTP/1.1\r\nUser-Agent: sqlmap/1.5\r\n"
        tools = server.detect_tools(data)
        assert 'sqlmap' in tools
        
        # Test hydra detection
        data = "hydra attempting login combination"
        tools = server.detect_tools(data)
        assert 'hydra' in tools
