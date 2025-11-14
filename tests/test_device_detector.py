"""Tests for device_detector module"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from device_detector import DeviceDetector


def test_ssh_client_detection():
    """Test SSH client detection"""
    assert 'OpenSSH' in DeviceDetector.detect_device('SSH-2.0-OpenSSH_8.2', 'ssh')
    assert 'PuTTY' in DeviceDetector.detect_device('SSH-2.0-PuTTY_Release_0.76', 'ssh')
    assert 'WinSCP' in DeviceDetector.detect_device('SSH-2.0-WinSCP_release_5.17', 'ssh')


def test_http_user_agent_detection():
    """Test HTTP User-Agent detection"""
    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/96.0.4664.110'
    result = DeviceDetector.detect_device(ua, 'http')
    assert 'Chrome' in result
    assert 'Windows' in result


def test_ftp_client_detection():
    """Test FTP client detection"""
    assert 'FileZilla' in DeviceDetector.detect_device('FileZilla/3.50.0', 'ftp')
    assert 'curl' in DeviceDetector.detect_device('curl/7.68.0', 'ftp')


def test_mysql_client_detection():
    """Test MySQL client detection"""
    assert 'MySQL' in DeviceDetector.detect_device('mysql client', 'mysql')
    assert 'HeidiSQL' in DeviceDetector.detect_device('HeidiSQL', 'mysql')


def test_unknown_device():
    """Test unknown device detection"""
    result = DeviceDetector.detect_device('random-string', 'ssh')
    assert 'Unknown' in result
