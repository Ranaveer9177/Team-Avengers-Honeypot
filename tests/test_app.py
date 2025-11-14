"""Tests for Flask dashboard application"""
import sys
import os
import tempfile
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import sanitize_string, process_attack_data, get_statistics
from datetime import datetime, timezone


def test_sanitize_string():
    """Test string sanitization"""
    # Test XSS prevention
    result = sanitize_string('<script>alert("xss")</script>')
    assert '&lt;script&gt;' in result
    assert '<script>' not in result
    
    # Test truncation
    long_string = 'a' * 300
    result = sanitize_string(long_string, max_length=100)
    assert len(result) <= 103  # 100 + '...'
    assert result.endswith('...')
    
    # Test None handling
    result = sanitize_string(None)
    assert result == ''


def test_process_attack_data():
    """Test attack data processing"""
    now = datetime.now(timezone.utc).isoformat()
    attacks = [{
        'timestamp': now,
        'ip': '192.168.1.100',
        'device_name': 'Test Device',
        'service': 'ssh',
        'attack_type': 'brute_force',
        'tools_detected': ['hydra', 'nmap'],
        'username': 'admin',
        'password': 'test123'
    }]
    
    processed = process_attack_data(attacks)
    
    assert len(processed) == 1
    assert processed[0]['ip'] == '192.168.1.100'
    assert processed[0]['service'] == 'ssh'
    assert 'hydra' in processed[0]['tools_detected']
    assert processed[0]['username'] == 'admin'


def test_get_statistics():
    """Test statistics generation"""
    now = datetime.now(timezone.utc).isoformat()
    attacks = [
        {
            'timestamp': now,
            'ip': '192.168.1.100',
            'service': 'ssh',
            'attack_type': 'brute_force',
            'tools_detected': 'hydra',
            'username': 'admin'
        },
        {
            'timestamp': now,
            'ip': '192.168.1.101',
            'service': 'http',
            'attack_type': 'sql_injection',
            'tools_detected': 'sqlmap',
            'username': 'admin'
        }
    ]
    
    processed = process_attack_data(attacks)
    stats = get_statistics(processed)
    
    assert stats['total_attacks'] == 2
    assert stats['unique_ips'] == 2
    assert 'ssh' in stats['service_distribution']
    assert 'http' in stats['service_distribution']
    assert len(stats['recent_attacks']) == 2


def test_xss_protection_in_templates():
    """Test that XSS is prevented in processed data"""
    attacks = [{
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'ip': '<script>alert(1)</script>',
        'device_name': '<img src=x onerror=alert(1)>',
        'service': 'ssh',
        'attack_type': 'test',
        'tools_detected': [],
        'username': '<b>admin</b>'
    }]
    
    processed = process_attack_data(attacks)
    
    # Verify all dangerous characters are escaped
    assert '&lt;' in processed[0]['ip']
    assert '<script>' not in processed[0]['ip']
    assert '&lt;' in processed[0]['device_name']
    assert '<img' not in processed[0]['device_name']
    assert '&lt;b&gt;' in processed[0]['username']
