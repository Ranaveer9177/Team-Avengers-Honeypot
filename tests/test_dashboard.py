from unified_dashboard import sanitize_string, process_attack_data
from datetime import datetime, timezone


def test_sanitize_string_truncates_and_escapes():
    s = '<script>alert(1)</script>'
    out = sanitize_string(s, max_length=10)
    assert '&lt;script&gt;' in out
    assert out.endswith('...')


def test_process_attack_data_sanitizes_fields():
    now = datetime.now(timezone.utc).isoformat()
    attacks = [{
        'timestamp': now,
        'ip': '1.2.3.4',
        'device_name': '<b>dev</b>',
        'service': 'http',
        'attack_type': 'xss',
        'tools_detected': ['nmap', 'sqlmap'],
        'username': '<img onerror=x>',
        'password': 'x'
    }]
    processed = process_attack_data(attacks)
    assert processed[0]['device_name'] == '&lt;b&gt;dev&lt;/b&gt;'
    assert 'nmap' in processed[0]['tools_detected']


