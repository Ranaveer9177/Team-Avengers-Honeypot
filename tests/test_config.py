import json
import os


def test_default_config_contains_new_fields(tmp_path):
    # simulate missing config file
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    os.chdir(tmp_path)

    from unified_honeypot import UnifiedHoneypotServer

    server = UnifiedHoneypotServer(config_file='config/unified_honeypot.json')
    assert 'pcap_dir' in server.config
    assert 'pcap_enabled' in server.config
    assert 'initial_payload_max_bytes' in server.config
    assert 'banners' in server.config


