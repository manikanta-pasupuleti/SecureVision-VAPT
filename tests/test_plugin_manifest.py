from scanner.plugins.registry import get_plugin


def test_plugin_manifest_is_attached():
    plugin = get_plugin("telnet")
    assert plugin is not None
    assert plugin.metadata is not None
    assert plugin.metadata["service_name"] == "telnet"
    assert plugin.metadata["severity"] == "high"
