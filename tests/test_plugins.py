from scanner.plugins.registry import get_plugin, get_plugins


def test_plugin_registry_contains_expected_services():
    plugin_names = {plugin.name for plugin in get_plugins()}
    assert "telnet" in plugin_names
    assert "rtsp" in plugin_names
    assert "onvif" in plugin_names
    assert "http" in plugin_names
    assert "ftp" in plugin_names


def test_plugin_lookup_returns_registered_plugin():
    plugin = get_plugin("telnet")
    assert plugin is not None
    assert plugin.name == "telnet"
