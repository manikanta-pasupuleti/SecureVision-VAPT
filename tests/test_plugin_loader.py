from scanner.plugins.loader import discover_plugin_classes
from scanner.plugins.registry import get_plugin, get_plugins


def test_loader_discovers_plugin_classes():
    classes = discover_plugin_classes()
    assert len(classes) >= 5


def test_registry_uses_loaded_plugins():
    plugins = get_plugins()
    assert len(plugins) >= 5
    assert get_plugin("telnet") is not None
    assert get_plugin("http") is not None
