from pathlib import Path
import yaml

_current_config = None

def set_config(config):
    global _current_config
    _current_config = config

def get_config():
    return _current_config

def load_config(filename: str):
    with open(Path("config") / filename, encoding="utf-8") as f:
        return yaml.safe_load(f)