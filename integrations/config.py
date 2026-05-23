"""
PILA Suite — Integration Config Loader
Reads pila.conf and exposes typed config objects.
"""
import configparser
import os

_conf = None

def _load() -> configparser.ConfigParser:
    global _conf
    if _conf is not None:
        return _conf
    _conf = configparser.ConfigParser()
    candidates = [
        os.environ.get("PILA_CONF", ""),
        os.path.join(os.path.dirname(__file__), "pila.conf"),
        os.path.join(os.path.dirname(__file__), "..", "integrations", "pila.conf"),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            _conf.read(path)
            return _conf
    raise FileNotFoundError("pila.conf not found.")


class ESConfig:
    def __init__(self):
        c = _load()["elasticsearch"]
        self.host      = c.get("host", "192.168.10.172")
        self.port      = int(c.get("port", "9200"))
        self.username  = c.get("username", "elastic")
        self.password  = c.get("password", "")
        self.scheme    = c.get("scheme", "http")
        self.verify_ssl = c.getboolean("verify_ssl", False)
        self.alert_indices    = [i.strip() for i in c.get("alert_indices", "filebeat-*").split(",")]
        self.suricata_index   = c.get("suricata_index", "filebeat-*")
        self.zeek_index       = c.get("zeek_index", "filebeat-*")
        self.packetbeat_index = c.get("packetbeat_index", "packetbeat-*")
        self.detection_window = int(c.get("detection_window_seconds", "120"))

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


class SuricataConfig:
    def __init__(self):
        c = _load()["suricata"]
        self.host     = c.get("host", "192.168.10.172")
        self.eve_path = c.get("eve_path", "/var/log/suricata/eve.json")
        self.ssh_user = c.get("ssh_user", "")
        self.ssh_key  = c.get("ssh_key", "~/.ssh/id_rsa")


class ZeekConfig:
    def __init__(self):
        c = _load()["zeek"]
        self.host     = c.get("host", "192.168.10.172")
        self.log_path = c.get("log_path", "/var/log/zeek/")
        self.ssh_user = c.get("ssh_user", "")
        self.ssh_key  = c.get("ssh_key", "~/.ssh/id_rsa")


class LMEPConfig:
    def __init__(self):
        c = _load()["lmep"]
        self.post_emulation_wait   = int(c.get("post_emulation_wait_seconds", "15"))
        self.min_suricata_severity = int(c.get("min_suricata_severity", "3"))


class IRVConfig:
    def __init__(self):
        c = _load()["irv"]
        self.clean_window_minutes = int(c.get("clean_window_minutes", "10"))
