from enum import Enum


class Subject(str, Enum):
    NETWORKS = "Networks"
    ROUTING = "Routing"
    FIREWALL = "Firewall"
    RADVD = "RADVD"
    RPDB = "RPDB"
    TUNNELING = "Tunneling"

    @classmethod
    def from_value(cls, value):
        if isinstance(value, cls):
            return value
        return cls(value)
