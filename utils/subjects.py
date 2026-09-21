from enum import Enum


class Subject(str, Enum):
    NETWORKS = "Networks"
    SINTAXIS = "Sintaxis"
    ROUTING = "Routing"
    FIREWALL = "Firewall"
    RADVD = "RADVD"
    RPDB = "RPDB"
    POLICY = "Policy"
    TUNNELING = "Tunneling"

    @classmethod
    def from_value(cls, value):
        if isinstance(value, cls):
            return value
        return cls(value)
