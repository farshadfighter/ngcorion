"""
Taking a configuration backup of one device.

Every family exposes the same ``backup_config()`` the pre-hardening flow uses, so a backup taken by
hand or on a schedule captures exactly what a hardening run would roll back to. All of them sign in
over SSH with a user name, password, optional Cisco enable secret and port.
"""
from typing import Optional

FAMILIES = ("cisco", "fortinet", "linux", "apache", "mongodb")


def take_backup(device_type: str, ip: str, username: str, password: str,
                secret: Optional[str] = None, port: int = 22) -> str:
    """Connect to a device and return its configuration (a file bundle for the server families)."""
    if device_type == "cisco":
        from app.modules.cisco.hardening.ssh_executor import CiscoHardeningExecutor
        with CiscoHardeningExecutor(ip=ip, username=username, password=password, secret=secret, port=port) as ex:
            return ex.backup_config()
    elif device_type == "fortinet":
        from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor
        with FortiGateHardeningExecutor(ip=ip, username=username, password=password, port=port) as ex:
            return ex.backup_config()
    elif device_type == "linux":
        from app.modules.linux.hardening.ssh_executor import LinuxSSHExecutor
        with LinuxSSHExecutor(ip=ip, username=username, password=password, port=port) as ex:
            return ex.backup_config()
    elif device_type == "apache":
        from app.modules.apache.hardening.ssh_executor import ApacheSSHExecutor
        with ApacheSSHExecutor(ip=ip, username=username, password=password, port=port) as ex:
            return ex.backup_config()
    elif device_type == "mongodb":
        from app.modules.mongodb.hardening.ssh_executor import MongoDBSSHExecutor
        with MongoDBSSHExecutor(ip=ip, username=username, password=password, ssh_port=port) as ex:
            return ex.backup_config()
    else:
        raise ValueError(f"Unsupported device type for manual backup: {device_type}")
