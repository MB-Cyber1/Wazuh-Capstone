"""
Build unattended Ubuntu 24.04 VMs for the SOC capstone lab (VMware Workstation 17.5).

For each VM it creates:
  - a cloud-init "CIDATA" seed ISO (autoinstall user-data + meta-data)
  - a growable VMDK disk (vmware-vdiskmanager)
  - a .vmx file with two NICs:
        ethernet0 -> VMnet1 host-only (lab network, static IP)  -- permanent
        ethernet1 -> VMnet8 NAT (internet, DHCP)                -- disconnect before attacks

Usage:  python build_vms.py [wazuh] [ubuntu-01]
"""
import io
import subprocess
import sys
from pathlib import Path

import pycdlib

ROOT = Path(__file__).resolve().parents[2]                     # soc-capstone/
ISO = ROOT / "isos" / "ubuntu-24.04.3-live-server-amd64.iso"
VM_DIR = Path.home() / "Documents" / "Virtual Machines" / "SOC-Lab"
VDISK = r"C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe"
PUBKEY = (Path.home() / ".ssh" / "soclab_ed25519.pub").read_text().strip()
# SHA-512 crypt of the lab password "SocLab!2026" (lab-only credential)
PWHASH = "$6$T8zFD202b01rqHr.$1he7LcJB2we9wkDC1GJ2gNDyyXba7ZI2NSatqTkNzPDLyIyE01X5or8dWdicEvWvaOPZuB7EN07yI8iGYtof01"

VMS = {
    "wazuh": {
        "display": "SOC-Wazuh", "ip": "192.168.99.10", "octet": "10",
        "mem": 8192, "cpus": 4, "disk_gb": 80,
        "packages": ["open-vm-tools", "docker.io", "docker-compose-v2", "git", "curl", "jq"],
        "late": [
            "echo 'vm.max_map_count=262144' > /target/etc/sysctl.d/99-wazuh.conf",
            "curtin in-target -- usermod -aG docker soc",
        ],
    },
    "ubuntu-01": {
        "display": "SOC-ubuntu-01", "ip": "192.168.99.40", "octet": "40",
        "mem": 2048, "cpus": 2, "disk_gb": 30,
        "packages": ["open-vm-tools", "auditd", "audispd-plugins", "nginx", "git", "curl"],
        "late": [],
    },
}


def user_data(name: str, vm: dict) -> str:
    o = vm["octet"]
    pkgs = "\n".join(f"    - {p}" for p in vm["packages"])
    late = "\n".join(f'    - "{c}"' for c in
                     ["echo 'soc ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/90-soc",
                      "chmod 440 /target/etc/sudoers.d/90-soc"] + vm["late"])
    return f"""#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard: {{layout: us}}
  timezone: Asia/Riyadh
  identity:
    hostname: {name}
    realname: SOC Lab
    username: soc
    password: "{PWHASH}"
  ssh:
    install-server: true
    allow-pw: true
    authorized-keys:
      - "{PUBKEY}"
  network:
    version: 2
    ethernets:
      lab0:
        match: {{macaddress: "00:50:56:2a:00:{o}"}}
        set-name: lab0
        addresses: [{vm["ip"]}/24]
      nat0:
        match: {{macaddress: "00:50:56:2a:01:{o}"}}
        set-name: nat0
        dhcp4: true
        optional: true
  storage:
    layout: {{name: lvm, sizing-policy: all}}
  packages:
{pkgs}
  late-commands:
{late}
  shutdown: reboot
"""


def build_seed(path: Path, name: str, vm: dict) -> None:
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="cidata")
    for iso_name, real, data in [
        ("/USERDATA.;1", "user-data", user_data(name, vm).encode()),
        ("/METADATA.;1", "meta-data", f"instance-id: {name}\nlocal-hostname: {name}\n".encode()),
    ]:
        iso.add_fp(io.BytesIO(data), len(data), iso_name, rr_name=real, joliet_path="/" + real)
    iso.write(str(path))
    iso.close()


def vmx(name: str, vm: dict, d: Path) -> str:
    o = vm["octet"]
    lines = {
        ".encoding": "UTF-8", "config.version": "8", "virtualHW.version": "21",
        "displayName": vm["display"], "guestOS": "ubuntu-64",
        "memsize": str(vm["mem"]), "numvcpus": str(vm["cpus"]), "cpuid.coresPerSocket": str(vm["cpus"]),
        "bios.bootOrder": "hdd,cdrom",
        "pciBridge0.present": "TRUE",
        "pciBridge4.present": "TRUE", "pciBridge4.virtualDev": "pcieRootPort", "pciBridge4.functions": "8",
        "pciBridge5.present": "TRUE", "pciBridge5.virtualDev": "pcieRootPort", "pciBridge5.functions": "8",
        "pciBridge6.present": "TRUE", "pciBridge6.virtualDev": "pcieRootPort", "pciBridge6.functions": "8",
        "pciBridge7.present": "TRUE", "pciBridge7.virtualDev": "pcieRootPort", "pciBridge7.functions": "8",
        "vmci0.present": "TRUE", "hpet0.present": "TRUE", "tools.syncTime": "TRUE",
        "scsi0.present": "TRUE", "scsi0.virtualDev": "lsilogic",
        "scsi0:0.present": "TRUE", "scsi0:0.fileName": f"{name}.vmdk",
        "sata0.present": "TRUE",
        "sata0:0.present": "TRUE", "sata0:0.deviceType": "cdrom-image", "sata0:0.fileName": str(ISO),
        "sata0:1.present": "TRUE", "sata0:1.deviceType": "cdrom-image", "sata0:1.fileName": str(d / "seed.iso"),
        "ethernet0.present": "TRUE", "ethernet0.connectionType": "hostonly",
        "ethernet0.virtualDev": "vmxnet3", "ethernet0.addressType": "static",
        "ethernet0.address": f"00:50:56:2A:00:{o}", "ethernet0.startConnected": "TRUE",
        "ethernet1.present": "TRUE", "ethernet1.connectionType": "nat",
        "ethernet1.virtualDev": "vmxnet3", "ethernet1.addressType": "static",
        "ethernet1.address": f"00:50:56:2A:01:{o}", "ethernet1.startConnected": "TRUE",
        "usb.present": "TRUE", "ehci.present": "TRUE",
        "floppy0.present": "FALSE",
    }
    return "\n".join(f'{k} = "{v}"' for k, v in lines.items()) + "\n"


def main(names):
    if not ISO.exists():
        sys.exit(f"ISO not found: {ISO}")
    for name in names:
        vm = VMS[name]
        d = VM_DIR / vm["display"]
        d.mkdir(parents=True, exist_ok=True)
        build_seed(d / "seed.iso", name, vm)
        disk = d / f"{name}.vmdk"
        if not disk.exists():
            subprocess.run([VDISK, "-c", "-s", f"{vm['disk_gb']}GB", "-a", "lsilogic", "-t", "0", str(disk)],
                           check=True, capture_output=True)
        vmx_path = d / f"{vm['display']}.vmx"
        vmx_path.write_text(vmx(name, vm, d), encoding="utf-8")
        print(f"[ok] {name}: {vmx_path}")


if __name__ == "__main__":
    main(sys.argv[1:] or list(VMS))
