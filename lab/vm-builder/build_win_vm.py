"""
Build a zero-click unattended Windows 11 Enterprise Evaluation VM (named "Win10"
to match the Detection Rule Pack) with:
  - Static lab IP 192.168.99.30/24 on VMnet1 (e1000e inbox driver)
  - OpenSSH Server with our lab SSH key + password auth
  - RDP enabled (for Rule 100204 T1021.001)
  - Windows Security audit policies enabled (4624, 4625, 4688, 1102, 7045, PS 4104)
  - Sysmon64 installed with SwiftOnSecurity config + explicit ProcessAccess on lsass.exe (Event 10 for Rule 100201)
  - Wazuh Agent 4.14.9 installed and pointing to 192.168.99.10
"""
import io
import subprocess
from pathlib import Path
import pycdlib

ROOT = Path(__file__).resolve().parents[2]
ISO_WIN = ROOT / "isos" / "win11-enterprise-eval.iso"
TOOLS = ROOT / "isos" / "win-tools"
VM_DIR = Path.home() / "Documents" / "Virtual Machines" / "SOC-Lab" / "SOC-Win10"
VDISK = r"C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe"
PUBKEY = (Path.home() / ".ssh" / "soclab_ed25519.pub").read_text().strip()


def build_sysmon_config() -> bytes:
    raw = (TOOLS / "sysmonconfig-swift.xml").read_text(encoding="utf-8")
    lsass_rule = (
        '<ProcessAccess onmatch="include">\n'
        '            <TargetImage name="technique_id=T1003.001,technique_name=LSASS Memory" condition="image">lsass.exe</TargetImage>\n'
        '        </ProcessAccess>'
    )
    patched = raw.replace(
        '<ProcessAccess onmatch="include">\n\t\t\t<!--NOTE: Using "include" with no rules means nothing in this section will be logged-->\n\t\t</ProcessAccess>',
        lsass_rule,
    )
    if lsass_rule not in patched:
        patched = raw.replace('<ProcessAccess onmatch="include">', '<ProcessAccess onmatch="include">\n<TargetImage condition="image">lsass.exe</TargetImage>')
    return patched.encode("utf-8")


AUTOUNATTEND = """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>1</Order>
          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>2</Order>
          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>3</Order>
          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>4</Order>
          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassCPUCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
      <DiskConfiguration>
        <Disk wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Type>Primary</Type>
              <Size>100</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Format>NTFS</Format>
              <Label>System</Label>
              <Active>true</Active>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order>
              <PartitionID>2</PartitionID>
              <Format>NTFS</Format>
              <Label>Windows</Label>
              <Letter>C</Letter>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
              <Key>/IMAGE/INDEX</Key>
              <Value>1</Value>
            </MetaData>
          </InstallFrom>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>2</PartitionID>
          </InstallTo>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>SOC Analyst</FullName>
        <Organization>SOC Lab</Organization>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>Win10</ComputerName>
      <TimeZone>Arab Standard Time</TimeZone>
    </component>
    <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <fDenyTSConnections>false</fDenyTSConnections>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword>
          <Value>SocLab!2026</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
        <LocalAccounts>
          <LocalAccount wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <Name>soc</Name>
            <Group>Administrators</Group>
            <Password>
              <Value>SocLab!2026</Value>
              <PlainText>true</PlainText>
            </Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Username>soc</Username>
        <Password>
          <Value>SocLab!2026</Value>
          <PlainText>true</PlainText>
        </Password>
        <Enabled>true</Enabled>
        <LogonCount>5</LogonCount>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>1</Order>
          <CommandLine>powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-PSDrive -PSProvider FileSystem | ForEach-Object { $p = Join-Path $_.Root 'setup_win.ps1'; if (Test-Path $p) { &amp; $p } }"</CommandLine>
          <Description>Configure SOC Lab Windows host</Description>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"""


def build_setup_ps1() -> str:
    return f"""$ErrorActionPreference = 'Continue'
Start-Transcript -Path 'C:\\soc_setup.log' -Append

$src = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force 'C:\\Temp' | Out-Null

# 1. Configure static IP 192.168.99.30/24 on MAC 00-50-56-2A-00-30
$nic = Get-NetAdapter | Where-Object {{ $_.MacAddress -eq '00-50-56-2A-00-30' }}
if ($nic) {{
    New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress 192.168.99.30 -PrefixLength 24 -ErrorAction SilentlyContinue
    Set-NetConnectionProfile -InterfaceIndex $nic.ifIndex -NetworkCategory Private -ErrorAction SilentlyContinue
}}

# 2. Enable RDP & ICMP & SSH firewall rules
Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'SOC-SSH' -DisplayName 'SOC SSH' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'SOC-ICMP' -DisplayName 'SOC ICMP' -Enabled True -Direction Inbound -Protocol ICMPv4 -Action Allow -ErrorAction SilentlyContinue

# 3. Install OpenSSH Server MSI
Start-Process msiexec.exe -ArgumentList "/i `"$src\\OpenSSH-Win64.msi`" /qn" -Wait
Start-Service sshd -ErrorAction SilentlyContinue
Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force 'C:\\ProgramData\\ssh' | Out-Null
Set-Content -Path 'C:\\ProgramData\\ssh\\administrators_authorized_keys' -Value '{PUBKEY}' -Encoding Ascii
icacls.exe 'C:\\ProgramData\\ssh\\administrators_authorized_keys' /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
Restart-Service sshd -ErrorAction SilentlyContinue

# 4. Enable Windows Audit Policies & PowerShell ScriptBlock Logging (4104)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord

# 5. Install Sysmon64 with Capstone Config
Expand-Archive -Path "$src\\Sysmon.zip" -DestinationPath 'C:\\Temp\\Sysmon' -Force
Copy-Item "$src\\sysmonconfig.xml" 'C:\\Temp\\Sysmon\\sysmonconfig.xml' -Force
& 'C:\\Temp\\Sysmon\\Sysmon64.exe' -accepteula -i 'C:\\Temp\\Sysmon\\sysmonconfig.xml'

# 6. Install Wazuh Agent 4.14.9 and add Sysmon channel
Start-Process msiexec.exe -ArgumentList "/i `"$src\\wazuh-agent.msi`" /q WAZUH_MANAGER=`"192.168.99.10`" WAZUH_AGENT_NAME=`"Win10`"" -Wait
$ossec = 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf'
if (Test-Path $ossec) {{
    $cfg = Get-Content $ossec -Raw
    if ($cfg -notmatch 'Microsoft-Windows-Sysmon/Operational') {{
        $sysmonBlock = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
"@
        # the MSI writes ossec.conf with CRLF + trailing blank lines, so a bare '>$' never matched
        $cfg = $cfg -replace '</ossec_config>\\s*$', $sysmonBlock
        Set-Content -Path $ossec -Value $cfg -Encoding UTF8
    }}
}}
Start-Service WazuhSvc -ErrorAction SilentlyContinue

Stop-Transcript
"""


def build_seed_iso(path: Path) -> None:
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="WINSEED")
    files = [
        ("AUTOUNATTEND.XML;1", "autounattend.xml", AUTOUNATTEND.encode("utf-8")),
        ("SETUP_WIN.PS1;1", "setup_win.ps1", build_setup_ps1().encode("utf-8")),
        ("SYSMONCONFIG.XML;1", "sysmonconfig.xml", build_sysmon_config()),
        ("SYSMON.ZIP;1", "Sysmon.zip", (TOOLS / "Sysmon.zip").read_bytes()),
        ("OPENSSH.MSI;1", "OpenSSH-Win64.msi", (TOOLS / "OpenSSH-Win64.msi").read_bytes()),
        ("WAZUH.MSI;1", "wazuh-agent.msi", (TOOLS / "wazuh-agent-4.14.9-1.msi").read_bytes()),
    ]
    for iso_name, real_name, data in files:
        iso.add_fp(io.BytesIO(data), len(data), "/" + iso_name, rr_name=real_name, joliet_path="/" + real_name)
    iso.write(str(path))
    iso.close()


def vmx(d: Path) -> str:
    lines = {
        ".encoding": "UTF-8", "config.version": "8", "virtualHW.version": "21",
        "displayName": "SOC-Win10", "guestOS": "windows9-64",
        "memsize": "4096", "numvcpus": "4", "cpuid.coresPerSocket": "4",
        "bios.bootOrder": "cdrom,hdd",
        "pciBridge0.present": "TRUE",
        "pciBridge4.present": "TRUE", "pciBridge4.virtualDev": "pcieRootPort", "pciBridge4.functions": "8",
        "pciBridge5.present": "TRUE", "pciBridge5.virtualDev": "pcieRootPort", "pciBridge5.functions": "8",
        "pciBridge6.present": "TRUE", "pciBridge6.virtualDev": "pcieRootPort", "pciBridge6.functions": "8",
        "pciBridge7.present": "TRUE", "pciBridge7.virtualDev": "pcieRootPort", "pciBridge7.functions": "8",
        "vmci0.present": "TRUE", "hpet0.present": "TRUE", "tools.syncTime": "TRUE",
        "scsi0.present": "TRUE", "scsi0.virtualDev": "lsisas1068",
        "scsi0:0.present": "TRUE", "scsi0:0.fileName": "Win10.vmdk",
        "sata0.present": "TRUE",
        "sata0:0.present": "TRUE", "sata0:0.deviceType": "cdrom-image", "sata0:0.fileName": str(ISO_WIN),
        "sata0:1.present": "TRUE", "sata0:1.deviceType": "cdrom-image", "sata0:1.fileName": str(d / "win-seed.iso"),
        "ethernet0.present": "TRUE", "ethernet0.connectionType": "hostonly",
        "ethernet0.virtualDev": "e1000e", "ethernet0.addressType": "static",
        "ethernet0.address": "00:50:56:2A:00:30", "ethernet0.startConnected": "TRUE",
        "ethernet1.present": "TRUE", "ethernet1.connectionType": "nat",
        "ethernet1.virtualDev": "e1000e", "ethernet1.addressType": "static",
        "ethernet1.address": "00:50:56:2A:01:30", "ethernet1.startConnected": "TRUE",
        "usb.present": "TRUE", "ehci.present": "TRUE",
        "floppy0.present": "FALSE",
    }
    return "\n".join(f'{k} = "{v}"' for k, v in lines.items()) + "\n"


def main():
    VM_DIR.mkdir(parents=True, exist_ok=True)
    build_seed_iso(VM_DIR / "win-seed.iso")
    disk = VM_DIR / "Win10.vmdk"
    if not disk.exists():
        subprocess.run([VDISK, "-c", "-s", "60GB", "-a", "lsilogic", "-t", "0", str(disk)], check=True)
    vmx_path = VM_DIR / "SOC-Win10.vmx"
    vmx_path.write_text(vmx(VM_DIR), encoding="ascii")
    print(f"[ok] Built {vmx_path}")


if __name__ == "__main__":
    main()
