"""Explanations in English per code (Oneata): max 2 sentences, 1-5 steps, plain language.

Same rules as templates_ro.py (checked in tests/test_explain.py): no port numbers, IPs, catalog codes,
CVEs or links; `harm` is one line on what an attacker could do (get_harm); `text` has at most 2 sentences; `steps` has 1-5 items, the most important first.
"""

from __future__ import annotations

TEMPLATES: dict[str, dict] = {
    "TELNET_OPEN": {
        "harm": "Someone on the network can learn your password and take control of the device.",
        "text": "Telnet is an old door that lets someone control this device from far away. The password travels in plain sight, like a postcard, and whoever catches it can take over the device.",
        "steps": [
            "Turn off Telnet in the device's admin page (usually under \"Services\" or \"Remote access\").",
            "If you need remote access, use SSH instead of Telnet.",
            "Change the device password, because it may already have been seen.",
            "Update the firmware; if Telnet cannot be turned off, ask the manufacturer for help or replace the device.",
        ],
    },
    "RDP_EXPOSED": {
        "harm": "Someone can guess the password and use the computer as if they were sitting at it.",
        "text": "Remote Desktop lets others see and control this computer's screen over the network. Attackers "
                "try thousands of passwords on it or use old Windows bugs to get in.",
        "steps": [
            "If you don't use Remote Desktop, turn it off: Settings → System → Remote Desktop → Off.",
            "If you use it, allow only the users who really need it and give them long passwords.",
            "Keep NLA turned on: it asks for the password before the screen opens.",
            "Install all Windows updates.",
            "Never open Remote Desktop to the internet from your router; use a VPN instead.",
        ],
    },
    "VNC_EXPOSED": {
        "harm": "Someone on the network can watch your screen and move the mouse for you.",
        "text": "VNC shows this device's screen to someone else on the network and lets them control it. It often "
                "has short passwords or none at all, and what is on the screen may travel unencrypted.",
        "steps": [
            "Turn off the VNC program on this device if you don't use it.",
            "If you use it, set a long, unique password in the VNC program's settings.",
            "If you connect from outside your home, use a VPN (an encrypted tunnel) instead of leaving VNC open.",
            "Update the VNC program to the latest version.",
        ],
    },
    "DB_EXPOSED": {
        "harm": "Someone on the network can read, change or delete the app's data.",
        "text": "A database stores an app's information, and this one can be reached directly from the network. "
                "Many databases come without a password, so anyone on the network could read, change or delete the data.",
        "steps": [
            "Find the program that put the database on this device and turn it off if you no longer use it.",
            "If you use it, ask whoever installed it to close the database to the rest of the network.",
            "Turn on authentication (a name and a password) in the database settings and set a long password.",
            "Update the database program.",
        ],
    },
    "CAMERA_STREAM_EXPOSED": {
        "harm": "Anyone on the network can watch what the camera films.",
        "text": "This camera's video can be watched directly from the network, without its app. If the password "
                "is missing or still the factory default, anyone on the network can see what the camera films.",
        "steps": [
            "Change the camera's factory password to a long, unique one.",
            "Turn off the direct video stream (RTSP) if the camera's app doesn't need it.",
            "Update the camera's firmware.",
            "Move cameras to a separate network, for example the router's guest network, if it has one.",
        ],
    },
    "OUTDATED_SERVICE": {
        "harm": "Someone can use a ready-made tool to break into the device.",
        "text": "A program on this device is an old version with security bugs that attackers already know about. "
                "For some of them there are ready-made tools that break in automatically.",
        "steps": [
            "Update the old program or the device firmware to the latest version.",
            "If there are no more updates, turn off the service or replace the device.",
            "Turn on automatic updates if the device has them.",
        ],
    },
    "FTP_CLEARTEXT": {
        "harm": "Someone on the network can read the password and the files you send.",
        "text": "FTP moves files over the network, but it sends the password and the files unencrypted. Anyone "
                "listening on the same network can read them.",
        "steps": [
            "Turn off FTP if you don't use it.",
            "Use SFTP or FTPS instead, which encrypt the password and the files.",
            "Turn off anonymous login (access without an account).",
            "Change the FTP account password, because it may already have been seen.",
        ],
    },
    "HTTP_ADMIN_CLEARTEXT": {
        "harm": "Someone on the network can steal your password and change the device's settings.",
        "text": "The device's admin page opens over HTTP, without encryption. When you type your password there, it "
                "travels over the network in plain sight and can be stolen.",
        "steps": [
            "Turn on HTTPS in the device settings and use only the https address.",
            "Change the factory password to a long, unique one.",
            "Turn off remote administration (from the internet) if you don't need it.",
            "Update the device firmware.",
        ],
    },
    "SMB_EXPOSED": {
        "harm": "Someone can reach your files or spread a virus that asks for money.",
        "text": "Windows file sharing (SMB) is open on the network. Attackers can use it to reach your files, and viruses that ask for money can spread through it.",
        "steps": [
            "If you don't share files, turn sharing off: Settings → Network & internet → Advanced network settings → Advanced sharing settings.",
            "If you do, require a password and give access only to people who need it.",
            "Turn off the old SMBv1 version (in \"Turn Windows features on or off\").",
            "Install all system updates.",
            "On Windows, set public networks (cafés, hotels) to \"Public\" so sharing is hidden there.",
        ],
    },
    "MQTT_EXPOSED": {
        "harm": "Someone on the network can send commands to your smart devices, like turning the lights on.",
        "text": "MQTT is how smart devices like bulbs, sensors or locks send each other messages. Without a "
                "password, anyone on the network can read the messages or give them commands.",
        "steps": [
            "In your smart-home hub's app or page, require a name and password from every device.",
            "In the same settings, turn on encryption for connections (TLS).",
            "In the firewall, let the message mail carrier (the broker) accept only your own devices.",
            "Update the MQTT program (the broker) to the latest version.",
        ],
    },
    "UPNP_EXPOSED": {
        "harm": "A virus on one device can open your network to the internet.",
        "text": "UPnP lets devices open doors in your router by themselves, without asking you. A virus on one "
                "device can use it to open your network to the internet.",
        "steps": [
            "Turn off UPnP in the device's settings (on a router: in its admin page).",
            "Open ports (doors) in the router by hand only when you need them, and only for as long as needed.",
            "Update the device firmware.",
        ],
    },
    "SNMP_EXPOSED": {
        "harm": "Someone can learn the device's model and settings to plan an attack.",
        "text": "SNMP tells anyone who asks many details about the device, such as its model, settings and network. "
                "It often uses the factory password \"public\", which everybody knows.",
        "steps": [
            "Turn off SNMP in the device's admin page (usually under \"Administration\" or \"Services\") if you don't use it.",
            "If you use it, change the factory SNMP password (\"public\") to a long one.",
            "Choose SNMP version 3 (SNMPv3), the only one that asks for a password and encrypts.",
            "Update the device firmware.",
        ],
    },
    "PRINTER_RAW_EXPOSED": {
        "harm": "Someone on the network can print on your printer without asking or jam it.",
        "text": "The printer accepts print jobs directly from the network, without any check. Anyone on the network "
                "can print on it or send it strange commands.",
        "steps": [
            "Turn off direct printing (RAW / JetDirect) in the printer's admin page if you don't use it.",
            "In the printer settings, allow only your own computers to print.",
            "Set a password on the printer's admin page.",
            "Update the printer firmware.",
        ],
    },
    "UNKNOWN_DEVICE": {
        "harm": "A stranger's device can spy on what happens on your network.",
        "text": "The scan could not find the name or the maker of a device on your network that accepts connections. "
                "It is good to know every device, because a stranger's device could spy on you.",
        "steps": [
            "Look for the device in your router's list of connected devices.",
            "Check first whether it is one of your phones or laptops: new ones hide their real address.",
            "If it isn't yours, change the Wi-Fi password.",
            "Give it a name in the router so you recognize it next time.",
            "Move smart devices and unknown devices to the guest network, if your router has one.",
        ],
    },
    "SSH_OPEN": {
        "harm": "Someone can try thousands of passwords, and if one works, they control the device.",
        "text": "SSH is a safe, encrypted way to control a device remotely, so it is not a problem by itself. "
                "It just has to be well protected, because attackers often try passwords on it.",
        "steps": [
            "If you don't use SSH, turn it off.",
            "Use SSH keys (a kind of digital key) instead of passwords.",
            "Don't allow logging in directly as the administrator (root).",
            "Keep the SSH server updated.",
        ],
    },
}
