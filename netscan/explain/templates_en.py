"""Explanations in English per code (Oneata): max 2 sentences, 1-5 steps, plain language.

Same rules as templates_ro.py (checked in tests/test_explain.py): no port numbers, IPs, catalog codes,
CVEs or links; `text` has at most 2 sentences; `steps` has 1-5 items, the most important first.
"""

from __future__ import annotations

TEMPLATES: dict[str, dict] = {
    "TELNET_OPEN": {
        "text": "Telnet is an old door that lets someone control this device remotely, and the password travels "
                "over the network unencrypted, like a postcard anyone can read. Whoever catches it can take over the device.",
        "steps": [
            "Turn off Telnet in the device's admin page (usually under \"Services\" or \"Remote access\").",
            "If you need remote access, use SSH instead of Telnet.",
            "Change the device password, because it may already have been seen.",
            "Update the firmware; if Telnet cannot be turned off, ask the manufacturer for help or replace the device.",
        ],
    },
    "RDP_EXPOSED": {
        "text": "Remote Desktop lets others see and control this computer's screen over the network. Attackers "
                "try thousands of passwords on it or use old Windows bugs to get in.",
        "steps": [
            "If you don't use Remote Desktop, turn it off: Settings → System → Remote Desktop → Off.",
            "If you use it, allow only the users who really need it and give them long passwords.",
            "Keep \"Network Level Authentication\" turned on.",
            "Install all Windows updates.",
            "Never open Remote Desktop to the internet from your router; use a VPN instead.",
        ],
    },
    "VNC_EXPOSED": {
        "text": "VNC shows this device's screen to someone else on the network and lets them control it. It often "
                "has short passwords or none at all, and what is on the screen may travel unencrypted.",
        "steps": [
            "Turn off the VNC server if you don't use it.",
            "If you use it, set a long, unique password.",
            "Allow VNC connections only through SSH or a VPN, not directly from the network.",
            "Update the VNC software to the latest version.",
        ],
    },
    "DB_EXPOSED": {
        "text": "A database stores an app's information, and this one can be reached directly from the network. "
                "Many databases come without a password, so anyone on the network could read, change or delete the data.",
        "steps": [
            "Make the database listen only on its own computer (the local address), not on the whole network.",
            "Turn on authentication and set a strong password.",
            "In the firewall, allow only the app that really needs the database to connect.",
            "Update the database server.",
        ],
    },
    "CAMERA_STREAM_EXPOSED": {
        "text": "This camera's video can be watched directly from the network, without its app. If the password "
                "is missing or still the factory default, anyone on the network can see what the camera films.",
        "steps": [
            "Change the camera's factory password to a long, unique one.",
            "Turn off the direct video stream (RTSP) if the camera's app doesn't need it.",
            "Update the camera's firmware.",
            "Move cameras to a separate network, for example the router's guest network.",
        ],
    },
    "OUTDATED_SERVICE": {
        "text": "A program on this device is an old version with security bugs that attackers already know about. "
                "For some of them there are ready-made tools that break in automatically.",
        "steps": [
            "Update the program or the device firmware to the latest version.",
            "If there are no more updates, turn off the service or replace the device.",
            "Turn on automatic updates if the device has them.",
        ],
    },
    "FTP_CLEARTEXT": {
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
        "text": "The device's admin page opens over HTTP, without encryption. When you log in, the password "
                "travels over the network in plain sight and can be stolen.",
        "steps": [
            "Turn on HTTPS in the device settings and use only the https address.",
            "Change the factory password to a long, unique one.",
            "Turn off remote administration (from the internet) if you don't need it.",
            "Update the device firmware.",
        ],
    },
    "SMB_EXPOSED": {
        "text": "Windows file sharing (SMB) is open on the network. Attackers can use it to try to reach your "
                "files, and ransomware can spread through it from one computer to another.",
        "steps": [
            "If you don't share files, turn off sharing in the network settings.",
            "If you do, require a password and give access only to people who need it.",
            "Turn off the old SMBv1 version (in \"Turn Windows features on or off\").",
            "Install all system updates.",
            "On Windows, set public networks (cafés, hotels) to \"Public\" so sharing is hidden there.",
        ],
    },
    "MQTT_EXPOSED": {
        "text": "MQTT is how smart devices like bulbs, sensors or locks send each other messages. Without a "
                "password, anyone on the network can read the messages or send commands, such as turning the lights on.",
        "steps": [
            "Require a username and password for every client (turn off anonymous access).",
            "Turn on encryption (TLS) for connections.",
            "In the firewall, let the broker accept connections only from your own devices.",
            "Update the MQTT broker to the latest version.",
        ],
    },
    "UPNP_EXPOSED": {
        "text": "UPnP lets devices open doors in your router by themselves, without asking you. A virus on one "
                "device can use it to open your network to the internet.",
        "steps": [
            "Turn off UPnP in the device's settings (on a router: in its admin page).",
            "Open ports manually in the router only when you need them, and only for as long as you need them.",
            "Update the device firmware.",
        ],
    },
    "SNMP_EXPOSED": {
        "text": "SNMP tells anyone who asks many details about the device, such as its model, settings and network. "
                "It often uses the factory password \"public\", which everybody knows.",
        "steps": [
            "Turn off SNMP if you don't use it.",
            "If you use it, change the factory passwords (\"community strings\").",
            "Switch to SNMPv3, which has authentication and encryption.",
            "Allow only the admin computer to send SNMP requests.",
        ],
    },
    "PRINTER_RAW_EXPOSED": {
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
        "text": "There is a device on the network with open services, and the scan could not find its name or maker. You should "
                "know what every device on your network is, because a stranger's device can spy or attack.",
        "steps": [
            "Look for the device in your router's list of connected devices.",
            "New phones and laptops hide their real address, so first check whether it is one of yours.",
            "If it isn't yours, change the Wi-Fi password.",
            "Give it a name in the router so you recognize it next time.",
            "Move smart devices and unknown devices to the guest network.",
        ],
    },
    "SSH_OPEN": {
        "text": "SSH is a safe, encrypted way to control a device remotely, so it is not a problem by itself. "
                "It just has to be well protected, because attackers often try passwords on it.",
        "steps": [
            "If you don't use SSH, turn it off.",
            "Use SSH keys instead of passwords.",
            "Don't allow logging in directly as the administrator (root).",
            "Keep the SSH server updated.",
        ],
    },
}
