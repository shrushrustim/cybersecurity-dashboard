"""
security_tools.py — Security Tools Reference Cards + Nmap Scanner UI layout.
"""

from dash import html, dcc

PANEL = {
    "backgroundColor": "#0a1520",
    "border": "1px solid #0f3a5c",
    "borderRadius": "8px",
    "padding": "16px",
}
MONO = {"fontFamily": "Share Tech Mono, monospace"}
RAJDHANI = {"fontFamily": "Rajdhani, monospace"}

CATEGORY_COLORS = {
    "Reconnaissance":      "#00d4ff",
    "Vulnerability":       "#ffd700",
    "Exploitation":        "#ff6b35",
    "Web Security":        "#a78bfa",
    "SIEM / Monitoring":   "#00ff88",
    "Digital Forensics":   "#ff79c6",
    "Password Cracking":   "#ff3355",
}

TOOLS = [
    {
        "name": "Nmap",
        "category": "Reconnaissance",
        "desc": "Advanced network scanning, port discovery, and service detection tool.",
        "features": ["Host discovery", "Port scanning", "Service & OS detection", "Script engine (NSE)"],
        "cmd": "nmap -sV -T4 -top-ports 1000 <target>",
        "install": "brew install nmap",
        "url": "https://nmap.org",
    },
    {
        "name": "Wireshark",
        "category": "Reconnaissance",
        "desc": "Network protocol analyzer for live traffic inspection and packet capture.",
        "features": ["Live packet capture", "Deep packet inspection", "Protocol filtering", "Export as PCAP"],
        "cmd": "tshark -i eth0 -w capture.pcap",
        "install": "brew install wireshark",
        "url": "https://wireshark.org",
    },
    {
        "name": "theHarvester",
        "category": "Reconnaissance",
        "desc": "OSINT tool for gathering emails, domains, subdomains, and employee names.",
        "features": ["Email harvesting", "Subdomain discovery", "DNS enumeration", "Multiple sources"],
        "cmd": "theHarvester -d example.com -b all",
        "install": "pip install theHarvester",
        "url": "https://github.com/laramies/theHarvester",
    },
    {
        "name": "OpenVAS",
        "category": "Vulnerability",
        "desc": "Full-featured open-source vulnerability scanner with CVE detection.",
        "features": ["CVE detection", "Misconfiguration checks", "Web app scanning", "Compliance auditing"],
        "cmd": "gvm-cli socket --gmp-username admin --xml '<get_tasks/>'",
        "install": "apt install openvas && gvm-setup",
        "url": "https://openvas.org",
    },
    {
        "name": "Nikto",
        "category": "Vulnerability",
        "desc": "Web server scanner that detects outdated software, dangerous files, and misconfigurations.",
        "features": ["Outdated software detection", "Default files check", "SSL issues", "XSS/SQLi fingerprinting"],
        "cmd": "nikto -h https://target.com -ssl",
        "install": "brew install nikto",
        "url": "https://cirt.net/Nikto2",
    },
    {
        "name": "Metasploit",
        "category": "Exploitation",
        "desc": "The world's most widely used penetration testing framework for exploit development.",
        "features": ["2000+ exploits", "Payload generation", "Post-exploitation", "Meterpreter shell"],
        "cmd": "msfconsole\nuse exploit/multi/handler\nset PAYLOAD windows/x64/meterpreter/reverse_tcp",
        "install": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall",
        "url": "https://metasploit.com",
    },
    {
        "name": "SQLmap",
        "category": "Exploitation",
        "desc": "Automated SQL injection detection and exploitation tool.",
        "features": ["Auto SQLi detection", "Database fingerprinting", "Data extraction", "WAF bypass techniques"],
        "cmd": "sqlmap -u 'https://target.com/page?id=1' --dbs --batch",
        "install": "pip install sqlmap",
        "url": "https://sqlmap.org",
    },
    {
        "name": "John the Ripper",
        "category": "Password Cracking",
        "desc": "Password security auditing and cracking tool supporting 400+ hash types.",
        "features": ["400+ hash formats", "Dictionary attacks", "Brute force", "Rule-based cracking"],
        "cmd": "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
        "install": "brew install john",
        "url": "https://openwall.com/john",
    },
    {
        "name": "OWASP ZAP",
        "category": "Web Security",
        "desc": "OWASP's web application security scanner for automated and manual testing.",
        "features": ["Active/passive scanning", "Spider & crawler", "AJAX support", "API scanning"],
        "cmd": "zap-cli quick-scan --self-contained -o '-config api.disablekey=true' https://target.com",
        "install": "brew install --cask owasp-zap",
        "url": "https://zaproxy.org",
    },
    {
        "name": "Wapiti",
        "category": "Web Security",
        "desc": "Black-box web vulnerability scanner detecting XSS, SQLi, file disclosure, and more.",
        "features": ["XSS detection", "SQL injection", "File inclusion", "SSRF testing"],
        "cmd": "wapiti -u https://target.com -v 2",
        "install": "pip install wapiti3",
        "url": "https://wapiti-scanner.github.io",
    },
    {
        "name": "Wazuh",
        "category": "SIEM / Monitoring",
        "desc": "Open-source SIEM and XDR solution for threat detection and compliance.",
        "features": ["Log analysis", "File integrity monitoring", "Intrusion detection", "Compliance (PCI DSS, HIPAA)"],
        "cmd": "curl -so ~/wazuh-install.sh https://packages.wazuh.com/4.x/wazuh-install.sh && sudo bash ~/wazuh-install.sh -a",
        "install": "See wazuh.com/install",
        "url": "https://wazuh.com",
    },
    {
        "name": "Snort",
        "category": "SIEM / Monitoring",
        "desc": "Network intrusion detection and prevention system (IDS/IPS) with real-time analysis.",
        "features": ["Packet sniffing", "Rule-based detection", "Protocol analysis", "Inline IPS mode"],
        "cmd": "snort -A console -i eth0 -c /etc/snort/snort.conf",
        "install": "apt install snort",
        "url": "https://snort.org",
    },
    {
        "name": "Autopsy",
        "category": "Digital Forensics",
        "desc": "GUI-based digital forensics platform for hard drive and smartphone analysis.",
        "features": ["File carving", "Timeline analysis", "Hash filtering", "Keyword search"],
        "cmd": "# GUI tool — launch with: autopsy",
        "install": "Download from sleuthkit.org/autopsy",
        "url": "https://sleuthkit.org/autopsy",
    },
    {
        "name": "Volatility",
        "category": "Digital Forensics",
        "desc": "Advanced memory forensics framework for incident response and malware analysis.",
        "features": ["Process analysis", "Network connections", "Malware detection", "Registry extraction"],
        "cmd": "vol.py -f memory.dmp --profile=Win10x64 pslist\nvol.py -f memory.dmp netscan",
        "install": "pip install volatility3",
        "url": "https://volatilityfoundation.org",
    },
]


def _tool_card(tool: dict) -> html.Div:
    cat = tool["category"]
    color = CATEGORY_COLORS.get(cat, "#527a99")

    return html.Div([
        # Header
        html.Div([
            html.Div(tool["name"], style={
                **RAJDHANI, "fontSize": "16px", "fontWeight": "700", "color": "#ffffff",
            }),
            html.Span(cat, style={
                **MONO, "fontSize": "8px", "padding": "2px 7px",
                "borderRadius": "3px", "border": f"1px solid {color}",
                "color": color, "letterSpacing": "1px",
            }),
        ], style={"display": "flex", "justifyContent": "space-between", "alignItems": "center", "marginBottom": "8px"}),

        # Description
        html.Div(tool["desc"], style={
            **RAJDHANI, "fontSize": "12px", "color": "#8fb4c8", "marginBottom": "8px", "lineHeight": "1.4",
        }),

        # Features
        html.Div([
            html.Span(f"✓ {f}", style={**MONO, "fontSize": "9px", "color": "#527a99", "marginRight": "8px"})
            for f in tool["features"]
        ], style={"marginBottom": "10px", "flexWrap": "wrap", "display": "flex", "gap": "2px"}),

        # Command example
        html.Div([
            html.Div("EXAMPLE", style={**MONO, "fontSize": "8px", "color": "#355a7a", "marginBottom": "3px"}),
            html.Pre(tool["cmd"], style={
                **MONO, "fontSize": "9px", "color": "#00d4ff",
                "backgroundColor": "#050a0f",
                "padding": "6px 8px", "borderRadius": "4px",
                "margin": "0", "overflowX": "auto",
                "border": "1px solid #0a2030",
                "whiteSpace": "pre-wrap", "wordBreak": "break-all",
            }),
        ], style={"marginBottom": "8px"}),

        # Install
        html.Div([
            html.Span("Install: ", style={**MONO, "fontSize": "9px", "color": "#355a7a"}),
            html.Code(tool["install"], style={**MONO, "fontSize": "9px", "color": "#ffd700"}),
        ]),

    ], style={
        **PANEL,
        "borderLeft": f"3px solid {color}",
        "borderRadius": "0 8px 8px 0",
        "display": "flex", "flexDirection": "column",
    })


def tab_security_tools_layout() -> html.Div:
    return html.Div([

        # ── Nmap Scanner ─────────────────────────────────────────────────────
        html.Div([
            html.Div([
                html.Div("🔍 Nmap Network Scanner", style={
                    **RAJDHANI, "fontSize": "15px", "fontWeight": "700",
                    "color": "#00d4ff", "letterSpacing": "1px",
                }),
                html.Div(
                    "⚠ WARNING: Only scan systems you own or have written permission to test. Unauthorised scanning may be illegal.",
                    style={
                        **MONO, "fontSize": "9px", "color": "#ff6b35",
                        "backgroundColor": "rgba(255,107,53,0.08)",
                        "border": "1px solid rgba(255,107,53,0.3)",
                        "borderRadius": "4px", "padding": "5px 10px",
                        "marginTop": "6px",
                    }
                ),
            ], style={"marginBottom": "14px"}),

            html.Div([
                dcc.Input(
                    id="nmap-target",
                    type="text",
                    placeholder="Target IP or hostname (e.g. 127.0.0.1 or scanme.nmap.org)",
                    style={
                        "flex": "1", "backgroundColor": "#050a0f",
                        "color": "#c8e6f5", "border": "1px solid #0f3a5c",
                        "borderRadius": "4px", "padding": "8px 12px",
                        **MONO, "fontSize": "12px", "outline": "none",
                    },
                ),
                dcc.Dropdown(
                    id="nmap-scan-type",
                    options=[
                        {"label": "Quick Scan (-F)", "value": "quick"},
                        {"label": "Ping Scan (-sn)", "value": "ping"},
                        {"label": "Service Detection (-sV)", "value": "full"},
                        {"label": "Top 1000 Ports", "value": "ports"},
                        {"label": "OS Detection (-O)", "value": "os"},
                        {"label": "Default Scripts (-sC)", "value": "scripts"},
                    ],
                    value="quick",
                    clearable=False,
                    style={
                        "width": "220px", "backgroundColor": "#0a1520",
                        "color": "#c8e6f5", "border": "1px solid #0f3a5c",
                        **RAJDHANI, "fontSize": "12px",
                    },
                ),
                html.Button("▶ Run Scan", id="btn-nmap-scan", n_clicks=0, style={
                    "backgroundColor": "rgba(0,255,136,0.1)",
                    "color": "#00ff88", "border": "1px solid #00ff88",
                    "borderRadius": "4px", "padding": "8px 18px",
                    **RAJDHANI, "fontSize": "13px", "cursor": "pointer",
                    "letterSpacing": "1px", "whiteSpace": "nowrap",
                }),
            ], style={"display": "flex", "gap": "10px", "flexWrap": "wrap", "marginBottom": "14px"}),

            dcc.Loading(
                id="loading-nmap",
                type="dot",
                color="#00ff88",
                children=html.Div(id="nmap-results", style={"minHeight": "40px"}),
            ),
        ], style={**PANEL, "marginBottom": "20px"}),

        # ── URL Scanner ───────────────────────────────────────────────────────
        html.Div([
            html.Div("🌐 URL / Domain Scanner", style={
                **RAJDHANI, "fontSize": "15px", "fontWeight": "700",
                "color": "#a78bfa", "letterSpacing": "1px", "marginBottom": "12px",
            }),
            html.Div([
                dcc.Input(
                    id="url-input",
                    type="text",
                    placeholder="Enter URL to scan (e.g. https://example.com)",
                    style={
                        "flex": "1", "backgroundColor": "#050a0f",
                        "color": "#c8e6f5", "border": "1px solid #0f3a5c",
                        "borderRadius": "4px", "padding": "8px 12px",
                        **MONO, "fontSize": "12px", "outline": "none",
                    },
                ),
                html.Button("🔎 Scan URL", id="btn-url-scan", n_clicks=0, style={
                    "backgroundColor": "rgba(167,139,250,0.1)",
                    "color": "#a78bfa", "border": "1px solid #a78bfa",
                    "borderRadius": "4px", "padding": "8px 18px",
                    **RAJDHANI, "fontSize": "13px", "cursor": "pointer",
                    "letterSpacing": "1px", "whiteSpace": "nowrap",
                }),
            ], style={"display": "flex", "gap": "10px", "marginBottom": "14px"}),

            dcc.Loading(
                id="loading-url",
                type="dot",
                color="#a78bfa",
                children=html.Div(id="url-scan-results", style={"minHeight": "40px"}),
            ),
        ], style={**PANEL, "marginBottom": "20px"}),

        # ── Tool Cards Grid ───────────────────────────────────────────────────
        html.Div("Security Tools Reference", style={
            **RAJDHANI, "fontSize": "15px", "fontWeight": "700",
            "color": "#c8e6f5", "letterSpacing": "1px", "marginBottom": "14px",
        }),

        html.Div([
            _tool_card(t) for t in TOOLS
        ], style={
            "display": "grid",
            "gridTemplateColumns": "repeat(auto-fill, minmax(340px, 1fr))",
            "gap": "12px",
        }),

    ], style={"padding": "4px 0"})
