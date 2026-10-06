"""
Full nmap argument builder.
Handles every option exposed in new_scan.html, resolves conflicts on the
server side as a second line of defence (the JS engine is the first).
"""

import nmap

DEFAULT_PORTS = "1-1024"


# ---------------- Presets ----------------
PRESETS = {
    "preset_intense":       "-T4 -A -v",
    "preset_intense_udp":   "-sS -sU -T4 -A -v",
    "preset_quick":         "-T4 -F",
    "preset_quick_plus":    "-sV -T4 -O -F --version-light",
    "preset_ping":          "-sn",
    "preset_regular":       "-sV -T4 -O",
    "preset_slow":          "-sS -sU -T2",
    "preset_vuln":          "-sV --script=vuln",
}


def _bool(opts, key):
    return bool(opts.get(key))


def _str(opts, key):
    v = opts.get(key)
    if v is None:
        return ""
    return str(v).strip()


# ============================================================
# Argument builder
# ============================================================

def _build_args(mode, options):
    options = options or {}

    if mode == "normal":
        return "-sV -T4 --version-intensity 5"

    parts = []

    # ---- Presets ----
    preset_applied = False
    for key, flag in PRESETS.items():
        if _bool(options, key):
            parts.append(flag)
            preset_applied = True
            break

    # If a preset is applied, skip most manual flags except a few extras
    if preset_applied:
        # Only add extras that commonly combine with presets
        if _bool(options, "verbose"):
            parts.append("-v")
        if _bool(options, "no_ping"):
            parts.append("-Pn")
        return " ".join(parts)

    # ---- Primary scan technique ----
    primary_map = [
        ("syn_scan",         "-sS"),
        ("connect_scan",     "-sT"),
        ("ack_scan",         "-sA"),
        ("window_scan",      "-sW"),
        ("maimon_scan",      "-sM"),
        ("null_scan",        "-sN"),
        ("fin_scan",         "-sF"),
        ("xmas_scan",        "-sX"),
        ("idle_scan",        "-sI"),
        ("sctp_init_scan",   "-sY"),
        ("sctp_cookie_scan", "-sZ"),
        ("ip_protocol_scan", "-sO"),
    ]
    for key, flag in primary_map:
        if _bool(options, key):
            parts.append(flag)
            break

    # Idle zombie host
    zombie = _str(options, "idle_zombie")
    if _bool(options, "idle_scan") and zombie:
        parts.append(zombie)

    # FTP bounce needs a relay argument
    if _bool(options, "ftp_bounce"):
        relay = _str(options, "ftp_relay")
        parts.append(f"-b {relay}" if relay else "-b")

    # UDP is additive
    if _bool(options, "udp_scan"):
        parts.append("-sU")

    # ---- Host discovery ----
    if _bool(options, "list_scan"):
        parts.append("-sL")
    elif _bool(options, "no_ping"):
        parts.append("-Pn")
    elif _bool(options, "ping_only"):
        parts.append("-sn")
    else:
        ping_map = [
            ("syn_ping",       "-PS"),
            ("ack_ping",       "-PA"),
            ("udp_ping",       "-PU"),
            ("sctp_ping",      "-PY"),
            ("icmp_echo",      "-PE"),
            ("icmp_timestamp", "-PP"),
            ("icmp_mask",      "-PM"),
            ("ip_proto_ping",  "-PO"),
            ("arp_ping",       "-PR"),
        ]
        for key, flag in ping_map:
            if _bool(options, key):
                parts.append(flag)

    if _bool(options, "disable_arp_ping"):
        parts.append("--disable-arp-ping")

    # ---- Ports ----
    if _bool(options, "fast_scan"):
        parts.append("-F")
    elif _str(options, "top_ports"):
        parts.append(f"--top-ports {int(_str(options, 'top_ports'))}")

    if _str(options, "port_ratio"):
        parts.append(f"--port-ratio {_str(options, 'port_ratio')}")
    if _str(options, "exclude_ports"):
        parts.append(f"--exclude-ports {_str(options, 'exclude_ports')}")
    if _str(options, "exclude_hosts"):
        parts.append(f"--exclude {_str(options, 'exclude_hosts')}")
    if _bool(options, "seq_ports"):
        parts.append("-r")

    # ---- DNS / traceroute ----
    if _str(options, "dns_servers"):
        parts.append(f"--dns-servers {_str(options, 'dns_servers')}")
    if _bool(options, "no_dns"):
        parts.append("-n")
    if _bool(options, "always_dns"):
        parts.append("-R")
    if _bool(options, "system_dns"):
        parts.append("--system-dns")
    if _bool(options, "traceroute"):
        parts.append("--traceroute")

    # ---- Service / Version ----
    if _bool(options, "aggressive"):
        parts.append("-A")
    else:
        if _bool(options, "version_detect"):
            parts.append("-sV")
        if _bool(options, "version_light"):
            parts.append("--version-light")
        elif _bool(options, "version_all"):
            parts.append("--version-all")
        else:
            vi = _str(options, "version_intensity")
            if vi and vi != "5":
                parts.append(f"--version-intensity {int(vi)}")
        if _bool(options, "version_trace"):
            parts.append("--version-trace")
        if _bool(options, "all_ports"):
            parts.append("--allports")

    # ---- OS detection ----
    if _bool(options, "os_detect"):
        parts.append("-O")
    if _bool(options, "osscan_limit"):
        parts.append("--osscan-limit")
    if _bool(options, "osscan_guess"):
        parts.append("--osscan-guess")
    if _str(options, "max_os_tries"):
        parts.append(f"--max-os-tries {int(_str(options, 'max_os_tries'))}")

    # ---- NSE scripts ----
    if _bool(options, "script_default"):
        parts.append("-sC")
    if _bool(options, "script_vuln"):
        parts.append("--script=vuln")
    if _str(options, "script"):
        parts.append(f"--script {_str(options, 'script')}")
    if _str(options, "script_args"):
        parts.append(f"--script-args {_str(options, 'script_args')}")
    if _str(options, "script_args_file"):
        parts.append(f"--script-args-file {_str(options, 'script_args_file')}")
    if _str(options, "script_help"):
        parts.append(f"--script-help {_str(options, 'script_help')}")
    if _bool(options, "script_trace"):
        parts.append("--script-trace")
    if _bool(options, "script_updatedb"):
        parts.append("--script-updatedb")

    # ---- Timing & performance ----
    parts.append(f"-{_str(options, 'timing') or 'T4'}")

    timing_fields = [
        ("min_rate",             "--min-rate"),
        ("max_rate",             "--max-rate"),
        ("min_parallelism",      "--min-parallelism"),
        ("max_parallelism",      "--max-parallelism"),
        ("min_hostgroup",        "--min-hostgroup"),
        ("max_hostgroup",        "--max-hostgroup"),
        ("max_hostgroup2",       "--max-hostgroup"),
        ("max_retries",          "--max-retries"),
    ]
    for key, flag in timing_fields:
        v = _str(options, key)
        if v:
            try:
                parts.append(f"{flag} {int(v)}")
            except ValueError:
                parts.append(f"{flag} {v}")

    time_str_fields = [
        ("host_timeout",         "--host-timeout"),
        ("scan_delay",           "--scan-delay"),
        ("max_scan_delay",       "--max-scan-delay"),
        ("min_rtt_timeout",      "--min-rtt-timeout"),
        ("max_rtt_timeout",      "--max-rtt-timeout"),
        ("initial_rtt_timeout",  "--initial-rtt-timeout"),
    ]
    for key, flag in time_str_fields:
        v = _str(options, key)
        if v:
            parts.append(f"{flag} {v}")

    if _bool(options, "defeat_rst_ratelimit"):
        parts.append("--defeat-rst-ratelimit")
    if _bool(options, "defeat_icmp_ratelimit"):
        parts.append("--defeat-icmp-ratelimit")

    # ---- Evasion / spoofing ----
    if _bool(options, "fragment"):
        parts.append("-f")
    if _str(options, "mtu"):
        try:
            parts.append(f"--mtu {int(_str(options, 'mtu'))}")
        except ValueError:
            pass
    if _str(options, "decoys"):
        parts.append(f"-D {_str(options, 'decoys')}")
    if _str(options, "spoof_ip"):
        parts.append(f"-S {_str(options, 'spoof_ip')}")
    if _str(options, "interface"):
        parts.append(f"-e {_str(options, 'interface')}")
    if _str(options, "source_port"):
        parts.append(f"--source-port {_str(options, 'source_port')}")
    if _str(options, "data_length"):
        try:
            parts.append(f"--data-length {int(_str(options, 'data_length'))}")
        except ValueError:
            pass
    if _str(options, "data_string"):
        parts.append(f'--data-string "{_str(options, "data_string")}"')
    if _str(options, "data_hex"):
        parts.append(f"--data {_str(options, 'data_hex')}")
    if _str(options, "ip_options"):
        parts.append(f"--ip-options {_str(options, 'ip_options')}")
    if _str(options, "ttl"):
        try:
            parts.append(f"--ttl {int(_str(options, 'ttl'))}")
        except ValueError:
            pass
    if _str(options, "spoof_mac"):
        parts.append(f"--spoof-mac {_str(options, 'spoof_mac')}")
    if _bool(options, "randomize_hosts"):
        parts.append("--randomize-hosts")
    if _bool(options, "badsum"):
        parts.append("--badsum")
    if _bool(options, "send_eth"):
        parts.append("--send-eth")
    if _bool(options, "send_ip"):
        parts.append("--send-ip")
    if _bool(options, "privileged"):
        parts.append("--privileged")
    if _bool(options, "unprivileged"):
        parts.append("--unprivileged")
    if _str(options, "scanflags"):
        parts.append(f"--scanflags {_str(options, 'scanflags')}")

    # ---- Output / verbosity / misc ----
    if _bool(options, "verbose"):
        parts.append("-v")
    if _bool(options, "very_verbose"):
        parts.append("-vv")
    if _bool(options, "debug"):
        parts.append("-d")
    if _bool(options, "reason"):
        parts.append("--reason")
    if _bool(options, "open_only"):
        parts.append("--open")
    if _bool(options, "packet_trace"):
        parts.append("--packet-trace")
    if _bool(options, "log_errors"):
        parts.append("--log-errors")
    if _bool(options, "append_output"):
        parts.append("--append-output")
    if _bool(options, "iflist"):
        parts.append("--iflist")
    if _bool(options, "release_memory"):
        parts.append("--release-memory")
    if _str(options, "resume"):
        parts.append(f"--resume {_str(options, 'resume')}")

    # ---- IPv6 / DB paths / nsock ----
    if _bool(options, "ipv6"):
        parts.append("-6")
    if _str(options, "datadir"):
        parts.append(f"--datadir {_str(options, 'datadir')}")
    if _str(options, "servicedb"):
        parts.append(f"--servicedb {_str(options, 'servicedb')}")
    if _str(options, "versiondb"):
        parts.append(f"--versiondb {_str(options, 'versiondb')}")
    if _str(options, "nsock_engine"):
        parts.append(f"--nsock-engine {_str(options, 'nsock_engine')}")
    if _bool(options, "webxml"):
        parts.append("--webxml")
    if _bool(options, "no_stylesheet"):
        parts.append("--no-stylesheet")

    # Safety net
    if not parts:
        parts.append("-sV")

    return " ".join(parts)


# ============================================================
# Runner
# ============================================================

def run_scan(target, mode="normal", options=None):
    options = options or {}

    # ---- Ports argument ----
    if mode == "normal":
        ports = DEFAULT_PORTS
    elif (
        _bool(options, "ping_only")
        or _bool(options, "list_scan")
        or _bool(options, "fast_scan")
        or _str(options, "top_ports")
        or any(_bool(options, k) for k in PRESETS)
    ):
        ports = None
    else:
        ports = _str(options, "ports") or DEFAULT_PORTS

    args = _build_args(mode, options)
    print(f"[scanner] mode={mode} args={args!r} ports={ports!r}")

    nm = nmap.PortScanner()
    kwargs = {"hosts": target, "arguments": args}
    if ports:
        kwargs["ports"] = ports

    try:
        nm.scan(**kwargs)
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"nmap error: {exc}") from exc

    hosts = {}
    for host in nm.all_hosts():
        info = nm[host]
        entry = {
            "status":    {"state": info.state()},
            "hostnames": info.hostnames(),
            "addresses": info.get("addresses", {}),
            "vendor":    info.get("vendor", {}),
            "scan":      {},
        }
        for proto in info.all_protocols():
            for port in info[proto]:
                data = dict(info[proto][port])
                data["protocol"] = proto
                data["port"] = port
                if isinstance(data.get("cpe"), str):
                    data["cpe"] = [data["cpe"]]
                entry["scan"][f"{proto}:{port}"] = data
        hosts[host] = info.to_dict() if hasattr(info, "to_dict") else {
            "status":    {"state": info.state()},
            "hostnames": info.hostnames(),
            "addresses": info.get("addresses", {}),
            "vendor":    info.get("vendor", {}),
            "scan":      {
                f"{proto}:{port}": {**dict(info[proto][port]), "protocol": proto, "port": port}
                for proto in info.all_protocols()
                for port in info[proto]
            },
        }
    return hosts
