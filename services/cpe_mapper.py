"""
Best-effort mapping from nmap service output to NVD CPE 2.3 identifiers.
"""

VENDOR_MAP = {
    "apache":       ("apache", "http_server"),
    "httpd":        ("apache", "http_server"),
    "nginx":        ("nginx", "nginx"),
    "openssh":      ("openbsd", "openssh"),
    "openssl":      ("openssl", "openssl"),
    "vsftpd":       ("vsftpd", "vsftpd"),
    "proftpd":      ("proftpd", "proftpd"),
    "samba":        ("samba", "samba"),
    "smbd":         ("samba", "samba"),
    "postfix":      ("postfix", "postfix"),
    "exim":         ("exim", "exim"),
    "bind":         ("isc", "bind"),
    "named":        ("isc", "bind"),
    "mysql":        ("mysql", "mysql"),
    "mariadb":      ("mariadb", "mariadb"),
    "postgresql":   ("postgresql", "postgresql"),
    "microsoft":    ("microsoft", "iis"),
    "iis":          ("microsoft", "iis"),
    "lighttpd":     ("lighttpd", "lighttpd"),
    "tomcat":       ("apache", "tomcat"),
    "jetty":        ("eclipse", "jetty"),
    "php":          ("php", "php"),
    "wordpress":    ("wordpress", "wordpress"),
    "openssl":      ("openssl", "openssl"),
    "dropbear":     ("dropbear_ssh_project", "dropbear_ssh"),
    "telnetd":      ("netkit", "netkit_telnetd"),
    "netkit_rsh":   ("netkit", "netkit_rsh"),
    "rsh":          ("netkit", "netkit_rsh"),
    "pppd":         ("samba", "ppp"),
}


def _cpe(vendor: str, product: str, version: str) -> str:
    v = version.strip() if version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


def _from_service(svc: dict):
    product = (svc.get("product") or "").strip().lower()
    name = (svc.get("name") or "").strip().lower()
    version = (svc.get("version") or "").strip()

    for key in (product, name):
        if key and key in VENDOR_MAP:
            vendor, prod = VENDOR_MAP[key]
            return _cpe(vendor, prod, version)

    if product:
        prod = product.replace(" ", "_")
        return _cpe(product.split()[0], prod, version)
    return None


def build_cpes(hosts: dict):
    """Return {host_ip: [[port_label, cpe], ...]}"""
    result = {}
    for ip, info in hosts.items():
        lst = []
        for port_label, svc in (info.get("scan") or {}).items():
            if svc.get("state") != "open":
                continue
            cpe = _from_service(svc)
            if cpe:
                lst.append([port_label, cpe])
        result[ip] = lst
    return result
