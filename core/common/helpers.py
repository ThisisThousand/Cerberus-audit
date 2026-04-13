import ipaddress
from collections import defaultdict

def classify_ip(ip):
   
    ip_clean = ip.strip('[]').split('%')[0]
    
    if ip_clean in ["*", "0.0.0.0", "::", "::1", "localhost"]:
        return "loopback"

    try:
        addr = ipaddress.ip_address(ip_clean)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        if addr.is_multicast:
            return "multicast"
        if addr.is_reserved:
            return "reserved"
        return "external"
    except ValueError:
        return "unknown"

def analyze_connections(connections):

    summary = {
        "total": len(connections), 
        "by_pid": defaultdict(list), 
        "external_ips": set(), 
        "private_ips": set(), 
        "unusual_ports": set(),
        "established_count": 0
    }

    common_ports = {
        22,   # SSH
        53,   # DNS
        80,   # HTTP
        443,  # HTTPS
        3306, # MySQL
        3389, # RDP
        5432, # PostgreSQL
        8080, # HTTP Alt
    }

    for c in connections:
        pid = c.get("pid")
        summary["by_pid"][pid].append(c)
        
        if c.get("state") == "ESTABLISHED":
            summary["established_count"] += 1
            
        remote_ip = str(c.get("remote_ip"))
        ip_type = classify_ip(remote_ip)
        
        if ip_type == "external":
            summary["external_ips"].add(remote_ip)
        elif ip_type == "private":
            summary["private_ips"].add(remote_ip)
            
        local_port = c.get("local_port")
        if isinstance(local_port, int):
            if local_port not in common_ports and local_port > 1024:
                if c.get("state") in ["LISTENING", "ESTABLISHED"]:
                    summary["unusual_ports"].add(local_port)

    return summary

def format_bytes(size):
    """Convierte bytes a formato legible (KB, MB, GB)."""
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"