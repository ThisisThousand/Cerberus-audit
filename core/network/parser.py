import re

def parse_netstat_windows(out):
    
    connections = []
    tcp_pattern = re.compile(r'^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)$', re.IGNORECASE)
    udp_pattern = re.compile(r'^\s*UDP\s+(\S+):(\d+)\s+\*:\*\s+(\d+)$', re.IGNORECASE)

    for line in out.split('\n'):
        line = line.strip()
        m_tcp = tcp_pattern.match(line)
        if m_tcp:
            connections.append({
                "protocol": "TCP",
                "local_ip": m_tcp.group(1),
                "local_port": int(m_tcp.group(2)),
                "remote_ip": m_tcp.group(3),
                "remote_port": int(m_tcp.group(4)),
                "state": m_tcp.group(5),
                "pid": int(m_tcp.group(6))
            })
            continue

        m_udp = udp_pattern.match(line)
        if m_udp:
            connections.append({
                "protocol": "UDP",
                "local_ip": m_udp.group(1),
                "local_port": int(m_udp.group(2)),
                "remote_ip": "*",
                "remote_port": "*",
                "state": "NONE",
                "pid": int(m_udp.group(3))
            })
            
    return connections

def parse_ss_output(out):
    connections = []
    pattern = re.compile(r'^(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+\d+\s+\d+\s+(?P<local>\S+):(?P<lport>\d+)\s+(?P<remote>\S+):(?P<rport>\d+)\s+.*pid=(?P<pid>\d+)')
    
    for line in out.split('\n'):
        line = line.strip()
        if not line: continue
        
        m = pattern.search(line)
        if m:
            connections.append({
                "protocol": m.group('proto').upper(),
                "local_ip": m.group('local').strip('[]'), 
                "local_port": int(m.group('lport')),
                "remote_ip": m.group('remote').strip('[]'),
                "remote_port": int(m.group('rport')),
                "state": m.group('state'),
                "pid": int(m.group('pid'))
            })
    return connections

def parse_netstat_linux(out):
    connections = []
    pattern = re.compile(r'^(?P<proto>tcp|udp)\s+\d+\s+\d+\s+(?P<local>\S+):(?P<lport>\d+)\s+(?P<remote>\S+):(?P<rport>\d+)\s+(?P<state>\S+)\s+(?P<pid>\d+)/')
    
    for line in out.split('\n'):
        line = line.strip()
        m = pattern.search(line)
        if m:
            connections.append({
                "protocol": m.group('proto').upper(),
                "local_ip": m.group('local').strip('[]'),
                "local_port": int(m.group('lport')),
                "remote_ip": m.group('remote').strip('[]'),
                "remote_port": int(m.group('rport')),
                "state": m.group('state'),
                "pid": int(m.group('pid'))
            })
    return connections

def parse_netstat_macos(out):
    connections = []
    pattern = re.compile(r'^(?P<proto>tcp4|tcp6|udp4|udp6)\s+\d+\s+\d+\s+(?P<local>\S+)\s+(?P<remote>\S+)\s+(?P<state>\S+)')
    
    for line in out.split('\n'):
        line = line.strip()
        m = pattern.search(line)
        if m:
            local = m.group('local')
            remote = m.group('remote')
            local_ip, local_port = local.rsplit('.', 1) if '.' in local else (local, '0')
            remote_ip, remote_port = remote.rsplit('.', 1) if '.' in remote else (remote, '0')
            
            connections.append({
                "protocol": m.group('proto').upper(),
                "local_ip": local_ip,
                "local_port": int(local_port) if local_port.isdigit() else 0,
                "remote_ip": remote_ip,
                "remote_port": int(remote_port) if remote_port.isdigit() else 0,
                "state": m.group('state'),
                "pid": None 
            })
    return connections