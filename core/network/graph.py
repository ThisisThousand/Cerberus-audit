import ipaddress
from collections import defaultdict
from core.network.process import get_process_info
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

def generate_ascii_graph(connections, show_ports=True, max_ips_per_pid=15, sort_ips=True, show_summary=True):
    if not connections:
        return "No hay conexiones activas para mostrar."

    tree = defaultdict(set)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True,
    ) as progress:
        
        task = progress.add_task("[cyan]Generando grafo...", total=len(connections))

        for c in connections:
            pid = c.get('pid')
            pid_val = pid if pid is not None else '?'
            
            remote_ip = c.get('remote_ip')
            if not remote_ip or remote_ip in ('0.0.0.0', '*', '::'):
                progress.advance(task)
                continue

            p_info = get_process_info(pid_val) if isinstance(pid_val, int) else None
            p_name = p_info['name'] if p_info else "Unknown"
            node_label = f"[{p_name} ({pid_val})]"

            if show_ports:
                remote_port = c.get('remote_port')
                key = f"{remote_ip}:{remote_port}" if remote_port and remote_port != '*' else remote_ip
            else:
                key = remote_ip
                
            tree[node_label].add(key)
            progress.advance(task)

    if not tree:
        return "No se encontraron conexiones externas válidas."

    node_labels = sorted(tree.keys())
    output = []
    total_connections = sum(len(ips) for ips in tree.values())
    total_nodes = len(node_labels)
    
    for i, label in enumerate(node_labels):
        is_last_node = (i == len(node_labels) - 1)
        node_prefix = "└── " if is_last_node else "├── "
        output.append(f"{node_prefix}{label}")
        
        remotes = list(tree[label])
        
        if sort_ips:
            def ip_sort_key(ip_str):
                try:
                    ip_part = ip_str.rsplit(':', 1)[0] if ':' in ip_str else ip_str
                    return ipaddress.ip_address(ip_part)
                except:
                    
                    return ipaddress.ip_address("0.0.0.0")
            
            remotes.sort(key=ip_sort_key)
        
        total_remotes = len(remotes)
        if max_ips_per_pid > 0 and total_remotes > max_ips_per_pid:
            remotes = remotes[:max_ips_per_pid]
            truncated = total_remotes - max_ips_per_pid
        else:
            truncated = 0
        
        margin = "    " if is_last_node else "│   "
        for j, ip in enumerate(remotes):
            is_last_ip = (j == len(remotes) - 1) and (truncated == 0)
            ip_connector = "└── " if is_last_ip else "├── "
            output.append(f"{margin}{ip_connector}{ip}")
        
        if truncated > 0:
            output.append(f"{margin}└── ... y {truncated} más")
    
    if show_summary:
        output.append(f"\n📊 Resumen: {total_connections} conexiones desde {total_nodes} procesos.")
    
    return "\n".join(output)