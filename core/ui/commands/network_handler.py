from rich.panel import Panel
from rich import print as rprint
from core.network.connections import get_connections
from core.network.process import get_process_info
from core.network.graph import generate_ascii_graph
from core.network.process_manager import kill_process_interactive
from core.common.helpers import classify_ip
from core.ui.interface import show_connections_table

def handle_list(params, lang):
    conns = get_connections()
    if not params:
        show_connections_table(lang, conns)
    elif params[0].isdigit():
        filtered = [c for c in conns if c.get('pid') == int(params[0])]
        show_connections_table(lang, filtered)
    elif params[0] in ['externas', 'external']:
        filtered = [c for c in conns if classify_ip(c.get('remote_ip')) == "external"]
        show_connections_table(lang, filtered)

def handle_graph(params):
    show_ports = 'ports' in params or 'puertos' in params
    conns = get_connections()
    graph_output = generate_ascii_graph(conns, show_ports=show_ports)
    rprint(Panel(graph_output, title="Network Topology", border_style="magenta", expand=True))

def handle_kill(params, lang):
    if params:
        success, msg = kill_process_interactive(params[0], lang)
        rprint(f"[{'green' if success else 'red'}]{msg}[/]")
    else:
        rprint("[yellow]Uso: kill <pid>[/yellow]")

def handle_process(params, lang):
    if params and params[0].isdigit():
        info = get_process_info(int(params[0]))
        if info and info.get('name') != "Unknown":
            content = f"PID: {params[0]}\nName: {info.get('name')}\nUser: {info.get('user')}\nCommand: {info.get('commandline')}"
            rprint(Panel(content, title=lang.get('process_cmd', 'Process Info'), border_style="bright_blue", expand=True))
    else:
        rprint(f"[yellow]{lang.get('usage_proc', 'Uso: proceso <pid>')}[/yellow]")