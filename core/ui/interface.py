from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

def get_fresh_console():
    return Console()

def display_header(lang):
    console = get_fresh_console()
    title = Text(lang.get('title', 'Cerberus Audit'), justify="center", style="bold white")
    console.print(Panel(title, border_style="bright_blue", expand=True))

def display_help_panel(lang):
    console = get_fresh_console()
    help_text = Text()
    
    command_keys = [
        'list_cmd', 'list_pid', 'list_external', 'process_cmd', 
        'summary_cmd', 'export_cmd', 'npm_cmd', 'help_cmd', 
        'graph_cmd', 'grafo_cmd', 'kill_cmd', 'exit_cmd', 'npm_locate_cmd', 'npm_global_cmd'
    ]
    
    help_text.append(f"{lang.get('commands_title', 'Available Commands')}:\n", style="bold cyan")
    
    for key in command_keys:
        cmd_desc = lang.get(key)
        if cmd_desc:
            help_text.append(f"   • {cmd_desc}\n", style="white")
    
    console.print(Panel(
        help_text, 
        title="[bold white]Menu[/bold white]", 
        border_style="bright_blue", 
        expand=True
    ))

def show_connections_table(lang, connections):
    console = get_fresh_console()
    if not connections:
        console.print(f"[bold red]{lang.get('no_connections', 'No connections found.')}[/bold red]")
        return
        
    table = Table(
        title="Cerberus Scan Results", 
        border_style="bright_blue", 
        expand=True,
        header_style="bold cyan"
    )
    
    table.add_column(lang.get('pid', 'PID'), justify="right")
    table.add_column(lang.get('proto', 'Proto'))
    table.add_column(lang.get('local', 'Local Address'))
    table.add_column(lang.get('remote', 'Remote Address'))
    table.add_column(lang.get('state', 'State'))
    
    for c in connections:
        table.add_row(
            str(c.get('pid', 'N/A')), 
            c.get('protocol', '??'),
            f"{c.get('local_ip')}:{c.get('local_port')}",
            f"{c.get('remote_ip')}:{c.get('remote_port')}",
            c.get('state', 'UNKNOWN')
        )
    
    console.print(table)