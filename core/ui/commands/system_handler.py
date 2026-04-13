from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

from core.network.connections import get_connections
from core.common.helpers import analyze_connections
from core.common.security_checks import audit_privileged_ports
from core.common.exporter import export_data 
from core.ui.interface import get_fresh_console

def handle_summary(lang):
    console = get_fresh_console()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
        progress.add_task("[cyan]Obteniendo conexiones...", total=None)
        all_c = get_connections()
        progress.add_task("[magenta]Analizando tráfico...", total=None)
        stats = analyze_connections(all_c)
        progress.add_task("[red]Auditando privilegios...", total=None)
        security_issues = audit_privileged_ports(all_c)

    unusual = list(stats['unusual_ports'])
    p_str = ", ".join(map(str, unusual[:8]))
    
    res_text = (
        f"[bold white]{lang.get('total_conns', 'Total Connections')}:[/bold white] {stats['total']}\n"
        f"[bold white]{lang.get('ext_conns', 'External')}:[/bold white] [bold red]{len(stats['external_ips'])}[/bold red]\n"
    )
    if unusual:
        res_text += f"[bold white]{lang.get('unusual_ports', 'Unusual Ports')}:[/bold white] [bold yellow]{p_str}[/bold yellow]\n"


    if security_issues:
        res_text += "\n\n[bold red]⚠  ALERTA DE SEGURIDAD:[/bold red]"
        for issue in security_issues:
            res_text += f"\n[bold yellow]![/bold yellow] {issue['name']} ({issue['pid']}) en puerto {issue['port']}"

    rprint(Panel(Text.from_markup(res_text), title="Summary", border_style="bright_blue", expand=True))


def handle_export(params):
    if params:
        conns = get_connections()
        success, msg = export_data(conns, params[0])
        rprint(f"[{'green' if success else 'red'}]{msg}[/]")
    else:
        rprint("[yellow]Uso: export <nombre_archivo.json/.csv>[/yellow]")