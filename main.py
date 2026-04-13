import os
import sys
from rich import print as rprint
from core.ui.interface import display_header, display_help_panel
from core.common.constants import LANG_EN, LANG_ES
from core.platform.platform_utils import ensure_admin_privileges
from core.ui.commands.network_handler import handle_list, handle_graph, handle_kill, handle_process
from core.ui.commands.system_handler import handle_summary,handle_export
from core.ui.commands.npm_handler import handle_npm_command
from modules.npm.npm_auditor import NPMAuditor

def main():
    ensure_admin_privileges()

    print("Select language / Seleccione idioma (en/es): ", end="")
    choice = input().strip().lower()
    lang = LANG_ES if choice.startswith('es') else LANG_EN
    
    try:
        import readline
        COMMANDS = ['list', 'process', 'summary', 'export', 'npm', 'help', 'exit', 'graph', 'kill']
        readline.set_completer(lambda t, s: [c for c in COMMANDS if c.startswith(t)][s] if s < len([c for c in COMMANDS if c.startswith(t)]) else None)
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass

    os.system('cls' if os.name == 'nt' else 'clear')
    display_header(lang)
    display_help_panel(lang)

    auditor = NPMAuditor()
    rprint("[bold green][+] npm detected[/bold green]" if auditor.npm_exec else "[bold red][-] npm not detected[/bold red]")


    while True:
        try:
            line = input("\n>> ").strip().split()
            if not line: continue
            
            cmd = line[0].lower()
            params = line[1:]

            if cmd in ['exit', 'salir', 'quit']:
                rprint("[bold yellow]Cerrando Cerberus...[/bold yellow]")
                break
            elif cmd in ['help', 'ayuda', '?']:
                display_help_panel(lang)

            elif cmd == 'list':
                handle_list(params, lang)
                
            elif cmd in ['grafo', 'graph']:
                handle_graph(params)
                
            elif cmd in ['kill', 'matar']:
                handle_kill(params, lang)
                
            elif cmd in ['proceso', 'process']:
                handle_process(params, lang)

            elif cmd in ['resumen', 'summary']:
                handle_summary(lang)
                
            elif cmd == 'export':
                handle_export(params)

            elif cmd == 'npm':
                handle_npm_command(auditor, params, lang)

            else:
                rprint(f"[bold red]⚠ Comando desconocido:[/bold red] {cmd}")

        except KeyboardInterrupt:
            rprint("\n[yellow]Saliendo...[/yellow]")
            break
        except Exception as e:
            rprint(f"[bold red] [-] Error:[/bold red] {e}")

if __name__ == "__main__":
    main()