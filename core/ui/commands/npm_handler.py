from rich.table import Table
from rich import print as rprint
from core.ui.interface import get_fresh_console

def handle_npm_command(auditor, params, lang):
    console = get_fresh_console()
    
    # 1. GESTIÓN DE SUBCOMANDOS (Argumentos específicos)
    if params:
        subcommand = params[0].lower()

        # Caso: npm raiz / npm root / npm locate
        if subcommand in ["locate", "raiz", "root"]:
            locations = auditor.find_npm_install_locations()
            table = Table(title=lang.get('npm_locate_title', "NPM Installations"), border_style="bright_blue")
            table.add_column(lang.get('npm_path_col', "Path"), style="yellow")
            table.add_column(lang.get('npm_ver_col', "Version"), justify="center", style="green")
            
            for loc in locations:
                table.add_row(loc['path'], loc['version'])
            
            console.print("\n", table)
            return

        # Caso: npm globales / npm global
        if subcommand in ["global", "globales"]:
            pkgs = auditor.list_global_packages()
            console.print(f"\n[bold cyan] {lang.get('npm_global_list_title', 'Global Packages:')}[/bold cyan]")
            if not pkgs:
                console.print("  [dim]No global packages detected.[/dim]")
            else:
                for p in pkgs:
                    rprint(f" [blue]•[/blue] {p}")
            return

    # 2. GESTIÓN DE AUDITORÍA (Si no es subcomando, es una ruta)
    target_path = params[0] if params else "."
    
    # Corregimos el formato del mensaje de inicio
    start_text = lang.get('npm_start', 'Iniciando auditoría en {}')
    if "{}" in start_text:
        start_msg = start_text.format(target_path)
    else:
        start_msg = f"{start_text} {target_path}"
        
    console.print(f"\n[bold yellow]🔍 {start_msg}[/bold yellow]")
    
    # Ejecutar motor de auditoría
    res = auditor.audit_all(target_path=target_path)

    # Verificar si hubo errores de ruta (ej: no hay package.json)
    if res.get("audit_errors"):
        console.print(f"[bold red] [-] {res['audit_errors']}[/bold red]")
        return

    # 3. RENDERIZADO DE RESULTADOS
    # Tabla de Configuración y Datos Generales
    config_table = Table(title=lang.get('npm_project_title', "PROJECT DATA"), show_header=False, border_style="dim")
    config_table.add_row(lang.get('npm_size', 'Size'), f"[bold white]{res.get('node_modules_size_mb', 0)} MB[/bold white]")
    
    paths = auditor.get_npm_config_paths()
    config_table.add_row(lang.get('npm_prefix', 'Prefix'), f"[dim]{paths.get('global_prefix', 'N/A')}[/dim]")
    config_table.add_row(lang.get('npm_cache', 'Cache'), f"[dim]{paths.get('cache_path', 'N/A')}[/dim]")
    
    console.print(config_table)

    # Alertas de Seguridad: Scripts Sospechosos (BLINDADO)
    if res.get('suspicious_scripts'):
        console.print(f"\n[bold red] 🔥 {lang.get('npm_scripts', 'Suspicious Scripts')}:[/bold red]")
        for s in res['suspicious_scripts']:
            # Forzamos que cada tag sea string para evitar errores de .join()
            tags_list = [str(t) for t in s.get('tags', [])]
            tags_str = ", ".join(tags_list)
            
            msg_template = lang.get('npm_alert_script', "Script '{}' contains: {}")
            console.print(msg_template.format(s.get('name', '???'), tags_str))

    # Alertas de Seguridad: Paquetes Maliciosos (Blacklist)
    if res.get('malicious_packages'):
        console.print(f"\n[bold red] 💀 {lang.get('npm_malicious', 'Malicious Packages')}:[/bold red]")
        for m in res['malicious_packages']:
            msg_malicious = lang.get('npm_critical_malicious', "Blacklisted package: {}")
            console.print(msg_malicious.format(m))

    # Tabla de Vulnerabilidades (npm audit) (BLINDADO)
    if res.get('vulnerabilities'):
        vuln_table = Table(title=lang.get('npm_vulns', "Vulnerabilities"), border_style="red")
        vuln_table.add_column("Package", style="cyan")
        vuln_table.add_column("Severity", style="bold red")
        vuln_table.add_column("Via", style="dim")

        for v in res['vulnerabilities']:
            # Procesamos 'via' para extraer nombres si vienen diccionarios
            raw_via = v.get('via', [])
            via_elements = []
            
            if isinstance(raw_via, list):
                for item in raw_via:
                    if isinstance(item, dict):
                        via_elements.append(str(item.get('name', 'unknown')))
                    else:
                        via_elements.append(str(item))
                via_str = ", ".join(via_elements)
            else:
                via_str = str(raw_via)
                
            vuln_table.add_row(
                str(v.get('package', 'unknown')), 
                str(v.get('severity', 'unknown')).upper(), 
                via_str
            )
        
        console.print("\n", vuln_table)
    else:
        console.print(f"\n[bold green] ✅ No se encontraron vulnerabilidades conocidas.[/bold green]")