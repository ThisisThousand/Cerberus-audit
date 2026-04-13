import subprocess
import json
import os
import re
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from core.platform.platform_utils import IS_WINDOWS

class NPMAuditor:
    def __init__(self, root_path: str = ".", verbose: bool = False):
        self.root_path = Path(root_path).resolve()
        self.verbose = verbose
        self.npm_exec = self._resolve_npm_path()
        self.reset_results()

    def reset_results(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "path": str(self.root_path),
            "vulnerabilities": [],
            "outdated": [],
            "suspicious_scripts": [],
            "malicious_packages": [],
            "audit_errors": None,
            "node_modules_size_mb": 0,
            "install_scripts": [],
        }

    def _resolve_npm_path(self) -> str:
        base_cmd = "npm.cmd" if IS_WINDOWS else "npm"
        found_path = shutil.which(base_cmd)
        if found_path:
            return found_path
        
        if IS_WINDOWS:
            common_paths = [
                r"C:\Program Files\nodejs\npm.cmd",
                r"C:\Program Files (x86)\nodejs\npm.cmd",
                os.path.join(os.environ.get("APPDATA", ""), "npm", "npm.cmd")
            ]
            for path in common_paths:
                if os.path.isfile(path):
                    return path
        return base_cmd

    def _run_npm(self, args: List[str], cwd: Optional[str] = None, timeout: int = 30) -> Tuple[bool, str]:
        try:
            target_cwd = cwd or str(self.root_path)
            result = subprocess.run(
                [self.npm_exec] + args,
                cwd=target_cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=IS_WINDOWS
            )
            return True, result.stdout.strip()
        except Exception as e:
            return False, str(e)

    def find_npm_install_locations(self) -> List[Dict[str, str]]:
        found_locations = []
        base_cmd = "npm.cmd" if IS_WINDOWS else "npm"
        env_paths = os.environ.get("PATH", "").split(os.pathsep)
        
        extra_dirs = []
        if IS_WINDOWS:
            extra_dirs = [os.environ.get("ProgramFiles", ""), os.environ.get("APPDATA", "")]
        else:
            extra_dirs = ["/usr/local/bin", "/usr/bin", "/opt"]

        search_set = set(env_paths + extra_dirs)
        
        for folder in search_set:
            if not folder or not os.path.isdir(folder): continue
            full_path = Path(folder) / base_cmd
            if full_path.exists():
                try:
                    ver = subprocess.run([str(full_path), "--version"], capture_output=True, text=True, shell=IS_WINDOWS, timeout=5)
                    version_str = ver.stdout.strip() if ver.returncode == 0 else "Error"
                except:
                    version_str = "Unknown"
                found_locations.append({"path": str(full_path), "version": version_str})
        return found_locations

    def get_npm_config_paths(self) -> Dict[str, str]:
        paths = {}
        _, prefix = self._run_npm(["config", "get", "prefix"])
        paths["global_prefix"] = prefix if prefix else "Not detected"
        
        _, cache = self._run_npm(["config", "get", "cache"])
        paths["cache_path"] = cache if cache else "Not detected"

        paths["userconfig"] = str(Path.home() / ".npmrc")
        return paths

    def load_project_data(self) -> Optional[Dict]:
        pkg_file = self.root_path / "package.json"
        if not pkg_file.exists():
            return None
        try:
            with open(pkg_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return None

    def get_node_modules_size(self) -> float:
        nm_path = self.root_path / "node_modules"
        if not nm_path.exists():
            return 0.0
        try:
            total_size = sum(f.stat().st_size for f in nm_path.rglob('*') if f.is_file())
            return round(total_size / (1024 * 1024), 2)
        except:
            return 0.0

    def detect_suspicious_scripts(self, pkg: Dict) -> List[Dict]:
        scripts = pkg.get("scripts", {})
        suspicious = []
        patterns = {
            "downloader": r"(curl|wget|fetch|powershell|Invoke-WebRequest)",
            "execution": r"(eval|exec|sh\s|bash\s|iex|node\s+-e)",
            "obfuscation": r"(base64|\\x[0-9a-fA-F]{2}|[A-Za-z0-9+/=]{50,})",
        }
        for name, content in scripts.items():
            if not isinstance(content, str): continue
            tags = [tag for tag, pat in patterns.items() if re.search(pat, content, re.I)]
            if tags:
                suspicious.append({"name": name, "script": content, "tags": tags})
        return suspicious

    def run_audit(self) -> List[Dict]:
        success, output = self._run_npm(["audit", "--json"])
        if not success or not output:
            return []
        try:
            data = json.loads(output)
            vulns = []
            items = data.get("vulnerabilities", data.get("advisories", {}))
            for key, val in items.items():
                vulns.append({
                    "package": val.get("name", key),
                    "severity": val.get("severity", "unknown"),
                    "via": val.get("via", []) if isinstance(val.get("via"), list) else [val.get("via")]
                })
            return vulns
        except:
            return []

    def audit_all(self, target_path: str = None) -> Dict:
        if target_path:
            self.root_path = Path(target_path).resolve()
        self.reset_results()
        pkg = self.load_project_data()
        if not pkg:
            self.results["audit_errors"] = f"No package.json at {self.root_path}"
            return self.results
        self.results["vulnerabilities"] = self.run_audit()
        self.results["suspicious_scripts"] = self.detect_suspicious_scripts(pkg)
        self.results["node_modules_size_mb"] = self.get_node_modules_size()
        blacklist = {"event-stream", "flatmap-stream", "es5-ext", "http-proxy-agent-hook"}
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        self.results["malicious_packages"] = [p for p in deps if p in blacklist]
        return self.results

    def list_global_packages(self) -> List[str]:
        success, output = self._run_npm(["list", "-g", "--depth=0"])
        if not success:
            return ["Error: Could not list packages."]
        return [line.strip() for line in output.split('\n') if "──" in line]