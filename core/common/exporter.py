import json
import csv
from pathlib import Path

def export_data(data, filename):
    path = Path(filename)
    extension = path.suffix.lower()

    try:
        if extension == '.json':
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return True, f"Reporte guardado exitosamente en JSON: {path}"

        elif extension == '.csv':
            if not data:
                return False, "No hay datos para exportar."
            
            keys = data[0].keys()
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(data)
            return True, f"Reporte guardado exitosamente en CSV: {path}"

        else:
            return False, "Formato no soportado. Usa .json o .csv"

    except Exception as e:
        return False, f"Error al exportar: {e}"