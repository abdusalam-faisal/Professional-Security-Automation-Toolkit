"""Unified report generation for every toolkit tool: TXT, CSV, JSON."""
import csv
import json
import os
import re
from datetime import datetime

from . import utils


class ReportGenerator:
    """Turns any tool's results into professional reports on disk.

    Implements the doc's 'export capabilities: CSV, JSON and plain text
    report generation' for ALL tools (previously only CSV for ports).
    """

    def __init__(self, output_dir=None):
        base = output_dir or os.path.join(os.path.expanduser("~"), "security_reports")
        self.output_dir = base
        os.makedirs(base, exist_ok=True)

    def _rows_from(self, results):
        """Flatten results into a list of dict rows."""
        if isinstance(results, dict):
            return [_clean(results)]
        if isinstance(results, (list, tuple)):
            rows = []
            for item in results:
                if isinstance(item, dict):
                    rows.append(_clean(item))
                elif isinstance(item, (list, tuple)):
                    rows.append({f"col_{i}": v for i, v in enumerate(item)})
                else:
                    rows.append({"value": item})
            return rows
        return [{"value": str(results)}]

    def save(self, tool_name, results, fmt="txt"):
        """Save a report; returns the path of the written file."""
        stamp = utils.full_stamp()
        safe = re.sub(r"[^\w\-]+", "_", tool_name).strip("_") or "report"
        path = os.path.join(self.output_dir, f"{safe}_{stamp}.{fmt}")
        fmt = fmt.lower().lstrip(".")
        if fmt == "json":
            self._write_json(path, tool_name, results)
        elif fmt == "csv":
            self._write_csv(path, results)
        else:
            self._write_txt(path, tool_name, results)
        return path

    def _write_txt(self, path, tool_name, results):
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("=" * 66 + "\n")
            f.write(" SECURITY AUTOMATION TOOLKIT - REPORT\n")
            f.write(f" Tool: {tool_name}\n")
            f.write(f" Generated: {datetime.now().isoformat(sep=' ', timespec='seconds')}\n")
            f.write("=" * 66 + "\n\n")
            for row in self._rows_from(results):
                for key, value in row.items():
                    label = str(key).replace("_", " ").title()
                    f.write(f"  {label:<28}: {value}\n")
                f.write("-" * 66 + "\n")

    def _write_csv(self, path, results):
        rows = self._rows_from(results) or [{"message": "No data"}]
        keys = []
        for r in rows:
            for k in r:
                if k not in keys:
                    keys.append(k)
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k, "") for k in keys})

    def _write_json(self, path, tool_name, results):
        payload = {
            "tool": tool_name,
            "generated": datetime.now().isoformat(sep=" ", timespec="seconds"),
            "results": results,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)


def _clean(obj):
    """Make a dict JSON-serialisable (sets -> lists, etc.)."""
    out = {}
    for k, v in obj.items():
        if isinstance(v, set):
            v = sorted(v)
        elif isinstance(v, dict):
            v = _clean(v)
        elif isinstance(v, (list, tuple)):
            v = [_clean(x) if isinstance(x, dict) else x for x in v]
        out[k] = v
    return out
