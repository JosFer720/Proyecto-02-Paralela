#!/usr/bin/env python3
"""Calcula promedio, desviación, speedup y eficiencia desde el CSV crudo."""
from __future__ import annotations

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def main() -> int:
    # Obtiene las rutas de entrada y salida desde los argumentos opcionales.
    source = Path(sys.argv[1] if len(sys.argv) > 1 else "resultados/mediciones.csv")
    target = Path(sys.argv[2] if len(sys.argv) > 2 else "resultados/resumen.csv")
    grouped: dict[tuple[int, int], list[float]] = defaultdict(list)
    # Agrupa los tiempos por llave y cantidad de procesos.
    with source.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            grouped[(int(row["llave"]), int(row["procesos"]))].append(
                float(row["tiempo_s"])
            )

    rows = []
    # Calcula las métricas de rendimiento para cada grupo.
    for (key, processes), values in sorted(grouped.items()):
        baseline = grouped.get((key, 1))
        if not baseline:
            raise ValueError(f"Falta la medición base con un proceso para la llave {key}")
        average = statistics.fmean(values)
        t1 = statistics.fmean(baseline)
        speedup = t1 / average
        rows.append(
            {
                "llave": key,
                "procesos": processes,
                "repeticiones": len(values),
                "promedio_s": f"{average:.6f}",
                "desviacion_s": f"{statistics.stdev(values) if len(values) > 1 else 0.0:.6f}",
                "speedup": f"{speedup:.3f}",
                "eficiencia": f"{speedup / processes:.3f}",
            }
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    # Escribe el resumen en formato CSV.
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"Resumen guardado en {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
