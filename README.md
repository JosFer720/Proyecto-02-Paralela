# Fuerza bruta DES con OpenMPI

## Estructura

- `src/bruteforce_mpi.c`: implementación corregida y paralela.
- `tests/test_core.c`: seis pruebas del núcleo.
- `datos/texto_350_palabras.txt`: texto original de exactamente 350 palabras.
- `scripts/benchmark.sh`: ejecuta 45 mediciones por defecto.
- `scripts/resumir_resultados.py`: calcula promedio, desviación, speedup y eficiencia.
- `resultados/`: observaciones crudas y resumen calculado.
- `imagenes/`: diagramas SVG del informe.
- `informe.md`: documento final solicitado.

## Dependencias en Ubuntu 24.04

```bash
sudo apt update
sudo apt install build-essential openmpi-bin libopenmpi-dev libssl-dev python3
```

El archivo original usa `rpc/des_crypt.h`. Esa interfaz ya no enlaza en una instalación moderna de Ubuntu; la versión entregada conserva DES/ECB, pero usa la implementación DES de OpenSSL 3 (`libcrypto`).

## Compilación y pruebas

```bash
make
make test
```

Ejecución pequeña:

```bash
mpirun -np 4 ./build/bruteforce_mpi \
  --text "Texto con la frase objetivo" \
  --phrase "frase objetivo" \
  --key 23 \
  --upper 64
```

Condiciones: `0 <= key < upper <= 2^56`; `--phrase` no puede estar vacío ni superar el texto. `upper` es exclusivo.

## Repetir el experimento

```bash
bash scripts/benchmark.sh
python3 scripts/resumir_resultados.py
```

Valores predeterminados:

- Llaves: `4095`, `16383` y `28671`.
- Procesos: `1`, `2` y `4`.
- Cinco repeticiones por combinación.
- Espacio experimental: `[0, 32768)`.
- Frase: `la memoria compartida fortalece a la comunidad`.

Se puede cambiar cualquier parámetro mediante variables de entorno, por ejemplo:

```bash
RUNS=7 PROCESSES="1 2 4 8" KEYS="4095 16383 28671" bash scripts/benchmark.sh
```

En Docker Desktop desde PowerShell:

```powershell
docker run --rm -v "${PWD}:/work" -w /work ubuntu:24.04 bash -lc "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential openmpi-bin libopenmpi-dev libssl-dev python3 >/dev/null && make clean && make && make test && bash scripts/benchmark.sh && python3 scripts/resumir_resultados.py"
```

Los tiempos dependen del hardware, carga del sistema, implementación MPI y ubicación de cada llave. Para una comparación válida se deben volver a generar en la máquina o clúster donde se presentará el análisis.
