#!/usr/bin/env bash
set -euo pipefail

# Lee la configuración del experimento desde variables de entorno.
binary="${BINARY:-./build/bruteforce_mpi}"
text_file="${TEXT_FILE:-datos/texto_350_palabras.txt}"
phrase="${PHRASE:-la memoria compartida fortalece a la comunidad}"
upper="${UPPER:-32768}"
runs="${RUNS:-5}"
processes="${PROCESSES:-1 2 4}"
keys="${KEYS:-4095 16383 28671}"
output="${OUTPUT:-resultados/mediciones.csv}"

# Comprueba que existan el ejecutable y el archivo de texto.
if [[ ! -x "$binary" ]]; then
  echo "No se encontró el ejecutable: $binary" >&2
  exit 1
fi
if [[ ! -f "$text_file" ]]; then
  echo "No se encontró el texto: $text_file" >&2
  exit 1
fi

# Prepara el archivo de salida y carga el texto de prueba.
mkdir -p "$(dirname "$output")"
printf 'llave,procesos,repeticion,tiempo_s\n' > "$output"
plaintext="$(<"$text_file")"

# Ejecuta cada combinación de llave, procesos y repetición.
for key in $keys; do
  for p in $processes; do
    for ((run = 1; run <= runs; ++run)); do
      result="$(mpirun --allow-run-as-root --oversubscribe -np "$p" "$binary" \
        --text "$plaintext" --phrase "$phrase" --key "$key" --upper "$upper")"
      found="$(printf '%s\n' "$result" | awk '/Llave encontrada:/ {print $3}')"
      elapsed="$(printf '%s\n' "$result" | awk '/Tiempo:/ {print $2}')"
      if [[ "$found" != "$key" || -z "$elapsed" ]]; then
        echo "Ejecución inválida para llave=$key procesos=$p repetición=$run" >&2
        exit 2
      fi
      printf '%s,%s,%s,%s\n' "$key" "$p" "$run" "$elapsed" >> "$output"
    done
  done
done

# Informa dónde se guardaron las mediciones.
echo "Mediciones guardadas en $output"
