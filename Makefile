CC ?= gcc
MPICC ?= mpicc
CPPFLAGS ?=
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CRYPTO_CFLAGS ?=
CRYPTO_LIBS ?= -lcrypto

# Declara los objetivos principales del proyecto.
.PHONY: all test clean

# Compila el programa MPI.
all: build/bruteforce_mpi

# Crea la carpeta para los ejecutables.
build:
	mkdir -p build

# Enlaza el programa con MPI y OpenSSL.
build/bruteforce_mpi: src/bruteforce_mpi.c | build
	$(MPICC) $(CPPFLAGS) $(CFLAGS) $(CRYPTO_CFLAGS) $< -o $@ $(CRYPTO_LIBS)

# Compila las pruebas del núcleo.
build/test_core: tests/test_core.c src/bruteforce_mpi.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

# Ejecuta las pruebas automatizadas.
test: build/test_core
	./build/test_core

# Elimina los archivos generados.
clean:
	rm -rf build
