/*
 * Demostracion academica de fuerza bruta DES con MPI.
 * DES y ECB son obsoletos e inseguros para sistemas reales; se conservan
 * exclusivamente porque forman parte de la consigna del curso.
 */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BRUTEFORCE_CORE_TEST
#include <mpi.h>
/* DES es intencional por la consigna; OpenSSL 3 lo marca como obsoleto. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/des.h>
#endif

#define DES_BLOCK_SIZE 8U
#define DES_KEYSPACE_SIZE (UINT64_C(1) << 56)
#define MAX_TEXT_BYTES (1024U * 1024U)
#define SEARCH_BATCH_SIZE UINT64_C(4096)

typedef struct {
    const char *text;
    const char *phrase;
    uint64_t key;
    uint64_t upper;
} CliOptions;

/* Calcula el rango de claves que corresponde a cada proceso MPI. */
bool compute_range(uint64_t key_count, int process_count, int rank,
                   uint64_t *lower, uint64_t *upper) {
    if (process_count <= 0 || rank < 0 || rank >= process_count ||
        lower == NULL || upper == NULL) {
        return false;
    }

    const uint64_t processes = (uint64_t)process_count;
    const uint64_t base = key_count / processes;
    const uint64_t remainder = key_count % processes;
    const uint64_t rank_u = (uint64_t)rank;
    const uint64_t extra_before = rank_u < remainder ? rank_u : remainder;
    const uint64_t local_size = base + (rank_u < remainder ? 1U : 0U);

    *lower = rank_u * base + extra_before;
    *upper = *lower + local_size;
    return true;
}

/* Calcula el tamaño necesario para completar un bloque DES. */
bool des_padded_length(size_t input_len, size_t *output_len) {
    if (output_len == NULL) {
        return false;
    }

    const size_t padding = DES_BLOCK_SIZE - (input_len % DES_BLOCK_SIZE);
    if (input_len > SIZE_MAX - padding) {
        return false;
    }
    *output_len = input_len + padding;
    return true;
}

/* Copia el texto y agrega el relleno PKCS#7 requerido por DES. */
bool pad_plaintext(const unsigned char *input, size_t input_len,
                   unsigned char **output, size_t *output_len) {
    size_t padded_len = 0;
    if (output == NULL || output_len == NULL ||
        (input == NULL && input_len != 0) ||
        !des_padded_length(input_len, &padded_len)) {
        return false;
    }

    unsigned char *buffer = malloc(padded_len);
    if (buffer == NULL) {
        return false;
    }
    if (input_len != 0) {
        memcpy(buffer, input, input_len);
    }
    const unsigned char padding = (unsigned char)(padded_len - input_len);
    memset(buffer + input_len, padding, padded_len - input_len);
    *output = buffer;
    *output_len = padded_len;
    return true;
}

/* Valida el relleno y obtiene el tamaño original del texto. */
bool remove_pkcs7_padding(const unsigned char *buffer, size_t buffer_len,
                          size_t *plain_len) {
    if (buffer == NULL || plain_len == NULL || buffer_len == 0 ||
        buffer_len % DES_BLOCK_SIZE != 0) {
        return false;
    }

    const unsigned char padding = buffer[buffer_len - 1];
    if (padding == 0 || padding > DES_BLOCK_SIZE || padding > buffer_len) {
        return false;
    }

    unsigned char mismatch = 0;
    for (size_t i = 0; i < padding; ++i) {
        mismatch |= (unsigned char)(buffer[buffer_len - 1 - i] ^ padding);
    }
    if (mismatch != 0) {
        return false;
    }
    *plain_len = buffer_len - padding;
    return true;
}

/* Comprueba que el texto descifrado sea exactamente el esperado. */
bool plaintext_matches_expected(const unsigned char *recovered,
                                size_t recovered_len,
                                const char *expected) {
    if (recovered == NULL || expected == NULL) {
        return false;
    }
    const size_t expected_len = strlen(expected);
    return recovered_len == expected_len &&
           memcmp(recovered, expected, recovered_len) == 0;
}

static void logical_key_to_des(uint64_t key, unsigned char des_key[8]) {
    /* Convierte la clave lógica al formato de ocho bytes usado por DES. */
    for (size_t byte = 0; byte < 8; ++byte) {
        const unsigned int shift = (unsigned int)((7U - byte) * 7U);
        des_key[byte] = (unsigned char)(((key >> shift) & UINT64_C(0x7f)) << 1);
    }
}

static bool crypt_buffer(uint64_t key, unsigned char *buffer, size_t len,
                         bool decrypting) {
    if (buffer == NULL || len == 0 || len % DES_BLOCK_SIZE != 0 ||
        key >= DES_KEYSPACE_SIZE) {
        return false;
    }

    unsigned char des_key[8];
    logical_key_to_des(key, des_key);

#ifdef BRUTEFORCE_CORE_TEST
    /* Usa una transformación determinista para probar el núcleo sin MPI ni DES. */
    (void)decrypting;
    for (size_t i = 0; i < len; ++i) {
        const unsigned int rotation = (unsigned int)((i % 8U) * 7U);
        const unsigned char stream =
            (unsigned char)(((key >> rotation) & UINT64_C(0xff)) ^
                            (UINT64_C(0x5b) + i * UINT64_C(29)));
        buffer[i] ^= stream;
    }
    return true;
#else
    /* Procesa el contenido por bloques de ocho bytes con DES en modo ECB. */
    DES_cblock key_block;
    DES_key_schedule schedule;
    memcpy(key_block, des_key, sizeof(key_block));
    DES_set_odd_parity(&key_block);
    DES_set_key_unchecked(&key_block, &schedule);
    for (size_t offset = 0; offset < len; offset += DES_BLOCK_SIZE) {
        DES_cblock input_block;
        DES_cblock output_block;
        memcpy(input_block, buffer + offset, sizeof(input_block));
        DES_ecb_encrypt(&input_block, &output_block, &schedule,
                        decrypting ? DES_DECRYPT : DES_ENCRYPT);
        memcpy(buffer + offset, output_block, sizeof(output_block));
    }
    return true;
#endif
}

bool encrypt_buffer(uint64_t key, unsigned char *buffer, size_t len) {
    return crypt_buffer(key, buffer, len, false);
}

bool decrypt_buffer(uint64_t key, unsigned char *buffer, size_t len) {
    return crypt_buffer(key, buffer, len, true);
}

/* Guarda un mensaje de error en el búfer proporcionado por el llamador. */
static void set_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size != 0) {
        (void)snprintf(error, error_size, "%s", message);
    }
}

/* Convierte una cadena decimal en una clave válida de 56 bits. */
static bool parse_uint56(const char *value, uint64_t *parsed) {
    if (value == NULL || value[0] == '\0' || value[0] == '-' || parsed == NULL) {
        return false;
    }
    errno = 0;
    char *end = NULL;
    const unsigned long long number = strtoull(value, &end, 10);
    if (errno == ERANGE || end == value || *end != '\0' ||
        number > DES_KEYSPACE_SIZE) {
        return false;
    }
    *parsed = (uint64_t)number;
    return true;
}

/* Lee y valida las opciones recibidas desde la línea de comandos. */
bool parse_cli_options(int argc, char **argv, CliOptions *options,
                       char *error, size_t error_size) {
    if (options == NULL || argv == NULL) {
        set_error(error, error_size, "Parametros internos invalidos.");
        return false;
    }

    CliOptions parsed = {0};
    bool have_text = false;
    bool have_phrase = false;
    bool have_key = false;
    bool have_upper = false;

    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc) {
            set_error(error, error_size, "Cada opcion requiere un valor.");
            return false;
        }
        const char *name = argv[i];
        const char *value = argv[i + 1];
        if (strcmp(name, "--text") == 0 && !have_text) {
            parsed.text = value;
            have_text = true;
        } else if (strcmp(name, "--phrase") == 0 && !have_phrase) {
            parsed.phrase = value;
            have_phrase = true;
        } else if (strcmp(name, "--key") == 0 && !have_key) {
            if (!parse_uint56(value, &parsed.key)) {
                set_error(error, error_size, "--key debe ser un entero DES valido.");
                return false;
            }
            have_key = true;
        } else if (strcmp(name, "--upper") == 0 && !have_upper) {
            if (!parse_uint56(value, &parsed.upper)) {
                set_error(error, error_size, "--upper debe ser un entero DES valido.");
                return false;
            }
            have_upper = true;
        } else {
            set_error(error, error_size, "Opcion desconocida o repetida.");
            return false;
        }
    }

    if (!have_text || !have_phrase || !have_key || !have_upper) {
        set_error(error, error_size, "Faltan opciones obligatorias.");
        return false;
    }
    const size_t text_len = strlen(parsed.text);
    const size_t phrase_len = strlen(parsed.phrase);
    if (text_len == 0 || text_len > MAX_TEXT_BYTES) {
        set_error(error, error_size, "El texto debe contener entre 1 byte y 1 MiB.");
        return false;
    }
    if (phrase_len == 0 || phrase_len > text_len) {
        set_error(error, error_size, "La frase no puede estar vacia ni superar el texto.");
        return false;
    }
    if (parsed.upper == 0 || parsed.upper > DES_KEYSPACE_SIZE ||
        parsed.key >= parsed.upper) {
        set_error(error, error_size, "Se requiere 0 <= key < upper <= 2^56.");
        return false;
    }
    *options = parsed;
    return true;
}

/* Descifra una candidata y busca la frase indicada. */
bool try_key(uint64_t key, const unsigned char *cipher, size_t cipher_len,
             const char *phrase) {
    if (cipher == NULL || cipher_len == 0 ||
        cipher_len % DES_BLOCK_SIZE != 0 || phrase == NULL ||
        phrase[0] == '\0' || cipher_len == SIZE_MAX) {
        return false;
    }

    unsigned char *candidate = malloc(cipher_len + 1U);
    if (candidate == NULL) {
        return false;
    }
    memcpy(candidate, cipher, cipher_len);

    size_t plain_len = 0;
    const bool valid = decrypt_buffer(key, candidate, cipher_len) &&
                       remove_pkcs7_padding(candidate, cipher_len, &plain_len);
    bool matches = false;
    if (valid) {
        candidate[plain_len] = '\0';
        matches = strstr((const char *)candidate, phrase) != NULL;
    }
    free(candidate);
    return matches;
}

/* Recorre un rango de claves hasta encontrar una coincidencia. */
bool search_range(uint64_t lower, uint64_t upper,
                  const unsigned char *cipher, size_t cipher_len,
                  const char *phrase, uint64_t *found_key) {
    if (lower > upper || found_key == NULL) {
        return false;
    }
    for (uint64_t key = lower; key < upper; ++key) {
        if (try_key(key, cipher, cipher_len, phrase)) {
            *found_key = key;
            return true;
        }
    }
    return false;
}

#ifndef BRUTEFORCE_CORE_TEST
/* Muestra la forma correcta de ejecutar el programa. */
static void print_usage(const char *program) {
    fprintf(stderr,
            "Uso: %s --text TEXTO --phrase FRASE --key N --upper N\n"
            "Condicion: 0 <= key < upper <= 2^56.\n",
            program);
}

int main(int argc, char **argv) {
    /* Inicializa MPI y obtiene la identidad del proceso actual. */
    if (MPI_Init(&argc, &argv) != MPI_SUCCESS) {
        fputs("No se pudo inicializar MPI.\n", stderr);
        return EXIT_FAILURE;
    }

    MPI_Comm comm = MPI_COMM_WORLD;
    int rank = 0;
    int process_count = 0;
    MPI_Comm_rank(comm, &rank);
    MPI_Comm_size(comm, &process_count);

    CliOptions options;
    char error[160] = {0};
    const int local_args_ok =
        parse_cli_options(argc, argv, &options, error, sizeof(error)) ? 1 : 0;
    int all_args_ok = 0;
    /* Verifica que todos los procesos reciban argumentos válidos. */
    MPI_Allreduce(&local_args_ok, &all_args_ok, 1, MPI_INT, MPI_MIN, comm);
    if (!all_args_ok) {
        if (rank == 0) {
            fprintf(stderr, "Error: %s\n", local_args_ok ?
                    "argumentos inconsistentes entre procesos" : error);
            print_usage(argv[0]);
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    unsigned char *cipher = NULL;
    size_t cipher_len = 0;
    const int local_setup_ok =
        pad_plaintext((const unsigned char *)options.text, strlen(options.text),
                      &cipher, &cipher_len) &&
        encrypt_buffer(options.key, cipher, cipher_len);
    int all_setup_ok = 0;
    /* Confirma que todos los procesos prepararon el texto correctamente. */
    MPI_Allreduce(&local_setup_ok, &all_setup_ok, 1, MPI_INT, MPI_MIN, comm);
    if (!all_setup_ok) {
        if (rank == 0) {
            fputs("No se pudo preparar el texto cifrado.\n", stderr);
        }
        free(cipher);
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    uint64_t lower = 0;
    uint64_t upper = 0;
    if (!compute_range(options.upper, process_count, rank, &lower, &upper)) {
        free(cipher);
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    const unsigned long long local_count =
        (unsigned long long)(upper - lower);
    unsigned long long max_count = 0;
    MPI_Allreduce(&local_count, &max_count, 1, MPI_UNSIGNED_LONG_LONG,
                  MPI_MAX, comm);

    MPI_Barrier(comm);
    const double start = MPI_Wtime();
    unsigned long long global_candidate = ULLONG_MAX;
    /* Busca las claves por lotes y sincroniza los resultados entre procesos. */
    for (uint64_t offset = 0; offset < (uint64_t)max_count;
         offset += SEARCH_BATCH_SIZE) {
        uint64_t batch_lower = lower + offset;
        uint64_t batch_upper = batch_lower;
        if (batch_lower < upper) {
            const uint64_t remaining = upper - batch_lower;
            batch_upper = batch_lower +
                (remaining < SEARCH_BATCH_SIZE ? remaining : SEARCH_BATCH_SIZE);
        }

        uint64_t local_found = UINT64_MAX;
        unsigned long long local_candidate = ULLONG_MAX;
        if (batch_lower < batch_upper &&
            search_range(batch_lower, batch_upper, cipher, cipher_len,
                         options.phrase, &local_found)) {
            local_candidate = (unsigned long long)local_found;
        }
        MPI_Allreduce(&local_candidate, &global_candidate, 1,
                      MPI_UNSIGNED_LONG_LONG, MPI_MIN, comm);
        if (global_candidate != ULLONG_MAX) {
            break;
        }
    }

    const double local_elapsed = MPI_Wtime() - start;
    double elapsed = 0.0;
    MPI_Reduce(&local_elapsed, &elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, comm);

    int exit_code = EXIT_SUCCESS;
    /* El proceso cero muestra el resultado y valida el texto recuperado. */
    if (rank == 0) {
        if (global_candidate == ULLONG_MAX) {
            printf("Llave no encontrada en [0, %llu). Tiempo: %.6f s\n",
                   (unsigned long long)options.upper, elapsed);
            exit_code = 3;
        } else {
            size_t plain_len = 0;
            const uint64_t found_key = (uint64_t)global_candidate;
            if (!decrypt_buffer(found_key, cipher, cipher_len) ||
                !remove_pkcs7_padding(cipher, cipher_len, &plain_len) ||
                !plaintext_matches_expected(cipher, plain_len, options.text)) {
                fputs("La llave se encontro, pero no se pudo descifrar.\n", stderr);
                exit_code = EXIT_FAILURE;
            } else {
                printf("Llave encontrada: %llu\nTiempo: %.6f s\nTexto: %.*s\n",
                       global_candidate, elapsed, (int)plain_len, (char *)cipher);
            }
        }
    }

    MPI_Bcast(&exit_code, 1, MPI_INT, 0, comm);
    free(cipher);
    MPI_Finalize();
    return exit_code;
}
#endif
