#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BRUTEFORCE_CORE_TEST
#include "../src/bruteforce_mpi.c"

/* Verifica que los rangos cubran el espacio de claves sin solaparse. */
static void test_balanced_ranges_cover_keyspace(void) {
    uint64_t lower = 99;
    uint64_t upper = 99;

    assert(compute_range(10, 3, 0, &lower, &upper));
    assert(lower == 0 && upper == 4);
    assert(compute_range(10, 3, 1, &lower, &upper));
    assert(lower == 4 && upper == 7);
    assert(compute_range(10, 3, 2, &lower, &upper));
    assert(lower == 7 && upper == 10);
    assert(!compute_range(10, 0, 0, &lower, &upper));
    assert(!compute_range(10, 3, 3, &lower, &upper));
}

/* Verifica que el relleno pueda agregarse y retirarse correctamente. */
static void test_pkcs7_padding_round_trip(void) {
    const unsigned char input[] = "ABCDEFGHI";
    unsigned char *padded = NULL;
    size_t padded_len = 0;
    size_t plain_len = 0;

    assert(des_padded_length(9, &padded_len));
    assert(padded_len == 16);
    assert(pad_plaintext(input, 9, &padded, &padded_len));
    assert(padded_len == 16);
    for (size_t i = 9; i < padded_len; ++i) {
        assert(padded[i] == 7);
    }
    assert(remove_pkcs7_padding(padded, padded_len, &plain_len));
    assert(plain_len == 9);
    assert(memcmp(padded, input, plain_len) == 0);
    free(padded);

    assert(des_padded_length(8, &padded_len));
    assert(padded_len == 16);
    assert(!des_padded_length(SIZE_MAX, &padded_len));
}

/* Comprueba que se rechacen diferentes formas de relleno inválido. */
static void test_rejects_invalid_padding(void) {
    unsigned char zero_pad[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 0};
    unsigned char mixed_pad[8] = {'A', 'B', 'C', 'D', 4, 4, 3, 4};
    size_t plain_len = 0;

    assert(!remove_pkcs7_padding(zero_pad, sizeof(zero_pad), &plain_len));
    assert(!remove_pkcs7_padding(mixed_pad, sizeof(mixed_pad), &plain_len));
    assert(!remove_pkcs7_padding(mixed_pad, 0, &plain_len));
}

/* Verifica la validación de las opciones de línea de comandos. */
static void test_cli_validation(void) {
    CliOptions options;
    char error[160];
    char *valid[] = {
        "bruteforce_mpi", "--text", "mensaje clave", "--phrase", "clave",
        "--key", "17", "--upper", "32"
    };
    char *empty_phrase[] = {
        "bruteforce_mpi", "--text", "mensaje", "--phrase", "",
        "--key", "1", "--upper", "2"
    };
    char *bad_number[] = {
        "bruteforce_mpi", "--text", "mensaje", "--phrase", "mensaje",
        "--key", "12x", "--upper", "20"
    };
    char *key_outside[] = {
        "bruteforce_mpi", "--text", "mensaje", "--phrase", "mensaje",
        "--key", "20", "--upper", "20"
    };
    char *too_large[] = {
        "bruteforce_mpi", "--text", "mensaje", "--phrase", "mensaje",
        "--key", "1", "--upper", "72057594037927937"
    };

    assert(parse_cli_options(9, valid, &options, error, sizeof(error)));
    assert(options.key == 17 && options.upper == 32);
    assert(strcmp(options.phrase, "clave") == 0);
    assert(!parse_cli_options(9, empty_phrase, &options, error, sizeof(error)));
    assert(!parse_cli_options(9, bad_number, &options, error, sizeof(error)));
    assert(!parse_cli_options(9, key_outside, &options, error, sizeof(error)));
    assert(!parse_cli_options(9, too_large, &options, error, sizeof(error)));
}

/* Comprueba que la búsqueda encuentre una clave en un rango pequeño. */
static void test_search_finds_key_in_small_space(void) {
    const unsigned char plaintext[] = "texto con frase objetivo y mas contenido";
    const uint64_t expected_key = 23;
    unsigned char *cipher = NULL;
    size_t cipher_len = 0;
    uint64_t found = UINT64_MAX;

    assert(pad_plaintext(plaintext, strlen((const char *)plaintext),
                         &cipher, &cipher_len));
    assert(encrypt_buffer(expected_key, cipher, cipher_len));
    assert(search_range(0, 64, cipher, cipher_len, "frase objetivo", &found));
    assert(found == expected_key);
    assert(!search_range(0, 20, cipher, cipher_len, "frase objetivo", &found));
    free(cipher);
}

/* Confirma que la comparación del texto sea exacta. */
static void test_plaintext_verification_requires_exact_match(void) {
    const unsigned char recovered[] = "mensaje completo";

    assert(plaintext_matches_expected(recovered, strlen("mensaje completo"),
                                      "mensaje completo"));
    assert(!plaintext_matches_expected(recovered, strlen("mensaje completo"),
                                       "mensaje distinto"));
    assert(!plaintext_matches_expected(recovered, strlen("mensaje"),
                                       "mensaje completo"));
}

int main(void) {
    /* Ejecuta todas las pruebas del núcleo. */
    test_balanced_ranges_cover_keyspace();
    test_pkcs7_padding_round_trip();
    test_rejects_invalid_padding();
    test_cli_validation();
    test_search_finds_key_in_small_space();
    test_plaintext_verification_requires_exact_match();
    puts("OK: 6 pruebas del nucleo superadas");
    return 0;
}
