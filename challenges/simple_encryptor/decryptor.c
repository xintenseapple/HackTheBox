#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
    // Handle args
    if (argc < 2) {
        printf("Missing argument [encrypted file].\n");
        printf("Usage: decryptor [encrypted file] [output file]\n");
        return 1;
    } else if (argc < 3) {
        printf("Missing argument [output file].\n");
        printf("Usage: decryptor [encrypted file] [output file]\n");
        return 1;
    } else if (argc > 3) {
        printf("Too many arguments.\n");
        printf("Usage: decryptor [encrypted file] [output file]\n");
        return 2;
    }

    char *encrypted_filename = argv[1];
    char *output_filename = argv[2];

    int encrypted_fd = open(encrypted_filename, O_RDONLY);
    if (encrypted_fd == -1) {
        printf("Failed to open encrypted file %s.\n", encrypted_filename);
        return 3;
    }

    int output_fd = open(output_filename, O_WRONLY | O_CREAT, 0640);
    if (output_fd == -1) {
        printf("Failed to open/create output file %s.\n", output_filename);
        return 3;
    }

    uint32_t encrypted_epoch;

    ssize_t size = read(encrypted_fd, &encrypted_epoch, 4);
    if (size != 4) {
        printf("Invalid encrypted file format.\n");
        return 4;
    }

    printf("Epoch time that file was encrypted: %d\n", encrypted_epoch);

    srand(encrypted_epoch);

    uint8_t encrypted_byte;
    size = read(encrypted_fd, &encrypted_byte, 1);

    while (size == 1) {
        uint32_t rand_1 = rand();
        uint32_t rand_2 = rand() & 7;

        uint8_t unencrypted_byte = encrypted_byte >> rand_2 | encrypted_byte << (8 - rand_2);
        unencrypted_byte = unencrypted_byte ^ rand_1;

        write(output_fd, &unencrypted_byte, 1);

        size = read(encrypted_fd, &encrypted_byte, 1);
    }

    printf("Decryption complete.\n");
}