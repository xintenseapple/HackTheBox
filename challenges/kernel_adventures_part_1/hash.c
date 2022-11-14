#include <stdio.h>
#include <stdint-gcc.h>
#include <string.h>

uint32_t hash(char* buf) {
    uint32_t hash = 0;
    size_t password_length = strlen(buf);
    for (size_t i = 0; i != password_length; i = i + 1) {
        uint32_t intermediate = (hash + (int)buf[i]) * 0x401;
        hash = intermediate ^ intermediate >> 6 ^ (int)buf[i];
    }
    return hash;
}

int main(int argc, char* argv[]) {

    if (argc != 2) {
        printf("Missing required argument.\n");
        return -1;
    }

    return hash(argv[1]);
}