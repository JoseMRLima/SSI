#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "uso: %s <ficheiro>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (f == NULL) {
        perror("erro ao abrir o ficheiro");
        return 1;
    }

    char buf[1024];
    while (fgets(buf, sizeof(buf), f) != NULL) {
        printf("%s", buf);
    }

    fclose(f);
    return 0;
}