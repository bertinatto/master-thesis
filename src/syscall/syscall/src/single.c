#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>
#include <time.h>

int main(int argc, char *argv[]) {
    const char *filename = NULL; // Initialize filename to NULL

    // Parse command line options
    int opt;
    while ((opt = getopt(argc, argv, "f:")) != -1) {
        switch (opt) {
            case 'f':
                filename = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -f <filename>\n", argv[0]);
                return 1;
        }
    }

    // Check if filename is provided
    if (filename == NULL) {
        fprintf(stderr, "Usage: %s -f <filename>\n", argv[0]);
        return 1;
    }

    // Get process ID and execution time
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    pid_t process_id = syscall(SYS_getpid);
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    // Check if getpid syscall failed
    if (process_id == -1) {
        perror("getpid");
        return 1;
    }

    // Calculate execution time
    double execution_time = (end_time.tv_sec - start_time.tv_sec) +
                            (double)(end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    // Open file for appending
    FILE *fp = fopen(filename, "a");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    // Write process ID and execution time to file
    fprintf(fp, "%d,%.10f\n", process_id, execution_time);

    // Close file
    fclose(fp);

    return 0;
}
