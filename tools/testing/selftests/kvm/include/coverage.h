// for NestedKVMFuzzer

#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// for COVERAGE_FILENAME

#include <string.h>

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define COVER_SIZE (64 << 12)

#define KCOV_TRACE_PC 0
#define KCOV_TRACE_CMP 1

int kcov_fd;
unsigned long *kcov_cover, kcov_n;
char coverage_file_path[200];
FILE *coverage_file;

#define COVERAGE_FILENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/* this should be macro to expand __FILE__ in COVERAGE_FILENAME to targed c filename */ \
#define coverage_start() \
do { \
    kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR); \
    if (kcov_fd == -1) \
        perror("open"), exit(1); \
    sprintf(coverage_file_path, "/home/mizutani/NestedKVMFuzzer/linux-kcov/linux-kcov-src/selftest-coverage/%s.bin", COVERAGE_FILENAME); \
    coverage_file = fopen(coverage_file_path, "wb"); \
    if (coverage_file == NULL) \
        perror("fopen"), exit(1); \
    /* Setup trace mode and trace size. */ \
    if (ioctl(kcov_fd, KCOV_INIT_TRACE, COVER_SIZE)) \
        perror("ioctl"), exit(1); \
    /* Mmap buffer shared between kernel- and user-space. */ \
    kcov_cover = (unsigned long *)mmap(NULL, COVER_SIZE * sizeof(unsigned long), \
                                    PROT_READ | PROT_WRITE, MAP_SHARED, kcov_fd, 0); \
    if ((void *)kcov_cover == MAP_FAILED) \
        perror("mmap"), exit(1); \
	/* Enable coverage collection on the current thread. */ \
	if (ioctl(kcov_fd, KCOV_ENABLE, KCOV_TRACE_PC)) \
		perror("ioctl"), exit(1); \
	/* Reset coverage from the tail of the ioctl() call. */ \
	__atomic_store_n(&kcov_cover[0], 0, __ATOMIC_RELAXED); \
} while (0)

/* this doesn't have to be macro,
but I make it a macro to match the format with coverage_start() */
#define coverage_end() \
do { \
	kcov_n = __atomic_load_n(&kcov_cover[0], __ATOMIC_RELAXED); \
	if (fwrite(kcov_cover + 1, sizeof(unsigned long), kcov_n, coverage_file) != kcov_n) \
		perror("fwrite"), exit(1); \
	/* Disable coverage collection for the current thread. After this call \
	* coverage can be enabled for a different thread. \
	*/ \
	if (ioctl(kcov_fd, KCOV_DISABLE, 0)) \
		perror("ioctl"), exit(1); \
 \
    /* Free resources. */ \
    if (munmap(kcov_cover, COVER_SIZE * sizeof(unsigned long))) \
        perror("munmap"), exit(1); \
    if (close(kcov_fd)) \
        perror("close"), exit(1); \
    if (fclose(coverage_file) == EOF) \
        perror("fclose"), exit(1); \
} while (0)
