// SPDX-License-Identifier: GPL-2.0
/*
 * CR4 and CPUID sync test
 *
 * Copyright 2018, Red Hat, Inc. and/or its affiliates.
 *
 * Author:
 *   Wei Huang <wei@redhat.com>
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"

#define X86_FEATURE_XSAVE	(1<<26)
#define X86_FEATURE_OSXSAVE	(1<<27)
#define VCPU_ID			1

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

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define COVER_SIZE (64 << 12)

#define KCOV_TRACE_PC 0
#define KCOV_TRACE_CMP 1

static inline bool cr4_cpuid_is_sync(void)
{
	int func, subfunc;
	uint32_t eax, ebx, ecx, edx;
	uint64_t cr4;

	func = 0x1;
	subfunc = 0x0;
	__asm__ __volatile__("cpuid"
			     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
			     : "a"(func), "c"(subfunc));

	cr4 = get_cr4();

	return (!!(ecx & X86_FEATURE_OSXSAVE)) == (!!(cr4 & X86_CR4_OSXSAVE));
}

static void guest_code(void)
{
	uint64_t cr4;

	/* turn on CR4.OSXSAVE */
	cr4 = get_cr4();
	cr4 |= X86_CR4_OSXSAVE;
	set_cr4(cr4);

	/* verify CR4.OSXSAVE == CPUID.OSXSAVE */
	GUEST_ASSERT(cr4_cpuid_is_sync());

	/* notify hypervisor to change CR4 */
	GUEST_SYNC(0);

	/* check again */
	GUEST_ASSERT(cr4_cpuid_is_sync());

	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_run *run;
	struct kvm_vm *vm;
	struct kvm_sregs sregs;
	struct kvm_cpuid_entry2 *entry;
	struct ucall uc;
	int rc;
    int kcov_fd;
    unsigned long *kcov_cover, kcov_n;
    FILE *coverage_file;

    kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (kcov_fd == -1)
        perror("open"), exit(1);
    coverage_file = fopen("/home/mizutani/NestedKVMFuzzer/selftest-coverage/coverage.bin", "wb");
    if (coverage_file == NULL)
        perror("fopen"), exit(1);
    /* Setup trace mode and trace size. */
    if (ioctl(kcov_fd, KCOV_INIT_TRACE, COVER_SIZE))
        perror("ioctl"), exit(1);
    /* Mmap buffer shared between kernel- and user-space. */
    kcov_cover = (unsigned long *)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
                                    PROT_READ | PROT_WRITE, MAP_SHARED, kcov_fd, 0);
    if ((void *)kcov_cover == MAP_FAILED)
        perror("mmap"), exit(1);
	/* Enable coverage collection on the current thread. */
	if (ioctl(kcov_fd, KCOV_ENABLE, KCOV_TRACE_PC))
		perror("ioctl"), exit(1);
	/* Reset coverage from the tail of the ioctl() call. */
	__atomic_store_n(&kcov_cover[0], 0, __ATOMIC_RELAXED);	

	entry = kvm_get_supported_cpuid_entry(1);
	if (!(entry->ecx & X86_FEATURE_XSAVE)) {
		print_skip("XSAVE feature not supported");
		return 0;
	}

	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	/* Create VM */
	vm = vm_create_default(VCPU_ID, 0, guest_code);
	run = vcpu_state(vm, VCPU_ID);

	while (1) {
		rc = _vcpu_run(vm, VCPU_ID);

		TEST_ASSERT(rc == 0, "vcpu_run failed: %d\n", rc);
		TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
			    "Unexpected exit reason: %u (%s),\n",
			    run->exit_reason,
			    exit_reason_str(run->exit_reason));

		switch (get_ucall(vm, VCPU_ID, &uc)) {
		case UCALL_SYNC:
			/* emulate hypervisor clearing CR4.OSXSAVE */
			vcpu_sregs_get(vm, VCPU_ID, &sregs);
			sregs.cr4 &= ~X86_CR4_OSXSAVE;
			vcpu_sregs_set(vm, VCPU_ID, &sregs);
			break;
		case UCALL_ABORT:
			TEST_FAIL("Guest CR4 bit (OSXSAVE) unsynchronized with CPUID bit.");
			break;
		case UCALL_DONE:
			goto done;
		default:
			TEST_FAIL("Unknown ucall %lu", uc.cmd);
		}
	}

	kvm_vm_free(vm);

done:
	kcov_n = __atomic_load_n(&kcov_cover[0], __ATOMIC_RELAXED);
	if (fwrite(kcov_cover, sizeof(unsigned long), kcov_n, coverage_file) != kcov_n)
		perror("fwrite"), exit(1);
	/* Disable coverage collection for the current thread. After this call
	* coverage can be enabled for a different thread.
	*/
	if (ioctl(kcov_fd, KCOV_DISABLE, 0))
		perror("ioctl"), exit(1);

    /* Free resources. */
    if (munmap(kcov_cover, COVER_SIZE * sizeof(unsigned long)))
        perror("munmap"), exit(1);
    if (close(kcov_fd))
        perror("close"), exit(1);
    if (fclose(coverage_file) == EOF)
        perror("fclose"), exit(1);

	return 0;
}
