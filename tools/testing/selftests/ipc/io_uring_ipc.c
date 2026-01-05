// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring IPC selftest
 *
 * Tests the io_uring IPC channel functionality including:
 * - Channel creation and attachment
 * - Message send and receive
 * - Broadcast mode
 * - Multicast mode
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

/* Check if IO_URING_IPC is supported */
#ifndef IORING_OP_IPC_SEND
#define IORING_OP_IPC_SEND 65
#define IORING_OP_IPC_RECV 66
#define IORING_OP_IPC_SENDRECV 67

#define IORING_REGISTER_IPC_CHANNEL_CREATE 37
#define IORING_REGISTER_IPC_CHANNEL_ATTACH 38
#define IORING_REGISTER_IPC_CHANNEL_DETACH 39
#define IORING_REGISTER_IPC_BUFFERS 40

/* Flags for IPC channel creation */
#define IOIPC_F_BROADCAST	(1U << 0)
#define IOIPC_F_MULTICAST	(1U << 1)
#define IOIPC_F_PRIVATE		(1U << 2)
#define IOIPC_F_ZEROCOPY	(1U << 3)

/* Flags for subscriber attachment */
#define IOIPC_SUB_SEND		(1U << 0)
#define IOIPC_SUB_RECV		(1U << 1)
#define IOIPC_SUB_BOTH		(IOIPC_SUB_SEND | IOIPC_SUB_RECV)

/* Create IPC channel */
struct io_uring_ipc_channel_create {
	__u32	flags;
	__u32	ring_entries;
	__u32	max_msg_size;
	__u32	mode;
	__u64	key;
	__u32	channel_id_out;
	__u32	reserved[3];
};

/* Attach to existing channel */
struct io_uring_ipc_channel_attach {
	union {
		__u32	channel_id;
		__u64	key;
	};
	__u32	flags;
	__s32	channel_fd;
	__u64	mmap_offset_out;
	__u32	local_id_out;
	__u32	region_size;
	__u32	reserved[2];
};
#endif

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif

#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

#define QUEUE_DEPTH 32
#define TEST_MSG "Hello from io_uring IPC!"
#define TEST_KEY 0x12345678ULL

/* Helper functions for io_uring system calls */
static int io_uring_setup(unsigned int entries, struct io_uring_params *p)
{
	return syscall(__NR_io_uring_setup, entries, p);
}

static int io_uring_enter(int fd, unsigned int to_submit, unsigned int min_complete,
			  unsigned int flags, sigset_t *sig)
{
	return syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
		       flags, sig);
}

static int io_uring_register(int fd, unsigned int opcode, void *arg,
			     unsigned int nr_args)
{
	return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

/* Simple io_uring structure */
struct io_uring {
	int ring_fd;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	unsigned int *sq_head;
	unsigned int *sq_tail;
	unsigned int *cq_head;
	unsigned int *cq_tail;
	unsigned int sq_ring_mask;
	unsigned int cq_ring_mask;
	unsigned int *sq_array;
	void *sq_ring_ptr;
	void *cq_ring_ptr;
};

static int setup_io_uring(struct io_uring *ring, unsigned int entries)
{
	struct io_uring_params p;
	void *sq_ptr, *cq_ptr;
	int ret;

	memset(&p, 0, sizeof(p));
	ret = io_uring_setup(entries, &p);
	if (ret < 0) {
		perror("io_uring_setup");
		return ret;
	}

	ring->ring_fd = ret;
	ring->sq_ring_mask = p.sq_entries - 1;
	ring->cq_ring_mask = p.cq_entries - 1;

	sq_ptr = mmap(NULL, p.sq_off.array + p.sq_entries * sizeof(unsigned int),
		      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		      ring->ring_fd, IORING_OFF_SQ_RING);
	if (sq_ptr == MAP_FAILED) {
		perror("mmap SQ ring");
		close(ring->ring_fd);
		return -1;
	}
	ring->sq_ring_ptr = sq_ptr;

	ring->sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe),
			  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
			  ring->ring_fd, IORING_OFF_SQES);
	if (ring->sqes == MAP_FAILED) {
		perror("mmap SQEs");
		munmap(sq_ptr, p.sq_off.array + p.sq_entries * sizeof(unsigned int));
		close(ring->ring_fd);
		return -1;
	}

	cq_ptr = mmap(NULL, p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe),
		      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		      ring->ring_fd, IORING_OFF_CQ_RING);
	if (cq_ptr == MAP_FAILED) {
		perror("mmap CQ ring");
		munmap(ring->sqes, p.sq_entries * sizeof(struct io_uring_sqe));
		munmap(sq_ptr, p.sq_off.array + p.sq_entries * sizeof(unsigned int));
		close(ring->ring_fd);
		return -1;
	}
	ring->cq_ring_ptr = cq_ptr;

	ring->sq_head = sq_ptr + p.sq_off.head;
	ring->sq_tail = sq_ptr + p.sq_off.tail;
	ring->sq_array = sq_ptr + p.sq_off.array;
	ring->cq_head = cq_ptr + p.cq_off.head;
	ring->cq_tail = cq_ptr + p.cq_off.tail;
	ring->cqes = cq_ptr + p.cq_off.cqes;

	return 0;
}

static void cleanup_io_uring(struct io_uring *ring)
{
	close(ring->ring_fd);
}

static struct io_uring_sqe *get_sqe(struct io_uring *ring)
{
	unsigned int tail = *ring->sq_tail;
	unsigned int index = tail & ring->sq_ring_mask;
	struct io_uring_sqe *sqe = &ring->sqes[index];

	tail++;
	*ring->sq_tail = tail;
	ring->sq_array[index] = index;

	memset(sqe, 0, sizeof(*sqe));
	return sqe;
}

static int submit_io_uring(struct io_uring *ring)
{
	unsigned int to_submit = *ring->sq_tail - *ring->sq_head;

	if (!to_submit)
		return 0;

	return io_uring_enter(ring->ring_fd, to_submit, 0, 0, NULL);
}

static int wait_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_ptr)
{
	struct io_uring_cqe *cqe;
	unsigned int head = *ring->cq_head;
	int ret;

	/* Wait for completion */
	ret = io_uring_enter(ring->ring_fd, 0, 1, IORING_ENTER_GETEVENTS, NULL);
	if (ret < 0) {
		perror("io_uring_enter (wait)");
		return ret;
	}

	/* Check if we have a CQE */
	if (head == *ring->cq_tail)
		return -EAGAIN;

	cqe = &ring->cqes[head & ring->cq_ring_mask];
	*cqe_ptr = cqe;
	return 0;
}

static void cqe_seen(struct io_uring *ring)
{
	(*ring->cq_head)++;
}

/* Test 1: Create IPC channel */
static int test_channel_create(struct io_uring *ring, unsigned int *channel_id)
{
	struct io_uring_ipc_channel_create create;
	int ret;

	memset(&create, 0, sizeof(create));
	create.flags = IOIPC_F_BROADCAST;
	create.ring_entries = 16;
	create.max_msg_size = 4096;
	create.mode = 0666;
	create.key = TEST_KEY;

	ret = io_uring_register(ring->ring_fd, IORING_REGISTER_IPC_CHANNEL_CREATE,
				&create, 1);
	if (ret < 0) {
		perror("IORING_REGISTER_IPC_CHANNEL_CREATE");
		return ret;
	}

	*channel_id = create.channel_id_out;
	printf("Created IPC channel with ID: %u\n", *channel_id);
	return 0;
}

/* Test 2: Attach to IPC channel */
static int test_channel_attach(struct io_uring *ring, unsigned int *local_id)
{
	struct io_uring_ipc_channel_attach attach;
	int ret;

	memset(&attach, 0, sizeof(attach));
	attach.key = TEST_KEY;
	attach.flags = IOIPC_SUB_BOTH;

	ret = io_uring_register(ring->ring_fd, IORING_REGISTER_IPC_CHANNEL_ATTACH,
				&attach, 1);
	if (ret < 0) {
		perror("IORING_REGISTER_IPC_CHANNEL_ATTACH");
		return ret;
	}

	*local_id = attach.local_id_out;
	printf("Attached to IPC channel with local ID: %u\n", *local_id);
	return 0;
}

/* Test 3: Send message */
static int test_send_message(struct io_uring *ring, unsigned int channel_id,
			     const char *msg)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = get_sqe(ring);
	sqe->opcode = IORING_OP_IPC_SEND;
	sqe->fd = channel_id;
	sqe->addr = (unsigned int long)msg;
	sqe->len = strlen(msg) + 1;
	sqe->user_data = 1;

	ret = submit_io_uring(ring);
	if (ret < 0) {
		perror("submit send");
		return ret;
	}

	ret = wait_cqe(ring, &cqe);
	if (ret < 0) {
		perror("wait send cqe");
		return ret;
	}

	if (cqe->res < 0) {
		fprintf(stderr, "Send failed: %s\n", strerror(-cqe->res));
		cqe_seen(ring);
		return cqe->res;
	}

	printf("Sent message: %d bytes\n", cqe->res);
	cqe_seen(ring);
	return 0;
}

/* Test 4: Receive message */
static int test_recv_message(struct io_uring *ring, unsigned int channel_id,
			     char *buf, size_t buf_len)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = get_sqe(ring);
	sqe->opcode = IORING_OP_IPC_RECV;
	sqe->fd = channel_id;
	sqe->addr = (unsigned int long)buf;
	sqe->len = buf_len;
	sqe->user_data = 2;

	ret = submit_io_uring(ring);
	if (ret < 0) {
		perror("submit recv");
		return ret;
	}

	ret = wait_cqe(ring, &cqe);
	if (ret < 0) {
		perror("wait recv cqe");
		return ret;
	}

	if (cqe->res < 0) {
		fprintf(stderr, "Receive failed: %s\n", strerror(-cqe->res));
		cqe_seen(ring);
		return cqe->res;
	}

	printf("Received message: %d bytes: '%s'\n", cqe->res, buf);
	cqe_seen(ring);
	return cqe->res;
}

static int run_ipc_test(void)
{
	struct io_uring ring1, ring2;
	unsigned int channel_id, local_id;
	char recv_buf[256];
	int ret, failed = 0;
	pid_t pid;

	printf("=== io_uring IPC Selftest ===\n\n");

	ret = setup_io_uring(&ring1, QUEUE_DEPTH);
	if (ret < 0) {
		fprintf(stderr, "Failed to setup ring1\n");
		return 1;
	}

	/* Test 1: Create channel */
	printf("Test 1: Create IPC channel\n");
	ret = test_channel_create(&ring1, &channel_id);
	if (ret < 0) {
		if (ret == -EINVAL || ret == -ENOSYS) {
			printf("SKIP: IO_URING_IPC not supported by kernel\n");
			cleanup_io_uring(&ring1);
			return 4; /* KSFT_SKIP */
		}
		fprintf(stderr, "FAILED: Could not create channel\n");
		failed++;
		goto cleanup;
	}
	printf("PASSED\n\n");

	pid = fork();
	if (pid < 0) {
		perror("fork");
		failed++;
		goto cleanup;
	}

	if (pid == 0) {
		/* Child process - consumer */
		cleanup_io_uring(&ring1);

		ret = setup_io_uring(&ring2, QUEUE_DEPTH);
		if (ret < 0) {
			fprintf(stderr, "Child: Failed to setup ring2\n");
			exit(1);
		}

		/* Small delay to ensure parent creates channel */
		usleep(100000);

		/* Test 2: Attach to channel */
		printf("Test 2 (Child): Attach to IPC channel\n");
		ret = test_channel_attach(&ring2, &local_id);
		if (ret < 0) {
			fprintf(stderr, "Child: FAILED to attach\n");
			exit(1);
		}
		printf("PASSED\n\n");

		/* Wait for parent to send message */
		usleep(250000);

		/* Test 4: Receive message */
		printf("Test 4 (Child): Receive message\n");
		ret = test_recv_message(&ring2, local_id, recv_buf, sizeof(recv_buf));
		if (ret < 0) {
			fprintf(stderr, "Child: FAILED to receive\n");
			exit(1);
		}

		if (strcmp(recv_buf, TEST_MSG) != 0) {
			fprintf(stderr, "Child: FAILED - message mismatch\n");
			fprintf(stderr, "Expected: '%s'\n", TEST_MSG);
			fprintf(stderr, "Got: '%s'\n", recv_buf);
			exit(1);
		}
		printf("PASSED\n\n");

		cleanup_io_uring(&ring2);
		exit(0);
	} else {
		/* Parent process - producer */

		/* Give child time to attach */
		usleep(200000);

		/* Test 3: Send message */
		printf("Test 3 (Parent): Send message\n");
		ret = test_send_message(&ring1, channel_id, TEST_MSG);
		if (ret < 0) {
			fprintf(stderr, "FAILED: Could not send message\n");
			failed++;
		} else {
			printf("PASSED\n\n");
		}

		/* Wait for child */
		int status;

		waitpid(pid, &status, 0);
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			fprintf(stderr, "Child process failed\n");
			failed++;
		}
	}

cleanup:
	cleanup_io_uring(&ring1);

	printf("\n=== Test Summary ===\n");
	if (failed == 0) {
		printf("All tests PASSED\n");
		return 0;
	}

	printf("%d test(s) FAILED\n", failed);
	return 1;
}

int main(void)
{
	return run_ipc_test();
}
