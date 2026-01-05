/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_IPC_H
#define IO_URING_IPC_H

#include <linux/io_uring_types.h>

#ifdef CONFIG_IO_URING_IPC

/*
 * Internal kernel structures for io_uring IPC
 */

/* Shared ring structure - lives in mmap'd memory region */
struct io_ipc_ring {
	/* Cache-aligned producer/consumer positions */
	struct {
		u32	head __aligned(64);
		u32	tail;
		u32	flags;
		u32	dropped;	/* Dropped messages (ring full) */
	} producer;

	struct {
		u32	head __aligned(64);
		u32	tail;
		u32	flags;
		u32	reserved;
	} consumer;

	/* Ring parameters */
	u32	ring_mask;
	u32	ring_entries;
	u32	max_msg_size;
	u32	features;		/* Feature flags */

	/* Message descriptors follow inline */
};

/* Message descriptor in the ring */
struct io_ipc_msg_desc {
	u64	offset;			/* Offset in data region for message payload */
	u32	len;			/* Message length */
	u32	msg_id;			/* Unique message ID */
	u64	sender_data;		/* Sender's user_data for context */
	u32	flags;			/* IOIPC_MSG_F_URGENT, IOIPC_MSG_F_OOB */
	u32	sender_id;		/* Sender ring ID */
	u64	timestamp;		/* When message was sent */
};

/* Per-subscriber attachment to a channel */
struct io_ipc_subscriber {
	struct io_ring_ctx	*ctx;		/* io_uring context */
	struct io_ipc_channel	*channel;	/* Channel this subscriber is attached to */

	u32	local_head;			/* Local read position */
	u32	subscriber_id;			/* Unique subscriber ID */
	u32	flags;				/* IOIPC_SUB_SEND, IOIPC_SUB_RECV */

	struct io_buffer_list	*recv_bufs;	/* Provided buffers for received msgs */

	/* For efficient lookup */
	unsigned long xa_index;			/* Index in subscribers xarray */

	struct list_head list;			/* List entry for channel's subscriber list */
};

/* IPC channel connecting two or more io_uring instances */
struct io_ipc_channel {
	struct io_mapped_region	*region;	/* Shared memory region */
	struct io_ipc_ring	*ring;		/* Shared ring structure in mmap'd region */
	void			*data_region;	/* Data storage area for messages */
	struct file		*file;		/* Anonymous file for mmap support */

	/* Subscribers to this channel */
	struct xarray		subscribers;	/* All subscribers */
	u32			next_subscriber_id;
	spinlock_t		sub_lock;	/* Protects subscriber list */

	/* Channel metadata */
	refcount_t		ref_count;
	u32			channel_id;
	u32			flags;		/* IOIPC_F_BROADCAST, IOIPC_F_MULTICAST */
	u64			key;		/* Unique key for lookup */

	/* Ring buffer configuration */
	u32			ring_size;
	u32			msg_max_size;
	u32			data_region_size;

	/* Access control */
	kuid_t			owner_uid;
	kgid_t			owner_gid;
	u16			mode;		/* Permission bits */

	/* Statistics */
	atomic64_t		msgs_sent;
	atomic64_t		msgs_received;
	atomic64_t		bytes_transferred;

	/* Next message ID */
	atomic_t		next_msg_id;

	/* For multicast round-robin */
	atomic_t		next_receiver_idx;

	/* Channel lifecycle */
	spinlock_t		lock;
	struct rcu_head		rcu;
	struct hlist_node	hash_node;	/* For global channel hash table */
};

/* Request state for IPC operations */
struct io_ipc_send {
	struct io_ipc_channel	*channel;
	u64			addr;
	u32			channel_id;
	u32			msg_flags;
	size_t			len;
};

struct io_ipc_recv {
	struct io_ipc_channel	*channel;
	struct io_ipc_subscriber *subscriber;
	u64			addr;
	u32			channel_id;
	size_t			len;
};

/* Function declarations */

/* Registration operations */
int io_ipc_channel_create(struct io_ring_ctx *ctx,
			   const struct io_uring_ipc_channel_create __user *arg);
int io_ipc_channel_attach(struct io_ring_ctx *ctx,
			   const struct io_uring_ipc_channel_attach __user *arg);
int io_ipc_channel_detach(struct io_ring_ctx *ctx, u32 channel_id);

/* Operation prep and execution */
int io_ipc_send_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_ipc_send(struct io_kiocb *req, unsigned int issue_flags);
void io_ipc_send_cleanup(struct io_kiocb *req);

int io_ipc_recv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_ipc_recv(struct io_kiocb *req, unsigned int issue_flags);
void io_ipc_recv_cleanup(struct io_kiocb *req);

/* Channel lifecycle */
void io_ipc_ctx_cleanup(struct io_ring_ctx *ctx);

/* Channel lookup and management */
struct io_ipc_channel *io_ipc_channel_get(u32 channel_id);
struct io_ipc_channel *io_ipc_channel_get_by_key(u64 key);
void io_ipc_channel_put(struct io_ipc_channel *channel);

#else /* !CONFIG_IO_URING_IPC */

static inline int io_ipc_channel_create(struct io_ring_ctx *ctx,
			const struct io_uring_ipc_channel_create __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int io_ipc_channel_attach(struct io_ring_ctx *ctx,
			const struct io_uring_ipc_channel_attach __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int io_ipc_channel_detach(struct io_ring_ctx *ctx, u32 channel_id)
{
	return -EOPNOTSUPP;
}

static inline void io_ipc_ctx_cleanup(struct io_ring_ctx *ctx)
{
}

#endif /* CONFIG_IO_URING_IPC */

#endif /* IO_URING_IPC_H */
