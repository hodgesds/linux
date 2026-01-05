// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring IPC channel implementation
 *
 * High-performance inter-process communication using io_uring infrastructure.
 * Provides broadcast and multicast channels with zero-copy support.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/io_uring.h>
#include <linux/io_uring/cmd.h>
#include <linux/hashtable.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "memmap.h"
#include "ipc.h"

#ifdef CONFIG_IO_URING_IPC

/*
 * Global channel registry
 * Protected by RCU and spinlock
 */
static DEFINE_HASHTABLE(channel_hash, 8);
static DEFINE_SPINLOCK(channel_hash_lock);
static DEFINE_XARRAY_ALLOC(channel_xa);

/*
 * File operations for IPC channel mmap support
 */
static int ipc_channel_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct io_ipc_channel *channel = file->private_data;
	size_t region_size = io_region_size(channel->region);
	unsigned long uaddr = vma->vm_start;
	void *kaddr = channel->region->ptr;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	int ret;

	/* Validate mmap parameters */
	if (vma->vm_pgoff != 0)
		return -EINVAL;

	if (size > region_size)
		return -EINVAL;

	/* Don't allow write if ZEROCOPY flag not set */
	if ((vma->vm_flags & VM_WRITE) && !(channel->flags & IOIPC_F_ZEROCOPY))
		return -EACCES;

	/* Map the vmalloc'd region page by page */
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	while (size > 0) {
		pfn = vmalloc_to_pfn(kaddr);
		ret = remap_pfn_range(vma, uaddr, pfn, PAGE_SIZE, vma->vm_page_prot);
		if (ret)
			return ret;

		uaddr += PAGE_SIZE;
		kaddr += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

	return 0;
}

static int ipc_channel_release(struct inode *inode, struct file *file)
{
	struct io_ipc_channel *channel = file->private_data;

	if (channel)
		io_ipc_channel_put(channel);

	return 0;
}

static const struct file_operations ipc_channel_fops = {
	.mmap		= ipc_channel_mmap,
	.release	= ipc_channel_release,
	.llseek		= noop_llseek,
};


/*
 * Calculate sizes for the shared memory region
 */
static int ipc_calc_region_size(u32 ring_entries, u32 max_msg_size,
				size_t *ring_size_out, size_t *data_size_out,
				size_t *total_size_out)
{
	size_t ring_size, data_size, total_size;

	/* Ring structure + array of message descriptors */
	ring_size = sizeof(struct io_ipc_ring) +
		    ring_entries * sizeof(struct io_ipc_msg_desc);
	ring_size = ALIGN(ring_size, PAGE_SIZE);

	/* Data region for message payloads */
	data_size = (size_t)ring_entries * max_msg_size;
	data_size = ALIGN(data_size, PAGE_SIZE);

	total_size = ring_size + data_size;

	if (total_size > INT_MAX)
		return -EINVAL;

	*ring_size_out = ring_size;
	*data_size_out = data_size;
	*total_size_out = total_size;

	return 0;
}

/*
 * Allocate shared memory region for IPC channel
 */
static int ipc_region_alloc(struct io_ipc_channel *channel, u32 ring_entries,
			    u32 max_msg_size)
{
	struct io_mapped_region *region;
	size_t ring_size, data_size, total_size;
	void *ptr;
	int ret;

	ret = ipc_calc_region_size(ring_entries, max_msg_size, &ring_size,
				   &data_size, &total_size);
	if (ret)
		return ret;

	/* Allocate the io_mapped_region structure */
	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	/* Allocate vmalloc'd memory for the shared region */
	ptr = vmalloc_user(total_size);
	if (!ptr) {
		kfree(region);
		return -ENOMEM;
	}

	/* Zero the allocated memory */
	memset(ptr, 0, total_size);

	/* Initialize region */
	region->ptr = ptr;
	region->nr_pages = (total_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	region->flags = 0;

	/* Set up ring and data region pointers */
	channel->region = region;
	channel->ring = (struct io_ipc_ring *)ptr;
	channel->data_region = ptr + ring_size;
	channel->data_region_size = data_size;

	/* Initialize the ring structure */
	channel->ring->ring_mask = ring_entries - 1;
	channel->ring->ring_entries = ring_entries;
	channel->ring->max_msg_size = max_msg_size;
	channel->ring->features = 0;

	return 0;
}

/*
 * Free shared memory region
 */
static void ipc_region_free(struct io_ipc_channel *channel)
{
	if (!channel->region)
		return;

	if (channel->region->ptr)
		vfree(channel->region->ptr);
	kfree(channel->region);
	channel->region = NULL;
	channel->ring = NULL;
	channel->data_region = NULL;
}

/*
 * Channel lifecycle management
 */
static void io_ipc_channel_free(struct io_ipc_channel *channel)
{
	struct io_ipc_subscriber *sub;
	unsigned long index;

	/* Remove from global hash */
	spin_lock(&channel_hash_lock);
	hash_del(&channel->hash_node);
	spin_unlock(&channel_hash_lock);

	/* Remove from xarray */
	xa_erase(&channel_xa, channel->channel_id);

	/* Clean up all subscribers */
	xa_lock(&channel->subscribers);
	xa_for_each(&channel->subscribers, index, sub) {
		xa_erase(&channel->subscribers, index);
		kfree(sub);
	}
	xa_unlock(&channel->subscribers);
	xa_destroy(&channel->subscribers);

	/* Release file if it exists */
	if (channel->file)
		fput(channel->file);

	/* Free the shared region */
	ipc_region_free(channel);

	kfree(channel);
}

static void io_ipc_channel_free_rcu(struct rcu_head *rcu)
{
	struct io_ipc_channel *channel;

	channel = container_of(rcu, struct io_ipc_channel, rcu);
	io_ipc_channel_free(channel);
}

void io_ipc_channel_put(struct io_ipc_channel *channel)
{
	if (refcount_dec_and_test(&channel->ref_count))
		call_rcu(&channel->rcu, io_ipc_channel_free_rcu);
}

struct io_ipc_channel *io_ipc_channel_get(u32 channel_id)
{
	struct io_ipc_channel *channel;

	rcu_read_lock();
	channel = xa_load(&channel_xa, channel_id);
	if (channel && !refcount_inc_not_zero(&channel->ref_count))
		channel = NULL;
	rcu_read_unlock();

	return channel;
}

struct io_ipc_channel *io_ipc_channel_get_by_key(u64 key)
{
	struct io_ipc_channel *channel;
	u32 hash = hash_64(key, HASH_BITS(channel_hash));

	rcu_read_lock();
	hash_for_each_possible_rcu(channel_hash, channel, hash_node, hash) {
		if (channel->key == key &&
		    refcount_inc_not_zero(&channel->ref_count)) {
			rcu_read_unlock();
			return channel;
		}
	}
	rcu_read_unlock();

	return NULL;
}

/*
 * Permission checking
 */
static int ipc_check_permission(struct io_ipc_channel *channel, u32 access)
{
	const struct cred *cred = current_cred();
	kuid_t uid = cred->fsuid;
	kgid_t gid = cred->fsgid;
	u16 mode = channel->mode;

	/* Owner has full access */
	if (uid_eq(uid, channel->owner_uid)) {
		if (mode & 0600)
			return 0;
		return -EACCES;
	}

	/* Group access */
	if (gid_eq(gid, channel->owner_gid)) {
		if (mode & 0060)
			return 0;
		return -EACCES;
	}

	/* Other access */
	if (mode & 0006)
		return 0;

	return -EACCES;
}

/*
 * Create a new IPC channel
 */
int io_ipc_channel_create(struct io_ring_ctx *ctx,
			   const struct io_uring_ipc_channel_create __user *arg)
{
	struct io_uring_ipc_channel_create create;
	struct io_ipc_channel *channel;
	u32 hash;
	int ret;

	if (copy_from_user(&create, arg, sizeof(create)))
		return -EFAULT;

	/* Validate parameters */
	if (!create.ring_entries || create.ring_entries > IORING_MAX_ENTRIES)
		return -EINVAL;

	/* Ring entries must be power of 2 */
	if (!is_power_of_2(create.ring_entries))
		return -EINVAL;

	if (!create.max_msg_size || create.max_msg_size > SZ_1M)
		return -EINVAL;

	/* Check for unsupported flags */
	if (create.flags & ~(IOIPC_F_BROADCAST | IOIPC_F_MULTICAST |
			     IOIPC_F_PRIVATE | IOIPC_F_ZEROCOPY))
		return -EINVAL;

	/* Broadcast and multicast are mutually exclusive */
	if ((create.flags & IOIPC_F_BROADCAST) &&
	    (create.flags & IOIPC_F_MULTICAST))
		return -EINVAL;

	/* Allocate channel structure */
	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return -ENOMEM;

	/* Initialize channel */
	refcount_set(&channel->ref_count, 1);
	channel->flags = create.flags;
	channel->key = create.key;
	channel->ring_size = create.ring_entries;
	channel->msg_max_size = create.max_msg_size;
	channel->owner_uid = current_fsuid();
	channel->owner_gid = current_fsgid();
	channel->mode = create.mode & 0666;
	atomic_set(&channel->next_msg_id, 1);
	atomic_set(&channel->next_receiver_idx, 0);
	spin_lock_init(&channel->lock);
	spin_lock_init(&channel->sub_lock);
	xa_init(&channel->subscribers);

	/* Allocate shared memory region */
	ret = ipc_region_alloc(channel, create.ring_entries, create.max_msg_size);
	if (ret)
		goto err_free_channel;

	/* Allocate channel ID using xarray (IDs start from 1) */
	ret = xa_alloc(&channel_xa, &channel->channel_id, channel,
		       XA_LIMIT(1, INT_MAX), GFP_KERNEL);

	if (ret < 0)
		goto err_free_region;

	/* Add to hash table for key-based lookup */
	hash = hash_64(create.key, HASH_BITS(channel_hash));
	spin_lock(&channel_hash_lock);
	hash_add_rcu(channel_hash, &channel->hash_node, hash);
	spin_unlock(&channel_hash_lock);

	/* Create anonymous file for mmap support */
	refcount_inc(&channel->ref_count); /* File holds a reference */
	channel->file = anon_inode_getfile("[io_uring_ipc]", &ipc_channel_fops,
					   channel, O_RDWR);
	if (IS_ERR(channel->file)) {
		ret = PTR_ERR(channel->file);
		channel->file = NULL;
		refcount_dec(&channel->ref_count);
		goto err_remove_channel;
	}

	/* Return channel ID to userspace */
	create.channel_id_out = channel->channel_id;
	if (copy_to_user((void __user *)arg, &create, sizeof(create))) {
		ret = -EFAULT;
		goto err_put_file;
	}

	return 0;

err_put_file:
	fput(channel->file);
	channel->file = NULL;

err_remove_channel:
	spin_lock(&channel_hash_lock);
	hash_del(&channel->hash_node);
	spin_unlock(&channel_hash_lock);
	xa_erase(&channel_xa, channel->channel_id);
err_free_region:
	ipc_region_free(channel);
err_free_channel:
	kfree(channel);
	return ret;
}

/*
 * Attach to an existing IPC channel
 */
int io_ipc_channel_attach(struct io_ring_ctx *ctx,
			   const struct io_uring_ipc_channel_attach __user *arg)
{
	struct io_uring_ipc_channel_attach attach;
	struct io_ipc_channel *channel = NULL;
	struct io_ipc_subscriber *sub;
	int ret;

	if (copy_from_user(&attach, arg, sizeof(attach)))
		return -EFAULT;

	/* Validate flags */
	if (!attach.flags || (attach.flags & ~IOIPC_SUB_BOTH))
		return -EINVAL;

	/* Find channel by ID or key */
	if (attach.key)
		channel = io_ipc_channel_get_by_key(attach.key);
	else
		channel = io_ipc_channel_get(attach.channel_id);

	if (!channel)
		return -ENOENT;

	/* Check permissions */
	ret = ipc_check_permission(channel, attach.flags);
	if (ret)
		goto err_put_channel;

	/* Allocate subscriber */
	sub = kzalloc(sizeof(*sub), GFP_KERNEL);
	if (!sub) {
		ret = -ENOMEM;
		goto err_put_channel;
	}

	/* Initialize subscriber */
	sub->ctx = ctx;
	sub->channel = channel;
	sub->flags = attach.flags;
	sub->local_head = 0;

	/* Add to channel's subscriber list */
	spin_lock(&channel->sub_lock);
	sub->subscriber_id = channel->next_subscriber_id++;
	ret = xa_insert(&channel->subscribers, sub->subscriber_id, sub, GFP_KERNEL);
	spin_unlock(&channel->sub_lock);

	if (ret) {
		kfree(sub);
		goto err_put_channel;
	}

	/* Increment channel reference for this subscriber */
	refcount_inc(&channel->ref_count);

	/* Add to context's subscriber list for cleanup */
	spin_lock(&ctx->ipc_subscriber_lock);
	list_add_rcu(&sub->list, &ctx->ipc_subscriber_list);
	spin_unlock(&ctx->ipc_subscriber_lock);

	/* Get file descriptor for mmap support */
	ret = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (ret < 0)
		goto err_remove_sub;

	/* Return information to userspace */
	attach.local_id_out = sub->subscriber_id;
	attach.region_size = io_region_size(channel->region);
	attach.channel_fd = ret;
	attach.mmap_offset_out = 0; /* Always mmap at offset 0 */

	if (copy_to_user((void __user *)arg, &attach, sizeof(attach))) {
		put_unused_fd(ret);
		ret = -EFAULT;
		goto err_remove_sub;
	}

	/* Install the file descriptor */
	get_file(channel->file);
	fd_install(attach.channel_fd, channel->file);

	return 0;

err_remove_sub:
	spin_lock(&ctx->ipc_subscriber_lock);
	list_del_rcu(&sub->list);
	spin_unlock(&ctx->ipc_subscriber_lock);
	synchronize_rcu();
	spin_lock(&channel->sub_lock);
	xa_erase(&channel->subscribers, sub->subscriber_id);
	spin_unlock(&channel->sub_lock);
	kfree(sub);
	io_ipc_channel_put(channel); /* Drop subscriber's reference */
err_put_channel:
	io_ipc_channel_put(channel); /* Drop lookup reference */
	return ret;
}

/*
 * Detach from an IPC channel
 */
int io_ipc_channel_detach(struct io_ring_ctx *ctx, u32 subscriber_id)
{
	struct io_ipc_subscriber *sub;
	struct io_ipc_channel *channel;

	/* Find subscriber in ctx's list */
	spin_lock(&ctx->ipc_subscriber_lock);
	list_for_each_entry(sub, &ctx->ipc_subscriber_list, list) {
		if (sub->subscriber_id == subscriber_id) {
			/* Found it - remove from ctx list */
			list_del_rcu(&sub->list);
			spin_unlock(&ctx->ipc_subscriber_lock);
			synchronize_rcu();

			/* Remove from channel's subscriber list */
			channel = sub->channel;
			spin_lock(&channel->sub_lock);
			xa_erase(&channel->subscribers, subscriber_id);
			spin_unlock(&channel->sub_lock);

			/* Release channel reference and free subscriber */
			io_ipc_channel_put(channel);
			kfree(sub);
			return 0;
		}
	}
	spin_unlock(&ctx->ipc_subscriber_lock);

	return -ENOENT;
}

/*
 * Wake up receivers waiting for messages
 */
static void ipc_wake_receivers(struct io_ipc_channel *channel)
{
	struct io_ipc_subscriber *sub;
	unsigned long index;

	rcu_read_lock();
	xa_for_each(&channel->subscribers, index, sub) {
		if (sub->flags & IOIPC_SUB_RECV) {
			/* Wake up the subscriber's io_uring context */
			io_cqring_wake(sub->ctx);
		}
	}
	rcu_read_unlock();
}

/*
 * IORING_OP_IPC_SEND operation
 */
int io_ipc_send_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ipc_send *ipc = io_kiocb_to_cmd(req, struct io_ipc_send);

	if (sqe->buf_index || sqe->personality)
		return -EINVAL;

	if (sqe->ioprio || sqe->rw_flags)
		return -EINVAL;

	ipc->channel_id = READ_ONCE(sqe->fd);
	ipc->addr = READ_ONCE(sqe->addr);
	ipc->len = READ_ONCE(sqe->len);
	ipc->msg_flags = 0;
	ipc->channel = NULL;

	/* TODO: Add support for fixed buffers */
	/* if (sqe->flags & IOSQE_FIXED_FILE) ... */

	return 0;
}

int io_ipc_send(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ipc_send *ipc = io_kiocb_to_cmd(req, struct io_ipc_send);
	struct io_ipc_subscriber *sub = NULL;
	struct io_ipc_channel *channel = NULL;
	struct io_ipc_ring *ring;
	struct io_ipc_msg_desc *desc;
	void __user *user_buf;
	void *dest;
	u32 head, tail, next_tail, idx;
	u64 offset;
	int ret;
	u32 fd = ipc->channel_id;

	/* First try to find subscriber in context's list (sqe->fd = subscriber_id) */
	rcu_read_lock();
	list_for_each_entry_rcu(sub, &req->ctx->ipc_subscriber_list, list) {
		if (sub->subscriber_id == fd) {
			channel = sub->channel;
			refcount_inc(&channel->ref_count);
			rcu_read_unlock();

			/* Check send permission */
			if (!(sub->flags & IOIPC_SUB_SEND)) {
				ret = -EACCES;
				goto out_put;
			}
			goto found;
		}
	}
	rcu_read_unlock();

	/* Not a subscriber_id, try as channel_id (for non-attached senders) */
	channel = io_ipc_channel_get(fd);
	if (!channel)
		return -ENOENT;

	/* Check send permission for non-subscriber */
	ret = ipc_check_permission(channel, IOIPC_SUB_SEND);
	if (ret)
		goto out_put;

found:
	ipc->channel = channel;
	ring = channel->ring;

	/* Check message size */
	if (ipc->len > channel->msg_max_size) {
		ret = -EMSGSIZE;
		goto out_put;
	}

	/* Get current producer tail */
	tail = READ_ONCE(ring->producer.tail);
	next_tail = tail + 1;

	/* Check if ring is full */
	head = READ_ONCE(ring->consumer.head);
	if (next_tail - head > ring->ring_entries) {
		WRITE_ONCE(ring->producer.dropped,
			   READ_ONCE(ring->producer.dropped) + 1);
		ret = -ENOBUFS;
		goto out_put;
	}

	/* Calculate ring index and data offset */
	idx = tail & ring->ring_mask;
	offset = (u64)(idx * channel->msg_max_size);
	dest = channel->data_region + offset;

	/* OPTIMIZATION: Copy directly from userspace to ring buffer */
	user_buf = u64_to_user_ptr(ipc->addr);
	if (copy_from_user(dest, user_buf, ipc->len)) {
		ret = -EFAULT;
		goto out_put;
	}

	/* Fill in message descriptor */
	desc = (struct io_ipc_msg_desc *)((u8 *)ring +
		sizeof(struct io_ipc_ring) + idx * sizeof(*desc));
	desc->offset = offset;
	desc->len = ipc->len;
	desc->msg_id = atomic_inc_return(&channel->next_msg_id);
	desc->sender_data = req->cqe.user_data;
	desc->flags = 0;
	desc->sender_id = 0;
	desc->timestamp = 0; /* Optimization: avoid expensive ktime_get_ns() */

	/* Memory barrier to ensure descriptor is written before tail update */
	smp_wmb();

	/* Update producer tail */
	WRITE_ONCE(ring->producer.tail, next_tail);

	/* Update statistics (relaxed, not performance-critical) */
	atomic64_inc(&channel->msgs_sent);
	atomic64_add(ipc->len, &channel->bytes_transferred);

	ret = ipc->len; /* Return bytes sent */

	/* Wake up receivers */
	ipc_wake_receivers(channel);

out_put:
	io_ipc_channel_put(channel);
	ipc->channel = NULL;
	return ret;
}

void io_ipc_send_cleanup(struct io_kiocb *req)
{
	struct io_ipc_send *ipc = io_kiocb_to_cmd(req, struct io_ipc_send);

	if (ipc->channel) {
		io_ipc_channel_put(ipc->channel);
		ipc->channel = NULL;
	}
}

/*
 * IORING_OP_IPC_RECV operation
 */
int io_ipc_recv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ipc_recv *ipc = io_kiocb_to_cmd(req, struct io_ipc_recv);

	if (sqe->buf_index || sqe->personality)
		return -EINVAL;

	if (sqe->ioprio || sqe->rw_flags)
		return -EINVAL;

	ipc->channel_id = READ_ONCE(sqe->fd);
	ipc->addr = READ_ONCE(sqe->addr);
	ipc->len = READ_ONCE(sqe->len);
	ipc->channel = NULL;
	ipc->subscriber = NULL;

	return 0;
}

int io_ipc_recv(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ipc_recv *ipc = io_kiocb_to_cmd(req, struct io_ipc_recv);
	struct io_ipc_subscriber *sub = NULL;
	struct io_ipc_channel *channel;
	struct io_ipc_ring *ring;
	struct io_ipc_msg_desc *desc;
	void __user *user_buf;
	void *src;
	u32 head, tail, idx;
	size_t copy_len;
	int ret;

	/* Find subscriber in context's list using subscriber_id from sqe->fd */
	rcu_read_lock();
	list_for_each_entry_rcu(sub, &req->ctx->ipc_subscriber_list, list) {
		if (sub->subscriber_id == ipc->channel_id) {
			channel = sub->channel;
			refcount_inc(&channel->ref_count);
			rcu_read_unlock();
			goto found;
		}
	}
	rcu_read_unlock();
	return -ENOENT;

found:
	ipc->channel = channel;
	ipc->subscriber = sub;
	ring = channel->ring;

	/* Check receive permission */
	if (!(sub->flags & IOIPC_SUB_RECV)) {
		ret = -EACCES;
		goto out_put;
	}

	/* For broadcast mode, use local head position */
	head = sub->local_head;

	/* Check if there are messages available */
	tail = READ_ONCE(ring->producer.tail);
	smp_rmb(); /* Ensure tail is read before checking */
	if (head == tail) {
		ret = -EAGAIN; /* No messages available */
		goto out_put;
	}

	/* Memory barrier to ensure we read fresh descriptor data */
	smp_rmb();

	/* Calculate ring index */
	idx = head & ring->ring_mask;

	/* Get message descriptor */
	desc = (struct io_ipc_msg_desc *)((u8 *)ring +
		sizeof(struct io_ipc_ring) + idx * sizeof(*desc));

	/* OPTIMIZATION: Copy directly from ring buffer to userspace */
	src = channel->data_region + desc->offset;
	copy_len = min_t(u32, desc->len, ipc->len);
	user_buf = u64_to_user_ptr(ipc->addr);
	if (copy_to_user(user_buf, src, copy_len)) {
		ret = -EFAULT;
		goto out_put;
	}

	/* Update local head position */
	sub->local_head = head + 1;

	/* For multicast mode, update global consumer head */
	if (channel->flags & IOIPC_F_MULTICAST)
		WRITE_ONCE(ring->consumer.head, head + 1);

	/* Update statistics */
	atomic64_inc(&channel->msgs_received);

	ret = copy_len; /* Return bytes received */

out_put:
	io_ipc_channel_put(channel);
	ipc->channel = NULL;
	return ret;
}

void io_ipc_recv_cleanup(struct io_kiocb *req)
{
	struct io_ipc_recv *ipc = io_kiocb_to_cmd(req, struct io_ipc_recv);

	if (ipc->channel) {
		io_ipc_channel_put(ipc->channel);
		ipc->channel = NULL;
	}
}

/*
 * Clean up IPC resources when io_uring context is destroyed
 */
void io_ipc_ctx_cleanup(struct io_ring_ctx *ctx)
{
	struct io_ipc_subscriber *sub, *tmp;
	struct io_ipc_channel *channel;

	/* Remove all subscribers for this context */
	spin_lock(&ctx->ipc_subscriber_lock);
	list_for_each_entry_safe(sub, tmp, &ctx->ipc_subscriber_list, list) {
		channel = sub->channel;
		list_del_rcu(&sub->list);

		/* Remove from channel's subscriber list */
		spin_lock(&channel->sub_lock);
		xa_erase(&channel->subscribers, sub->subscriber_id);
		spin_unlock(&channel->sub_lock);

		/* Release channel reference and free subscriber */
		io_ipc_channel_put(channel);
		kfree(sub);
	}
	spin_unlock(&ctx->ipc_subscriber_lock);
	synchronize_rcu();
}

static int __init io_uring_ipc_init(void)
{
	return 0;
}

static void __exit io_uring_ipc_exit(void)
{
	struct io_ipc_channel *channel;
	struct hlist_node *tmp;
	int bkt;

	/* Clean up all channels */
	hash_for_each_safe(channel_hash, bkt, tmp, channel, hash_node) {
		io_ipc_channel_put(channel);
	}
}

module_init(io_uring_ipc_init);
module_exit(io_uring_ipc_exit);

MODULE_DESCRIPTION("io_uring IPC support");
MODULE_LICENSE("GPL");

#endif /* CONFIG_IO_URING_IPC */
