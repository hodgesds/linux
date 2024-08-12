/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Daniel Hodges <hodges.daniel.scott@gmail.com>
 */
#ifdef CONFIG_SLAB_BPF

struct slab_bpf_ops {
	void	(*init)(void);
	int	(*create)(struct kmem_cache *cache, slab_flags_t flags);
	void	(*create_boot_cache)(struct kmem_cache *cache, const char *name, unsigned int size, slab_flags_t flags, unsigned int useroffset, unsigned int usersize);
	int	(*slab_unmergeable)(struct kmem_cache *s);
	struct kmem_cache*(*find_mergeable)(unsigned size, unsigned align, slab_flags_t flags, const chart *name, void (*ctor)(void *));
	struct kmem_cache*(*cache_alias)(const char *name, unsigned int size, unsigned int align, slab_flags_t flags, void (*ctor)(void *));
	slab_flags_t	(*kmem_cache_flags)(slab_flags_t flags, const char *name);


// bool __kmem_cache_empty(struct kmem_cache *);
// int __kmem_cache_shutdown(struct kmem_cache *);
// void __kmem_cache_release(struct kmem_cache *);
// int __kmem_cache_shrink(struct kmem_cache *);
// void slab_kmem_cache_release(struct kmem_cache *);


//void get_slabinfo(struct kmem_cache *s, struct slabinfo *sinfo);

// extern void print_tracking(struct kmem_cache *s, void *object);
// long validate_slab_cache(struct kmem_cache *s);
};



#endif
