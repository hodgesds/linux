/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/bpf_notifier.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>




// struct_ops setup
static int bpf_notifier_init(struct btf *btf)
{
	return 0;
}

static int bpf_notifier_check_member(const struct btf_type *t, const struct btf_member *member,
		const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_notifier_ops, notifier_call):
		break;
	}

	return 0;
}

static int bpf_notifier_init_member(const struct btf_type *t, const struct btf_member *member, void
		*kdata, const void *udata)
{
	return 0;
}

static int bpf_notifier_reg(void *kdata)
{
	struct bpf_notifier_ops *ops = kdata;

	return 0;
}

static void bpf_notifier_unreg(void *kdata)
{
	struct bpf_notifier_ops *ops = kdata;
}

static int bpf_notifier_update(void *kdata, void *old_kdata)
{
	const struct bpf_notifier_ops *old_ops = old_kdata;
	struct bpf_notifier_ops *new_ops = kdata;

	return 0;
}

static int bpf_notifier_validate(void *kdata)
{

	struct bpf_notifier_ops *ops = kdata;

	if (!ops)
		return -EINVAL;

	return 0;
}


static int bpf_notifier_notifier_stub(struct notifier_block *nb, unsigned long action, void *data)
{
	return 0;
}


// verifier setup
static const struct bpf_func_proto * bpf_notifier_get_func_proto(
	enum bpf_func_id func_id, const struct bpf_prog *prog
)
{

	switch (func_id) {
	case BPF_FUNC_trace_vprintk:
		return bpf_get_trace_vprintk_proto();
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	default:
		struct bpf_func_proto * proto;
		proto = bpf_base_func_proto(func_id, prog);
		if (proto)
			return proto;

		return tracing_prog_func_proto(func_id, prog);
	}
}

static bool bpf_cpufreq_is_valid_access(
	int off, int size, enum bpf_access_type type, const struct bpf_prog *prog,
	struct bpf_insn_access_aux *info
) {
	return true;
}

static int bpf_cpufreq_btf_struct_access(
	struct bpf_verifier_log *log, const struct bpf_reg_state *reg, int off, int size
) {
	return 0;
}


static struct bpf_notifier_ops __bpf_ops_notifier_ops = {
	.notifier_call = bpf_notifier_notifier_stub,
};

static const struct bpf_verifier_ops bpf_notifier_verifier_ops = {
	.get_func_proto		= bpf_notifier_get_func_proto,
	.is_valid_access	= bpf_cpufreq_is_valid_access,
	.btf_struct_access	= bpf_cpufreq_btf_struct_access,
};


static struct bpf_struct_ops bpf_notifier_struct_ops = {
	.verifier_ops = &bpf_notifier_verifier_ops ,
	.reg = bpf_notifier_reg,
	.unreg = bpf_notifier_unreg,
	.check_member = bpf_notifier_check_member,
	.init_member = bpf_notifier_init_member,
	.init = bpf_notifier_init,
	.update = bpf_notifier_update,
	.validate = bpf_notifier_validate,
	.name = "bpf_notifier_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &__bpf_ops_notifier_ops,
};


static int __init init_notifier(void)
{
	int ret;

	ret = register_bpf_struct_ops(&bpf_notifier_struct_ops,
			bpf_notifier_ops);
	if (ret) {
		pr_err("Failed to register struct_ops (%d)\n", ret);
		return ret;
	}

	return ret;
}

__initcall(init_notifier);
