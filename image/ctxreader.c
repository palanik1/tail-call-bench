#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 34,
};

#define PROG(X) SEC("action/prog" #X)			\
int bpf_prog ## X(void *ctx) {			\
	bpf_tail_call(ctx, &progs, X+1);	\
	return 0;				\
}

struct meta_info {
	__u32 mark;
} __attribute__((aligned(4)));

#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})



SEC("ctxwriter")
int ctx_writer(struct xdp_md *ctx){
  struct meta_info *meta;
  void *data;
  int ret;
  ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
  if (ret < 0){
    bpf_printk("ABORTED DUE TO META");
    return XDP_DROP;

  }

/* Notice: Kernel-side verifier requires that loading of
 * ctx->data MUST happen _after_ helper bpf_xdp_adjust_meta(),
 * as pkt-data pointers are invalidated.  Helpers that require
 * this are determined/marked by bpf_helper_changes_pkt_data()
 */
  
/* Check data_meta have room for meta_info struct */
  data = (void *)(unsigned long)ctx->data;
  meta = (void *)(unsigned long)ctx->data_meta;
  if (meta + 1 > data) {
   bpf_printk("ABORTED DUE TO META");
   return XDP_DROP;
  } 
	  

  meta->mark = 42;
  bpf_tail_call(ctx, &progs, 0);   
  return 0;

}

