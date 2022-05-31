#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct meta_info {
	__u32 mark;
} __attribute__((aligned(4)));

struct eth_hdr {
  __be64 dst : 48;
  __be64 src : 48;
  __be16 proto;
} __attribute__((packed));


struct bpf_map_def SEC("maps") progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 34,
};

struct bpf_map_def SEC("maps") packetData = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct meta_info),
	.max_entries = 1,
};


#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

SEC("xdp/mapwriter")
int map_writer(struct xdp_md *ctx){
  struct meta_info *meta;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct eth_hdr *ethernet = data;
  if (data + sizeof(*ethernet) > data_end)
    return XDP_DROP;
  int key = 0; 
  //bpf_printk("Before Packet LookUp");
  meta = bpf_map_lookup_elem(&packetData,&key);
  //meta = packetData.lookup(&key);
  if (meta == NULL) {
    bpf_printk("Packet is NULL");
    // Not possible
    return XDP_DROP;
  }
  meta->mark = 42;
  bpf_tail_call(ctx, &progs, 0);   
  return 0;

}

SEC("xdp/mapreader")
int map_reader(struct xdp_md * ctx){
   struct meta_info *meta;
   //void *data;
   /* Check data_meta have room for meta_info struct */
   //data = (void *)(unsigned long)ctx->data;
   
   int key = 0;
   
   //bpf_printk("Before Packet LookUp");
   meta = bpf_map_lookup_elem(&packetData,&key);
   //meta = packetData.lookup(&key);
  if (meta == NULL) {
    bpf_printk("Packet is NULL");
    // Not possible
    return XDP_DROP;
  }
  //bpf_printk("MAP READ MARK = %d", meta->mark);
  meta->mark;
  return 0;

}

char _license[] SEC("license") = "GPL";
