#include <bpf/bpf_endian.h>

#include "mp_bouncer.bpf.h"
#include "mp_common.h"

SEC("sk_skb/mp_mirror_tcp")
int32_t _mp_mirror_tcp(__attribute__((unused)) struct __sk_buff *const skb) {
  // bpf_printk("");
  // bpf_printk("mirror_tcp");
  // bpf_printk("len: %u", skb->len);
  // bpf_printk("local_port: %u", skb->local_port);
  // bpf_printk("remote_port: %u", bpf_ntohl(skb->remote_port));

  // TODO(Matt): In the scenario where we want the first response back to be forwarded to the client, handle that here?

  return SK_DROP;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
