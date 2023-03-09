#include <bpf/bpf_endian.h>

#include "mp_bouncer.bpf.h"
#include "mp_common.h"

SEC("sk_skb/mp_mirror_udp")
int32_t _mp_mirror_udp(struct __sk_buff *const skb) {
  // bpf_printk("");
  // bpf_printk("mirror_udp");
  // bpf_printk("len: %u", skb->len);
  // bpf_printk("local_port: %u", skb->local_port);
  // bpf_printk("remote_port: %u", bpf_ntohl(skb->remote_port));

  // Read the stashed data offset.
  uint8_t data_offset;
  bpf_skb_load_bytes(skb, 0, &data_offset, 1);
  // bpf_printk("data offset: %u", data_offset);
  // Read the stashed TCP destination port.
  uint32_t tcp_port;
  bpf_skb_load_bytes(skb, 1, &tcp_port, 4);

  // Trim the buffer to remove any leftover bits of TCP header and stashed metadata.
  bpf_skb_adjust_room(skb, -data_offset, 0, 0);
  // bpf_printk("len: %u", skb->len);

  // Redirect the buffer to the correct TCP port.
  // bpf_printk("bouncing to %u", tcp_port);
  return bpf_sk_redirect_map(skb, &mirror_tcp_sockets, tcp_port, 0);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
