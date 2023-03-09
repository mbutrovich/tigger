// clang-format off
#include "vmlinux.h" // Needs to be included before bpf_helpers.h
#include <bpf/bpf_helpers.h>
// clang-format on
#include <bpf/bpf_endian.h>

#include "mp_common.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(MirrorPorts));
  __uint(max_entries, 65536);
} mirror_ports SEC(".maps");

SEC("classifier/tc_test")
int32_t tc_test(struct __sk_buff *const skb) {
  // Pass any marked packets.
  if (skb->mark == 12131989) {
    return BPF_OK;
  }

  // Grab some boundary pointers for our input packet.
  void *data = (void *)(uint64_t)skb->data;
  void *data_end = (void *)(uint64_t)skb->data_end;

  // Initialize Ethernet header and bounds check for BPF verifier.
  struct ethhdr *eth = data;
  if (unlikely((void *)eth + sizeof(*eth) > data_end)) {
    // Not enough data in the packet for an Ethernet header.
    return BPF_DROP;
  }

  // Pass any packets that are not IPv4 protocol.
  // TODO(Matt): IPv6 protocol support?
  if (eth->h_proto != bpf_htons(0x0800)) {  // ETH_P_IP
    return BPF_OK;
  }

  // Initialize IP header and bounds check for BPF verifier.
  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (unlikely((void *)iph + sizeof(*iph) > data_end)) {
    // Ethernet protocol is IP but there's not enough data in the packet for an IP header.
    return BPF_DROP;
  }

  // Pass any packets that are not TCP protocol.
  if (iph->protocol != IPPROTO_TCP) {
    return BPF_OK;
  }

  // IHL specifies the size of the IPv4 header in 32-bit words. 5 <= ihl <= 15.
  const uint8_t ip_header_size = iph->ihl * sizeof(uint32_t);

  // Initialize TCP header and bounds check for BPF verifier.
  struct tcphdr *const tcph = (void *)iph + ip_header_size;
  if (unlikely((void *)tcph + sizeof(*tcph) > data_end)) {
    // IP protocol is TCP but there's not enough data in the packet for a TCP header.
    return BPF_DROP;
  }

  // Pass any packets that are not PostgreSQL protocol.
  if (tcph->dest != bpf_htons(5432)) {
    return BPF_OK;
  }

  // Data offset specifies the size of the TCP header in 32-bit words. 5 <= doff <= 15.
  const uint8_t tcp_header_size = tcph->doff * sizeof(uint32_t);

  // Pass any packets that have no payload. These are likely SYN, ACK, SYN/ACK etc. packets.
  const uint16_t iph_tot_len = bpf_ntohs(iph->tot_len);
  if (ip_header_size + tcp_header_size == iph_tot_len) {
    //    bpf_printk("Got a packet without a TCP payload.");
    return BPF_OK;
  }

  // bpf_printk("");
  // bpf_printk("tc_test");
  // bpf_printk("len: %u", skb->len);
  // bpf_printk("tcph dest: %u", bpf_ntohs(tcph->dest));
  // bpf_printk("tcph src: %u", bpf_ntohs(tcph->source));

  const uint32_t server_socket_key = bpf_ntohs(tcph->source);
  // TODO(Matt): This doesn't need to be in a BPF map -- could codegen mapping of server_socket_key -> {udp, tcp}
  MirrorPorts *ports;
  ports = bpf_map_lookup_elem(&mirror_ports, &server_socket_key);
  if (!ports) {
    // Bail I guess. this shouldn't happen.
    // bpf_printk("Failed to find server_socket_key %u in mirror_ports map.", server_socket_key);
    return BPF_OK;
  }
  if (ports->udp_port_ == 0) {
    // bpf_printk("Ports not defined for server_socket_key %u in mirror_ports map, not mirroring.", server_socket_key);
    return BPF_OK;
  }

  // Capture the old MAC and IP addresses since we'll swap them later.
  uint8_t old_ethhdr_h_dest[6];
  uint8_t old_ethhdr_h_source[6];
  __builtin_memcpy(old_ethhdr_h_dest, &(eth->h_dest), 6);
  __builtin_memcpy(old_ethhdr_h_source, &(eth->h_source), 6);
  const uint32_t old_iphdr_saddr = iph->saddr;
  const uint32_t old_iphdr_daddr = iph->daddr;

  // Mark the current skb, and then duplicate it to the egress path on the same network device. The duplicate leaves
  // this host as our unmodified "original" packet. The skb we are left with is our clone, which we'll convert to an
  // incoming UDP packet since it's easier to spoof back up to the sockmap layer.
  skb->mark = 12131989;
  if (bpf_clone_redirect(skb, skb->ifindex, 0) == 0) {
    long ret = 0;

    // Swap the source and destination MAC addresses. Could change them both to localhost, but then the checksum
    // change isn't a compile-time constant.
    ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), &old_ethhdr_h_source, 6, 0);
    if (ret < 0) {
      // bpf_printk("Failed to store mac h_dest %d.", ret);
    }
    ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), &old_ethhdr_h_dest, 6, 0);
    if (ret < 0) {
      // bpf_printk("Failed to store mac h_source %d.", ret);
    }

    // Swap the source and destination IP. Could change them both to localhost, but then the checksum
    // change isn't a compile-time constant.
    ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), &old_iphdr_daddr, 4, 0);
    if (ret < 0) {
      // bpf_printk("Failed to store ip saddr %d.", ret);
    }
    ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), &old_iphdr_saddr, 4, 0);
    if (ret < 0) {
      // bpf_printk("Failed to store ip daddr %d.", ret);
    }

    // Change the protocol to UDP in the IP header.
    static const uint8_t ipproto_udp = IPPROTO_UDP;
    ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol), &ipproto_udp, 1, 0);
    if (ret < 0) {
      // bpf_printk("Failed to store ip protocol %d.", ret);
    }

    // Change the IP header's checksum based on the protocol change. Precompute this and store it as a magic
    // constant because it's always the same checksum difference for changing TCP to UDP:
    // bpf_csum_diff(bpf_htonl(IPPROTO_TCP), sizeof(IPPROTO_TCP), bpf_htonl(IPPROTO_UDP), sizeof(IPPROTO_UDP), 0);
    ret = bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, 184549376, 0);
    if (ret < 0) {
      // bpf_printk("Failed to store ip checksum %d.", ret);
    }

    // Write the new UDP header.
    const struct udphdr new_header = {.dest = bpf_htons(ports->udp_port_),
                                      .len = bpf_htons(iph_tot_len - ip_header_size)};
    ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + ip_header_size, &new_header, sizeof(struct udphdr), 0);
    if (ret < 0) {
      // bpf_printk("Failed to store udp header %d.", ret);
    }

    // Write the data offset. Since TCP headers are >= 20 bytes, and UDP header is 8 bytes, we have at least 12 bytes
    // to pack with metadata to help the sockmap layer understand what's going on. We'll steal the first byte to write
    // a data offset for now.
    const uint8_t data_offset = tcp_header_size - sizeof(struct udphdr);
    ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + ip_header_size + sizeof(struct udphdr), &data_offset, 1, 0);
    if (ret < 0) {
      // bpf_printk("Failed to store data offset %d.", ret);
    }
    ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + ip_header_size + sizeof(struct udphdr) + sizeof(uint8_t),
                              &(ports->tcp_port_), 4, 0);
    if (ret < 0) {
      // bpf_printk("Failed to store tcp port %d.", ret);
    }

    // bpf_printk("cloning to %u", bpf_ntohs(new_header.dest));
    // Redirect this UDP packet to ingress to be caught by a sockmap program.
    return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
  }
  return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
