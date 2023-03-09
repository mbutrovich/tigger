#pragma once

// clang-format off
#include "vmlinux.h" // Needs to be included before bpf_helpers.h
#include <bpf/bpf_helpers.h>
// clang-format on

#include "mp_common.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(SocketState));
  __uint(max_entries, 65536);
} socket_states SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 65536);
} client_sockets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 65536);
} server_sockets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 65536);
} mirror_udp_sockets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 65536);
} mirror_tcp_sockets SEC(".maps");

// TODO(Matt): idle_server_sockets size should be the same as bpf_pool_size in pgbouncer.ini.
struct {
  __uint(type, BPF_MAP_TYPE_STACK);
  __uint(key_size, 0);
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 65536);
} idle_server_sockets SEC(".maps");

enum {
  MAX_MESSAGES = 2048  // Arbitrary limit to make the verifier happy. I had to raise this from 255 to make pg_dump happy
                       // since it sends a lot of stuff back in a single buffer sometimes.
};