#include <bpf/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include "client.skel.h"
#include "mirror_tcp.skel.h"
#include "mirror_udp.skel.h"
#include "mp_common.h"
#include "server.skel.h"

static volatile bool exiting = false;

static void SignalHandler(__attribute__((unused)) int sig) { exiting = true; }

#define OPEN_SKB_PROGRAM(program)                                              \
  program = mp_##program##_bpf__open();                                        \
  if (!(program)) {                                                            \
    fprintf(stderr, "Failed to open " #program ".\n");                         \
    goto cleanup;                                                              \
  }                                                                            \
  bpf_program__set_type((program)->progs._mp_##program, BPF_PROG_TYPE_SK_SKB); \
  bpf_program__set_expected_attach_type((program)->progs._mp_##program, BPF_SK_SKB_VERDICT);

#define CREATE_BPF_MAP(map_type, name, key_size, value_size, max_entries, map_flags)              \
  name##_fd = bpf_create_map_name(map_type, #name, key_size, value_size, max_entries, map_flags); \
  if (name##_fd < 0) {                                                                            \
    fprintf(stderr, "Failed to create " #name " file descriptor.\n");                             \
    goto cleanup;                                                                                 \
  }

#define PIN_BPF_MAP(name)                              \
  err = bpf_obj_pin(name##_fd, "/sys/fs/bpf/" #name);  \
  if (err < 0) {                                       \
    fprintf(stderr, "Failed to pin " #name " map.\n"); \
    goto cleanup;                                      \
  }

#define REUSE_BPF_MAP(program, name)                                     \
  err = bpf_map__reuse_fd((program)->maps.name, name##_fd);              \
  if (err < 0) {                                                         \
    fprintf(stderr, "Failed to reuse " #name " map in " #program ".\n"); \
    goto cleanup;                                                        \
  }

#define LOAD_BPF_PROGRAM(program)                      \
  err = mp_##program##_bpf__load(program);             \
  if (err) {                                           \
    fprintf(stderr, "Failed to load " #program ".\n"); \
    goto cleanup;                                      \
  }

#define ATTACH_SKB_PROGRAM(program, sockmap)                                                                   \
  err = bpf_prog_attach(bpf_program__fd((program)->progs._mp_##program), sockmap##_fd, BPF_SK_SKB_VERDICT, 0); \
  if (err < 0) {                                                                                               \
    fprintf(stderr, "Failed to attach " #program " to " #sockmap ".\n");                                       \
    goto cleanup;                                                                                              \
  }

#define BUMP_RLIMIT                                                  \
  {                                                                  \
    struct rlimit rlim_new = {                                       \
        .rlim_cur = RLIM_INFINITY,                                   \
        .rlim_max = RLIM_INFINITY,                                   \
    };                                                               \
                                                                     \
    err = setrlimit(RLIMIT_MEMLOCK, &rlim_new);                      \
    if (err < 0) {                                                   \
      fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n"); \
      goto cleanup;                                                  \
    }                                                                \
  }

int main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[]) {
  signal(SIGINT, SignalHandler);
  signal(SIGTERM, SignalHandler);
  int32_t err, client_sockets_fd = -1, server_sockets_fd = -1, mirror_udp_sockets_fd = -1, mirror_tcp_sockets_fd = -1,
               idle_server_sockets_fd = -1, socket_states_fd = -1;
  struct mp_client_bpf *client = NULL;
  struct mp_server_bpf *server = NULL;
  struct mp_mirror_udp_bpf *mirror_udp = NULL;
  struct mp_mirror_tcp_bpf *mirror_tcp = NULL;

  // TODO(Matt): Not sure if this is still necessary.
  BUMP_RLIMIT

  OPEN_SKB_PROGRAM(client)
  OPEN_SKB_PROGRAM(server)
  OPEN_SKB_PROGRAM(mirror_udp)
  OPEN_SKB_PROGRAM(mirror_tcp)

  CREATE_BPF_MAP(BPF_MAP_TYPE_SOCKMAP, client_sockets, sizeof(uint32_t), sizeof(uint32_t), 65536, 0)
  CREATE_BPF_MAP(BPF_MAP_TYPE_SOCKMAP, server_sockets, sizeof(uint32_t), sizeof(uint32_t), 65536, 0)
  CREATE_BPF_MAP(BPF_MAP_TYPE_SOCKMAP, mirror_udp_sockets, sizeof(uint32_t), sizeof(uint32_t), 65536, 0)
  CREATE_BPF_MAP(BPF_MAP_TYPE_SOCKMAP, mirror_tcp_sockets, sizeof(uint32_t), sizeof(uint32_t), 65536, 0)
  // TODO(Matt): idle_server_sockets size should be the same as bpf_pool_size in pgbouncer.ini.
  CREATE_BPF_MAP(BPF_MAP_TYPE_STACK, idle_server_sockets, 0, sizeof(uint32_t), 65536, 0)
  CREATE_BPF_MAP(BPF_MAP_TYPE_ARRAY, socket_states, sizeof(uint32_t), sizeof(SocketState), 65536, 0)

  PIN_BPF_MAP(client_sockets)
  PIN_BPF_MAP(server_sockets)
  PIN_BPF_MAP(mirror_udp_sockets)
  PIN_BPF_MAP(mirror_tcp_sockets)
  PIN_BPF_MAP(idle_server_sockets)
  PIN_BPF_MAP(socket_states)

  REUSE_BPF_MAP(client, client_sockets)
  REUSE_BPF_MAP(client, server_sockets)
  REUSE_BPF_MAP(client, mirror_udp_sockets)
  REUSE_BPF_MAP(client, mirror_tcp_sockets)
  REUSE_BPF_MAP(client, idle_server_sockets)
  REUSE_BPF_MAP(client, socket_states)

  REUSE_BPF_MAP(server, client_sockets)
  REUSE_BPF_MAP(server, server_sockets)
  REUSE_BPF_MAP(server, mirror_udp_sockets)
  REUSE_BPF_MAP(server, mirror_tcp_sockets)
  REUSE_BPF_MAP(server, idle_server_sockets)
  REUSE_BPF_MAP(server, socket_states)

  REUSE_BPF_MAP(mirror_udp, client_sockets)
  REUSE_BPF_MAP(mirror_udp, server_sockets)
  REUSE_BPF_MAP(mirror_udp, mirror_udp_sockets)
  REUSE_BPF_MAP(mirror_udp, mirror_tcp_sockets)
  REUSE_BPF_MAP(mirror_udp, idle_server_sockets)
  REUSE_BPF_MAP(mirror_udp, socket_states)

  REUSE_BPF_MAP(mirror_tcp, client_sockets)
  REUSE_BPF_MAP(mirror_tcp, server_sockets)
  REUSE_BPF_MAP(mirror_tcp, mirror_udp_sockets)
  REUSE_BPF_MAP(mirror_tcp, mirror_tcp_sockets)
  REUSE_BPF_MAP(mirror_tcp, idle_server_sockets)
  REUSE_BPF_MAP(mirror_tcp, socket_states)

  LOAD_BPF_PROGRAM(client)
  LOAD_BPF_PROGRAM(server)
  LOAD_BPF_PROGRAM(mirror_udp)
  LOAD_BPF_PROGRAM(mirror_tcp)

  ATTACH_SKB_PROGRAM(client, client_sockets)
  ATTACH_SKB_PROGRAM(server, server_sockets)
  ATTACH_SKB_PROGRAM(mirror_udp, mirror_udp_sockets)
  ATTACH_SKB_PROGRAM(mirror_tcp, mirror_tcp_sockets)

  printf("Everything is loaded...\n");

  while (!exiting) {
    pause();
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
  }

cleanup:
  if (client != NULL) {
    mp_client_bpf__destroy(client);
  }
  if (server != NULL) {
    mp_server_bpf__destroy(server);
  }
  if (mirror_udp != NULL) {
    mp_mirror_udp_bpf__destroy(mirror_udp);
  }
  if (mirror_tcp != NULL) {
    mp_mirror_tcp_bpf__destroy(mirror_tcp);
  }

  unlink("/sys/fs/bpf/client_sockets");
  unlink("/sys/fs/bpf/server_sockets");
  unlink("/sys/fs/bpf/mirror_udp_sockets");
  unlink("/sys/fs/bpf/mirror_tcp_sockets");
  unlink("/sys/fs/bpf/idle_server_sockets");
  unlink("/sys/fs/bpf/socket_states");

  if (client_sockets_fd >= 0) {
    close(client_sockets_fd);
  }
  if (server_sockets_fd >= 0) {
    close(server_sockets_fd);
  }
  if (mirror_udp_sockets_fd >= 0) {
    close(mirror_udp_sockets_fd);
  }
  if (mirror_tcp_sockets_fd >= 0) {
    close(mirror_tcp_sockets_fd);
  }
  if (idle_server_sockets_fd >= 0) {
    close(idle_server_sockets_fd);
  }
  if (socket_states_fd >= 0) {
    close(socket_states_fd);
  }

  return err < 0 ? -err : 0;
}