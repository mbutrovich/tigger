#include "mpbouncer.h"
#include <bpf/bpf.h>
#include <unistd.h>
#include "bouncer.h"
#include "server.h"
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
  int64_t offset_;
  uint8_t split_header_[4];  // PostgresMessageHeader is 5 bytes. We need at most 4 bytes to hold a partial read.
  uint32_t sink_;
} MPSocketState;

typedef struct {
  uint32_t udp_port_;
  uint32_t tcp_port_;
} MirrorPorts;

static const MPSocketState empty_socket_state = {.offset_ = 0, .split_header_ = {0, 0, 0, 0}, .sink_ = 0};

/**
 * Create a new UDP socket for use as a mirroring socket.
 * @return Port number of new UDP socket, -1 if operation failed.
 */
static int32_t create_udp_socket(void) {
  int ret;
  // Open a UDP socket.
  int32_t udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_socket_fd >= 0) {
	socklen_t address_len = sizeof(struct sockaddr_in);
	// Accept from any address, and in port of 0 means the OS will assign one. In address could be localhost, but that
	// would be another value to change in the header, so it's easier to leave it at INADDR_ANY.
	const struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = {INADDR_ANY}, .sin_port = 0};
	// Bind the UDP socket.
	ret = bind(udp_socket_fd, (const struct sockaddr *)&address, sizeof(struct sockaddr_in));
	if (ret >= 0) {
	  // Find the assigned port number.
	  ret = getsockname(udp_socket_fd, (struct sockaddr *)&address, &address_len);
	  if (ret >= 0) {
		const int32_t port = ntohs(address.sin_port);
		// Add the UDP port to the mirror_udp_sockets sockmap so mirror_udp.bpf.c runs for this socket.
		const int sockmap = bpf_obj_get("/sys/fs/bpf/mirror_udp_sockets");
		ret = bpf_map_update_elem(sockmap, &port, &udp_socket_fd, BPF_NOEXIST);
		if (ret >= 0) {
		  log_info("Added UDP socket at port %u to mirror_udp_sockets sockmap.", port);
		  close(sockmap);
		  return port;
		}
		log_error("Failed to add UDP socket at port %u to mirror_udp_sockets sockmap.", port);
	  } else {
		log_error("Failed to getsockname() of UDP socket.");
	  }
	} else {
	  log_error("Failed to bind() UDP socket.");
	}
	close(udp_socket_fd);
  } else {
	log_error("Failed to open UDP socket.");
  }
  return -1;
}

static void add_server_to_queue(const PgSocket *const socket) {
  const int idle_server_sockets = bpf_obj_get("/sys/fs/bpf/idle_server_sockets");

  if (idle_server_sockets >= 0) {
	int ret;
	const uint32_t sport = ntohs(socket->local_addr.sin.sin_port);

	ret = bpf_map_update_elem(idle_server_sockets, NULL, &sport, BPF_ANY);
	if (ret < 0) {
	  log_warning("Failed to add socket %u to idle_server_sockets.\n", sport);
	} else {
	  log_noise("Added socket %u to idle_server_sockets.\n", sport);
	}
	close(idle_server_sockets);
  } else {
	log_warning("We didn't get the BPF maps.\n");
  }
}

static void reset_client_link(const uint32_t sport) {
  const int socket_states = bpf_obj_get("/sys/fs/bpf/socket_states");

  if (socket_states >= 0) {
	int ret;

	ret = bpf_map_update_elem(socket_states, &sport, &empty_socket_state, BPF_EXIST);
	if (ret < 0) {
	  log_warning("Failed to reset socket %u in socket_states.\n", sport);
	} else {
	  log_noise("Reset socket %u in socket_states.\n", sport);
	}

	close(socket_states);
  } else {
	log_warning("We didn't get the BPF maps.\n");
  }
}

PgSocket *get_client_link(const PgSocket *const socket) {
  PgSocket *server = NULL;
  int socket_states;

  Assert(socket);

  if (pool_bpf_pool_size(socket->pool) == 0) {
	return NULL;
  }

  socket_states = bpf_obj_get("/sys/fs/bpf/socket_states");

  if (socket_states >= 0) {
	int ret;
	MPSocketState socket_state;
	const struct List *list_item;
	const PgPool *const pool = socket->pool;
	const uint32_t sport = ntohs(socket->remote_addr.sin.sin_port);

	ret = bpf_map_lookup_elem(socket_states, &sport, &socket_state);
	if (ret < 0) {
	  log_warning("Failed to get socket %u in socket_states.\n", sport);
	  return NULL;
	} else {
	  log_noise("Got socket %u in socket_states.\n", sport);
	}

	log_noise("client port %u is to linked BPF socket: %u\n", sport, socket_state.sink_);
	statlist_for_each(list_item, &pool->bpf_server_list) {
	  PgSocket *const temp = container_of(list_item, PgSocket, head);
	  const uint32_t server_port = htons(temp->local_addr.sin.sin_port);
	  if (server_port == socket_state.sink_) {
		server = temp;
		break;
	  }
	}
	close(socket_states);
  } else {
	log_warning("We didn't get the BPF maps.\n");
  }
  return server;
}

void add_socket_to_sockmap(PgSocket *const socket, enum socket_type type) {
  int sockmap;
  uint32_t sport;

  Assert(socket);
  Assert(type == CLIENT || type == SERVER);

  if (pool_bpf_pool_size(socket->pool) == 0) {
	log_noise("Not using BPF fast path because the pool size is 0.");
	return;
  } else if (type == CLIENT && socket->state != CL_ACTIVE) {
	log_noise("Trying to add client socket to sockmap, but it's not logged in yet?");
	return;
  } else if (type == CLIENT && socket->pool->db->mirror != NULL) {
	log_noise("Trying to add client socket to sockmap, but this a client connecting to a mirror backend.");
	return;
  }

  sport = type == CLIENT ? ntohs(socket->remote_addr.sin.sin_port) : ntohs(socket->local_addr.sin.sin_port);

  if (type == SERVER && socket->pool->db->mirror != NULL) {
	type = MIRROR;
  }

  if (type == CLIENT) {
	reset_client_link(sport);
	sockmap = bpf_obj_get("/sys/fs/bpf/client_sockets");
  } else if (type == SERVER) {
	sockmap = bpf_obj_get("/sys/fs/bpf/server_sockets");
  } else {
	Assert(type == MIRROR);
	sockmap = bpf_obj_get("/sys/fs/bpf/mirror_tcp_sockets");
  }

  if (sockmap >= 0) {
	int ret;

	ret = bpf_map_update_elem(sockmap, &sport, &(socket->sbuf.sock), BPF_NOEXIST);
	if (ret < 0) {
	  log_warning("Failed to add socket %u to sockmap.\n", sport);
	} else {
	  log_noise("Added socket %u to sockmap.\n", sport);
	}

	close(sockmap);

	if (type != CLIENT) {
	  // We always want to pause servers in the sockmap. Clients might need to pass to userspace.
	  ret = sbuf_pause(&(socket->sbuf));
	  if (ret == 0) {
		log_warning("Failed to pause server socket %u.\n", sport);
	  } else {
		log_noise("Paused server socket %u.\n", sport);
	  }
	  if (type == SERVER) {
		// Servers not defined as a mirror go into the queue to be used.
		add_server_to_queue(socket);
	  } else {
		int32_t udp_port;
		Assert(type == MIRROR);
		// Servers defined as a mirror need to open a corresponding UDP socket.
		udp_port = create_udp_socket();
		if (udp_port >= 0) {
		  PgPool *mirror_pool = get_pool(socket->pool->db->mirror, socket->pool->db->mirror->forced_user);
		  if (mirror_pool) {
			const int mirror_ports_fd = bpf_obj_get("/sys/fs/bpf/mirror_ports");
			if (mirror_ports_fd >= 0) {
			  const struct List *list_item;
			  statlist_for_each(list_item, &mirror_pool->bpf_server_list) {
				MirrorPorts ports;
				PgSocket *const temp = container_of(list_item, PgSocket, head);
				const uint32_t server_port = htons(temp->local_addr.sin.sin_port);
				ret = bpf_map_lookup_elem(mirror_ports_fd, &server_port, &ports);
				if (ret >= 0) {
				  if (ports.udp_port_ == 0) {
					// This primary doesn't have a matched UDP temp and TCP mirror. Match them.
					ports.udp_port_ = udp_port;
					ports.tcp_port_ = sport;
					ret = bpf_map_update_elem(mirror_ports_fd, &server_port, &ports, BPF_ANY);
					if (ret >= 0) {
					  log_info("Updated server port %u to use udp %u and tcp %u.", server_port, udp_port, sport);
					  close(mirror_ports_fd);
					  return;
					} else {
					  log_error("Failed to update server port %u in mirror_ports map.", server_port);
					}
				  }
				} else {
				  log_error("Failed to look up server port %u in mirror_ports map.", server_port);
				}
			  }
			  close(mirror_ports_fd);
			} else {
			  log_error("We didn't get the mirror_ports map.");
			}
		  } else {
			log_error("didn't get the mirror pool.");
		  }
		}
	  }
	}
  } else {
	log_warning("We didn't get the sockmap.\n");
  }
}

void remove_socket_from_sockmap(PgSocket *const socket, enum socket_type type) {
  int sockmap;

  Assert(socket);
  Assert(type == CLIENT || type == SERVER);

  if (pool_bpf_pool_size(socket->pool) == 0) {
	log_noise("Not using BPF fast path because the pool size is 0.");
	return;
  } else if (type == CLIENT && socket->pool->db->mirror != NULL) {
	log_noise("Trying to remove client socket from sockmap, but this a client disconnecting from a mirror backend.");
	return;
  }

  if (type == SERVER && socket->pool->db->mirror != NULL) {
	type = MIRROR;
  }

  if (type != CLIENT) {
	sbuf_continue(&(socket->sbuf));
  }

  if (type == CLIENT) {
	sockmap = bpf_obj_get("/sys/fs/bpf/client_sockets");
  } else if (type == SERVER) {
	sockmap = bpf_obj_get("/sys/fs/bpf/server_sockets");
  } else {
	Assert(type == MIRROR);
	sockmap = bpf_obj_get("/sys/fs/bpf/mirror_tcp_sockets");
  }

  if (sockmap >= 0) {
	int ret;
	const uint32_t
		sport = type == CLIENT ? ntohs(socket->remote_addr.sin.sin_port) : ntohs(socket->local_addr.sin.sin_port);

	ret = bpf_map_delete_elem(sockmap, &sport);
	if (ret < 0) {
	  // This can happen if the client was already being handled in userspace.
	  log_warning("Failed to remove socket %u from sockmap.\n", sport);
	} else {
	  log_noise("Removed socket %u from sockmap.\n", sport);
	}

	close(sockmap);
  } else {
	log_warning("We didn't get the sockmap.\n");
  }
}
