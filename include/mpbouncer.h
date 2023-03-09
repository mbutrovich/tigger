#pragma once

#include <stdint.h>

typedef struct PgSocket PgSocket;

enum socket_type {
  CLIENT = 0,
  SERVER = 1,
  MIRROR = 2
};

void add_socket_to_sockmap(PgSocket *, enum socket_type);
void remove_socket_from_sockmap(PgSocket *, enum socket_type);
PgSocket *get_client_link(const PgSocket *socket);
