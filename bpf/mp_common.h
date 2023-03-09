#pragma once

#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

enum PoolingMode {
  SESSION_POOLING = 0,
  TRANSACTION_POOLING = 1,  // TODO(Matt): Not sure we care about statement pooling.
};

typedef struct {
  char type_;
  int32_t length_;
} __attribute__((packed)) PostgresMessageHeader;
// __attribute__((packed)) is necessary to avoid padding between type_ and length_

typedef struct {
  int64_t offset_;
  uint8_t split_header_[4];  // PostgresMessageHeader is 5 bytes. We need at most 4 bytes to hold a partial read.
  uint32_t sink_;
} SocketState;

typedef struct {
  // TODO(Matt): Maybe keep these network order to there's not constant translation.
  uint32_t udp_port_;
  uint32_t tcp_port_;
} MirrorPorts;
