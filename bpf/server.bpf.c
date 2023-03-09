#include <bpf/bpf_endian.h>

#include "mp_bouncer.bpf.h"

const volatile int pooling_mode = SESSION_POOLING;

static char process_server(struct __sk_buff *const skb, SocketState *const server_socket_state) {
  // // bpf_printk("\n process_server");
  const uint32_t skb_length = skb->len;
  uint32_t offset = 0;

  uint8_t header_buffer[5] = {0, 0, 0, 0, 0};
  PostgresMessageHeader *const header = (PostgresMessageHeader *const)header_buffer;

  // Check if we have a leftover offset from the last buffer.
  if (server_socket_state->offset_ > 0) {
    // We have a leftover offset from the last buffer, so start our message processing there.
    offset = server_socket_state->offset_;
    // // bpf_printk("retrieved offset: %u", offset);
    // We "consumed" this offset so reset it to 0.
    server_socket_state->offset_ = 0;
  } else if (server_socket_state->offset_ < 0) {
    // We have a partial header. Read it into stack header.
    const int64_t partial_offset = server_socket_state->offset_;
    // // bpf_printk("finish partial header read with partial_offset: %d", partial_offset);

    switch (partial_offset) {
      case -4:
        // [ X X X X ] in header
        __builtin_memcpy(header_buffer, &(server_socket_state->split_header_), 4);
        bpf_skb_load_bytes(skb, 0, &(header_buffer[4]), 1);  // TODO(Matt): In theory this could fail with a tiny skb.
        break;
      case -3:
        // [ X X X - ] in header
        __builtin_memcpy(header_buffer, &(server_socket_state->split_header_), 3);
        bpf_skb_load_bytes(skb, 0, &(header_buffer[3]), 2);  // TODO(Matt): In theory this could fail with a tiny skb.
        break;
      case -2:
        // [ X X - - ] in header
        __builtin_memcpy(header_buffer, &(server_socket_state->split_header_), 2);
        bpf_skb_load_bytes(skb, 0, &(header_buffer[2]), 3);  // TODO(Matt): In theory this could fail with a tiny skb.
        break;
      case -1:
        // [ X - - - ] in header
        __builtin_memcpy(header_buffer, &(server_socket_state->split_header_), 1);
        bpf_skb_load_bytes(skb, 0, &(header_buffer[1]), 4);  // TODO(Matt): In theory this could fail with a tiny skb.
        break;
    }
    // Reset the offset_ and split_header_.
    __builtin_memset(server_socket_state, 0, 8);

    //    char query_type[2] = {header->type_, 0};

    // // bpf_printk("split header query type: %s", query_type);
    // // bpf_printk("split header query length: %u", bpf_ntohl(header->length_));

    if (header->type_ == 'Z') {
      // I think it's okay to short circuit here because ReadyForQuery should be the last message sent back to the
      // client.
      char txn_status;
      bpf_skb_load_bytes(skb, offset + sizeof(PostgresMessageHeader), &txn_status, sizeof(char));
      return txn_status;  // I = idle, T = in transaction, E = errored transaction
    }

    // Move our offset to look for the next message.
    offset += sizeof(char) + bpf_ntohl(header->length_) + partial_offset;

    // // bpf_printk("offset after split header: %u", offset);
  }

  uint16_t messages = 0;
  do {
    // // bpf_printk("offset: %u", offset);
    // // bpf_printk("skb_length: %u", skb_length);

    if (offset > skb_length) {
      // The offset is past this buffer's length. Stash the difference as the starting point for the next buffer.
      server_socket_state->offset_ = offset - skb_length;
      // // bpf_printk("stashing offset_map_val: %d", server_socket_state->offset_);
      return true;
    }

    if (offset == skb_length) {
      // This buffer is complete.
      // // bpf_printk("done with this buffer");
      return true;
    }

    // offset < skb_length

    // Check for a header split across buffers.
    if (skb_length - offset < sizeof(PostgresMessageHeader)) {
      // We can't do a full header read.
      const uint8_t remaining_bytes = skb_length - offset;
      // // bpf_printk("start partial header read with remaining bytes: %u", remaining_bytes);
      switch (remaining_bytes) {
        case 4: {
          // Put [ X X X X ] in temp buffer.
          bpf_skb_load_bytes(skb, offset, &(server_socket_state->split_header_), 4);
          server_socket_state->offset_ = -4;
          break;
        }
        case 3: {
          // Put [ X X X - ] in temp buffer.
          bpf_skb_load_bytes(skb, offset, &(server_socket_state->split_header_), 3);
          server_socket_state->offset_ = -3;
          break;
        }
        case 2: {
          // Put [ X X - - ] in temp buffer, truncate it from current skb.
          bpf_skb_load_bytes(skb, offset, &(server_socket_state->split_header_), 2);
          server_socket_state->offset_ = -2;
          break;
        }
        case 1: {
          // Put [ X - - - ] in temp buffer, truncate it from current skb.
          bpf_skb_load_bytes(skb, offset, &(server_socket_state->split_header_), 1);
          server_socket_state->offset_ = -1;
          break;
        }
      }
      return true;
    }

    // offset + sizeof(PostgresMessageHeader) <= skb_length
    // We can do a full header read from this buffer. This is the common case.
    bpf_skb_load_bytes(skb, offset, header, sizeof(PostgresMessageHeader));

    //    char query_type[2] = {header->type_, 0};

    // // bpf_printk("query type: %s", query_type);
    // // bpf_printk("query length: %u", bpf_ntohl(header->length_));

    if (header->type_ == 'Z') {
      // I think it's okay to short circuit here because ReadyForQuery should be the last message sent back to the
      // client.
      char txn_status;
      bpf_skb_load_bytes(skb, offset + sizeof(PostgresMessageHeader), &txn_status, sizeof(char));
      return txn_status;  // I = idle, T = in transaction, E = errored transaction
    }

    // Move our offset to look for the next message.
    offset += sizeof(char) + bpf_ntohl(header->length_);
    messages++;
  } while (messages < MAX_MESSAGES);  // Need to bound the loop to some constant to please the verifier.
  return true;
}

SEC("sk_skb/mp_server")
int32_t _mp_server(struct __sk_buff *const skb) {
  // bpf_printk("");
  // bpf_printk("server");
  // bpf_printk("len: %u", skb->len);
  // bpf_printk("local_port: %u", skb->local_port);
  // bpf_printk("remote_port: %u", bpf_ntohl(skb->remote_port));
  if (bpf_ntohl(skb->remote_port) == 5432) {
    const uint32_t server_socket_key = skb->local_port;
    // bpf_printk("server traffic from %u", server_socket_key);
    SocketState *const server_socket_state = bpf_map_lookup_elem(&socket_states, &server_socket_key);

    if (!server_socket_state) {
      // bpf_printk("no server socket state.");
      // This shouldn't happen, but it keeps the verifier happy.
      return SK_PASS;
    }

    const char txn_status = process_server(skb, server_socket_state);
    //    char txn_status_string[2] = {txn_status, 0};
    // bpf_printk("txn status: %s", txn_status_string);

    if (txn_status == 'I') {
      // The primary is Idle. See if we're ready to proceed.
      MirrorResponses *responses = bpf_map_lookup_elem(&mirror_responders, &server_socket_key);

      if (!responses) {
        // bpf_printk("no server socket state.");
        // This shouldn't happen, but it keeps the verifier happy.
        return SK_PASS;
      }

      bpf_spin_lock(&(responses->lock_));

      const bool wait = responses->wait_;

      if (responses->wait_) {
        // Mirror has already responded. We're okay to proceed.
        responses->wait_ = false;
      } else {
        // Primary is the first to respond. Start blocking the client.
        responses->wait_ = true;
      }

      bpf_spin_unlock(&(responses->lock_));

      if (wait) {
        // bpf_printk("Primary has already responded. We're okay to proceed.");
      } else {
        // bpf_printk("Mirror is the first to respond. Start blocking the client.");
      }
    }

    const uint32_t client_socket_key = server_socket_state->sink_;
    // bpf_printk("bouncing to %u", client_socket_key);
    bpf_sk_redirect_map(skb, &client_sockets, client_socket_key, 0);
  }
  return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
