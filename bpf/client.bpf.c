#include <bpf/bpf_endian.h>

#include "mp_bouncer.bpf.h"

const volatile int pooling_mode = SESSION_POOLING;

const char ERROR_RESPONSE[44] = {
    'E',                                                                                     // Error
    0,   0,   0,   37,                                                                       // Length
    'S', 'E', 'R', 'R', 'O', 'R', 0,                                                         // Severity
    'C', '0', '3', '0', '0', '0', 0,                                                         // Code
    'M', 'P', 'r', 'o', 'x', 'y', ' ', 'n', 'o', 't', ' ', 'r', 'e', 'a', 'd', 'y', '.', 0,  // Message
    0,                                                                                       // Empty field
    'Z',                                                                                     // Ready for query
    0,   0,   0,   5,                                                                        // Length
    'I'                                                                                      // Idle
};

static int64_t change_to_error_response(struct __sk_buff *const skb) {
  const int32_t len_diff = 44 - skb->len;
  // bpf_printk("len_diff: %d", len_diff);
  int64_t result = bpf_skb_adjust_room(skb, len_diff, 0, 0);
  if (result < 0) {
    // bpf_printk("Failed to change tail of skb.");
    return result;
  }
  result = bpf_skb_store_bytes(skb, 0, ERROR_RESPONSE, 44, 0);
  if (result < 0) {
    // bpf_printk("Failed to write error response.");
  }
  return result;
}

static bool process_client(struct __sk_buff *const skb, SocketState *const client_socket_state) {
  // // bpf_printk("\n process_client");
  const uint32_t skb_length = skb->len;
  uint32_t offset = 0;

  uint8_t header_buffer[5] = {0, 0, 0, 0, 0};
  PostgresMessageHeader *const header = (PostgresMessageHeader *const)header_buffer;

  // Check if we have a leftover offset from the last buffer.
  if (client_socket_state->offset_ > 0) {
    // We have a leftover offset from the last buffer, so start our message processing there.
    offset = client_socket_state->offset_;
    // // bpf_printk("retrieved offset: %u", offset);
    // We "consumed" this offset so reset it to 0.
    client_socket_state->offset_ = 0;
  } else if (client_socket_state->offset_ < 0) {
    // We have a partial header. Read it into stack header.
    const int64_t partial_offset = client_socket_state->offset_;
    // // bpf_printk("finish partial header read with partial_offset: %d", partial_offset);

    switch (partial_offset) {
      case -4:
        // [ X X X X ] in header
        __builtin_memcpy(header_buffer, &(client_socket_state->split_header_), 4);
        bpf_skb_load_bytes(skb, 0, &(header_buffer[4]), 1);  // TODO(Matt): In theory this could fail with a tiny skb.
        break;
      case -3:
        // [ X X X - ] in header
        __builtin_memcpy(header_buffer, &(client_socket_state->split_header_), 3);
        bpf_skb_load_bytes(skb, 0, &(header_buffer[3]), 2);  // TODO(Matt): In theory this could fail with a tiny skb.
        break;
      case -2:
        // [ X X - - ] in header
        __builtin_memcpy(header_buffer, &(client_socket_state->split_header_), 2);
        bpf_skb_load_bytes(skb, 0, &(header_buffer[2]), 3);  // TODO(Matt): In theory this could fail with a tiny skb.
        break;
      case -1:
        // [ X - - - ] in header
        __builtin_memcpy(header_buffer, &(client_socket_state->split_header_), 1);
        bpf_skb_load_bytes(skb, 0, &(header_buffer[1]), 4);  // TODO(Matt): In theory this could fail with a tiny skb.
        break;
    }
    // Reset the SocketState.
    __builtin_memset(client_socket_state, 0, 8);

    //    char query_type[2] = {header->type_, 0};

    // // bpf_printk("split header query type: %s", query_type);
    // // bpf_printk("split header query length: %u", bpf_ntohl(header->length_));

    if (header->type_ == 'X') {
      // bpf_printk("Retrieved a split header for a disconnect message.");
      // TODO(Matt): Check if type is 'X', if yes -> extend front of packet, prepend header, and don't redirect.
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
      client_socket_state->offset_ = offset - skb_length;
      // // bpf_printk("stashing offset_map_val: %d", client_socket_state->offset_);
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
          bpf_skb_load_bytes(skb, offset, &(client_socket_state->split_header_), 4);
          client_socket_state->offset_ = -4;
          break;
        }
        case 3: {
          // Put [ X X X - ] in temp buffer.
          bpf_skb_load_bytes(skb, offset, &(client_socket_state->split_header_), 3);
          client_socket_state->offset_ = -3;
          break;
        }
        case 2: {
          // Put [ X X - - ] in temp buffer, truncate it from current skb.
          bpf_skb_load_bytes(skb, offset, &(client_socket_state->split_header_), 2);
          client_socket_state->offset_ = -2;
          break;
        }
        case 1: {
          // Put [ X - - - ] in temp buffer, truncate it from current skb.
          bpf_skb_load_bytes(skb, offset, &(client_socket_state->split_header_), 1);
          client_socket_state->offset_ = -1;
          break;
        }
      }
      if (client_socket_state->split_header_[0] == 'X') {
        // bpf_printk("Got a split header for a disconnect message.");
        // TODO(Matt): Check if type is 'X', if yes -> truncate and forward.
      }
      return true;
    }

    // offset + sizeof(PostgresMessageHeader) <= skb_length
    // We can do a full header read from this buffer. This is the common case.
    bpf_skb_load_bytes(skb, offset, header, sizeof(PostgresMessageHeader));

    //    char query_type[2] = {header->type_, 0};

    // // bpf_printk("query type: %s", query_type);
    // // bpf_printk("query length: %u", bpf_ntohl(header->length_));

    if (header->type_ == 'X') {
      // Client wants to disconnect. Don't redirect this buffer.
      return false;
    }
    // Move our offset to look for the next message.
    offset += sizeof(char) + bpf_ntohl(header->length_);
    messages++;
  } while (messages < MAX_MESSAGES);  // Need to bound the loop to some constant to please the verifier.
  return true;
}

SEC("sk_skb/mp_client")
int32_t _mp_client(struct __sk_buff *const skb) {
  // bpf_printk("");
  // bpf_printk("client");
  // bpf_printk("len: %u", skb->len);
  // bpf_printk("local_port: %u", skb->local_port);
  // bpf_printk("remote_port: %u", bpf_ntohl(skb->remote_port));
  if (skb->local_port == 6432) {
    const uint32_t client_socket_key = bpf_ntohl(skb->remote_port);
    // bpf_printk("client traffic from %u", client_socket_key);

    SocketState *const client_socket_state = bpf_map_lookup_elem(&socket_states, &client_socket_key);

    if (!client_socket_state) {
      // bpf_printk("no client socket state.");
      // This shouldn't happen, but it keeps the verifier happy.
      return SK_PASS;
    }

    // Check if client has a link, if not find one.
    if (client_socket_state->sink_ == 0) {
      uint32_t server_socket_key;
      const int64_t pop_result = bpf_map_pop_elem(&idle_server_sockets, &server_socket_key);
      if (pop_result < 0 || server_socket_key == 0) {
        // bpf_printk("couldn't get a server socket, sending client to userspace.");
        // Send this client on the slow path to userspace and handle it there for the rest of this pooled operation.
        client_socket_state->sink_ = 0xFFFFFFFF;
        return SK_PASS;
      }
      client_socket_state->sink_ = server_socket_key;

      SocketState *const server_socket_state = bpf_map_lookup_elem(&socket_states, &server_socket_key);
      if (server_socket_state) {
        server_socket_state->sink_ = client_socket_key;
      }
      // bpf_printk("linked client %u and server %u", client_socket_key, server_socket_key);
    } else if (client_socket_state->sink_ == 0xFFFFFFFF) {
      // bpf_printk("client being handled in userspace.");
      return SK_PASS;
    }

    const bool redirect = process_client(skb, client_socket_state);

    const uint32_t server_socket_key = client_socket_state->sink_;

    if (redirect) {
      {
        // See if we're ready to proceed.
        MirrorResponses *responses = bpf_map_lookup_elem(&mirror_responders, &server_socket_key);

        if (!responses) {
          // bpf_printk("no server socket state.");
          // This shouldn't happen, but it keeps the verifier happy.
          return SK_DROP;
        }

        bpf_spin_lock(&(responses->lock_));

        if (responses->wait_) {
          // We're waiting for a server to respond.
          bpf_spin_unlock(&(responses->lock_));

          change_to_error_response(skb);
          bpf_sk_redirect_map(skb, &client_sockets, client_socket_key, 0);

          return SK_PASS;
        }
        bpf_spin_unlock(&(responses->lock_));
      }

      // bpf_printk("bouncing to %u", server_socket_key);
      bpf_sk_redirect_map(skb, &server_sockets, server_socket_key, 0);
    } else {
      // bpf_printk("unlinking client %u and server %u", client_socket_key, server_socket_key);
      SocketState *const server_socket_state = bpf_map_lookup_elem(&socket_states, &server_socket_key);
      if (server_socket_state) {
        server_socket_state->sink_ = 0;
      }
      client_socket_state->sink_ = 0;
      bpf_map_push_elem(&idle_server_sockets, &server_socket_key, 0);
    }
  }
  return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
