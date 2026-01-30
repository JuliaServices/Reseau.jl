#include <Network/Network.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stddef.h>

typedef void (*awsio_nw_state_changed_fn)(void *ctx, nw_connection_state_t state, nw_error_t error);
typedef void (*awsio_nw_listener_state_fn)(void *ctx, nw_listener_state_t state, nw_error_t error);
typedef void (*awsio_nw_new_connection_fn)(void *ctx, nw_connection_t connection);
typedef void (*awsio_nw_receive_fn)(
    void *ctx,
    dispatch_data_t data,
    nw_content_context_t context,
    bool is_complete,
    nw_error_t error);
typedef void (*awsio_nw_send_fn)(void *ctx, nw_error_t error, dispatch_data_t data);
typedef void (*awsio_nw_protocol_options_fn)(void *ctx, nw_protocol_options_t options);
typedef bool (*awsio_sec_verify_fn)(void *ctx, sec_protocol_metadata_t metadata, sec_trust_t trust);

static void *(*awsio_jl_adopt_thread_fn)(void) = NULL;
static void *(*awsio_jl_get_pgcstack_fn)(void) = NULL;

static void awsio_ensure_julia_thread(void) {
    if (!awsio_jl_adopt_thread_fn) {
        awsio_jl_adopt_thread_fn = (void *(*)(void))dlsym(RTLD_DEFAULT, "jl_adopt_thread");
    }
    if (!awsio_jl_get_pgcstack_fn) {
        awsio_jl_get_pgcstack_fn = (void *(*)(void))dlsym(RTLD_DEFAULT, "jl_get_pgcstack");
    }
    if (awsio_jl_get_pgcstack_fn && awsio_jl_get_pgcstack_fn() != NULL) {
        return;
    }
    if (awsio_jl_adopt_thread_fn) {
        awsio_jl_adopt_thread_fn();
    }
}

__attribute__((visibility("default")))
void awsio_nw_connection_set_state_changed_handler(
    nw_connection_t connection,
    void *ctx,
    awsio_nw_state_changed_fn fn) {
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
      if (fn) {
          awsio_ensure_julia_thread();
          fn(ctx, state, error);
      }
    });
}

__attribute__((visibility("default")))
void awsio_nw_listener_set_state_changed_handler(
    nw_listener_t listener,
    void *ctx,
    awsio_nw_listener_state_fn fn) {
    nw_listener_set_state_changed_handler(listener, ^(nw_listener_state_t state, nw_error_t error) {
      if (fn) {
          awsio_ensure_julia_thread();
          fn(ctx, state, error);
      }
    });
}

__attribute__((visibility("default")))
void awsio_nw_listener_set_new_connection_handler(
    nw_listener_t listener,
    void *ctx,
    awsio_nw_new_connection_fn fn) {
    nw_listener_set_new_connection_handler(listener, ^(nw_connection_t connection) {
      if (fn) {
          awsio_ensure_julia_thread();
          fn(ctx, connection);
      }
    });
}

__attribute__((visibility("default")))
void awsio_nw_connection_receive(
    nw_connection_t connection,
    size_t minimum_incomplete_length,
    size_t maximum_length,
    void *ctx,
    awsio_nw_receive_fn fn) {
    nw_connection_receive(
        connection,
        minimum_incomplete_length,
        maximum_length,
        ^(dispatch_data_t data, nw_content_context_t context, bool is_complete, nw_error_t error) {
          if (fn) {
              awsio_ensure_julia_thread();
              fn(ctx, data, context, is_complete, error);
          }
        });
}

__attribute__((visibility("default")))
void awsio_nw_connection_send(
    nw_connection_t connection,
    dispatch_data_t data,
    bool is_complete,
    void *ctx,
    awsio_nw_send_fn fn) {
    nw_connection_send(
        connection,
        data,
        NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,
        is_complete,
        ^(nw_error_t error) {
          if (fn) {
              awsio_ensure_julia_thread();
              fn(ctx, error, data);
          }
        });
}

__attribute__((visibility("default")))
nw_parameters_t awsio_nw_parameters_create_secure_tcp(
    void *ctx,
    bool enable_tls,
    awsio_nw_protocol_options_fn tls_fn,
    awsio_nw_protocol_options_fn tcp_fn) {
    if (enable_tls && tls_fn) {
        return nw_parameters_create_secure_tcp(
            ^(nw_protocol_options_t tls_options) {
              tls_fn(ctx, tls_options);
            },
            ^(nw_protocol_options_t tcp_options) {
              if (tcp_fn) {
                  tcp_fn(ctx, tcp_options);
              }
            });
    }

    return nw_parameters_create_secure_tcp(
        NW_PARAMETERS_DISABLE_PROTOCOL,
        ^(nw_protocol_options_t tcp_options) {
          if (tcp_fn) {
              tcp_fn(ctx, tcp_options);
          }
        });
}

__attribute__((visibility("default")))
nw_parameters_t awsio_nw_parameters_create_secure_udp(
    void *ctx,
    bool enable_tls,
    awsio_nw_protocol_options_fn tls_fn,
    awsio_nw_protocol_options_fn tcp_fn) {
    if (enable_tls && tls_fn) {
        return nw_parameters_create_secure_udp(
            ^(nw_protocol_options_t tls_options) {
              tls_fn(ctx, tls_options);
            },
            ^(nw_protocol_options_t udp_options) {
              if (tcp_fn) {
                  tcp_fn(ctx, udp_options);
              }
            });
    }

    return nw_parameters_create_secure_udp(
        NW_PARAMETERS_DISABLE_PROTOCOL,
        ^(nw_protocol_options_t udp_options) {
          if (tcp_fn) {
              tcp_fn(ctx, udp_options);
          }
        });
}

__attribute__((visibility("default")))
void awsio_sec_protocol_options_set_verify_block(
    sec_protocol_options_t options,
    void *ctx,
    awsio_sec_verify_fn fn,
    dispatch_queue_t queue) {
    sec_protocol_options_set_verify_block(options, ^(sec_protocol_metadata_t metadata, sec_trust_t trust,
                                                    sec_protocol_verify_complete_t complete) {
      bool result = false;
      if (fn) {
          awsio_ensure_julia_thread();
          result = fn(ctx, metadata, trust);
      }
      complete(result);
    }, queue);
}
