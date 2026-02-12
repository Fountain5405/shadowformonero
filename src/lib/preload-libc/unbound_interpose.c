/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 *
 * Interposes libunbound API functions via LD_PRELOAD so that DNS queries
 * inside the Shadow simulation go through Shadow's simulated network instead
 * of libunbound's internal networking (which doesn't work in Shadow because
 * libunbound never calls connect() on its TCP sockets).
 *
 * We send a raw DNS query over UDP to the configured forwarder and parse
 * the response into a ub_result struct.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Use fprintf for logging since we don't have access to the shim logger here */
#define debug(fmt, ...) fprintf(stderr, "[DNS-shim] " fmt "\n", ##__VA_ARGS__)
#define warning(fmt, ...) fprintf(stderr, "[DNS-shim WARNING] " fmt "\n", ##__VA_ARGS__)

/* DNS constants (RFC 1035) */
#define DNS_PORT 53
#define DNS_MAX_PACKET_SIZE 4096
#define DNS_HEADER_SIZE 12
#define DNS_CLASS_IN 1
#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_RD 0x0100  /* Recursion Desired */
#define DNS_FLAG_RCODE_MASK 0x000F

/* libunbound return codes (from unbound.h) */
#define UB_NOERROR 0
#define UB_SERVFAIL 3
#define UB_NOMEM 1
#define UB_SYNTAX 2

/* Our internal context structure (replaces opaque ub_ctx) */
struct ub_ctx {
    char fwd_addr[64];  /* Forwarder IP address string */
    int has_fwd;         /* Whether a forwarder is set */
    int do_tcp;          /* Whether TCP is enabled */
    int do_udp;          /* Whether UDP is enabled */
};

/* Must match the public struct ub_result from unbound.h */
struct ub_result {
    char* qname;
    int qtype;
    int qclass;
    char** data;
    int* len;
    char* canonname;
    int rcode;
    void* answer_packet;
    int answer_len;
    int havedata;
    int nxdomain;
    int secure;
    int bogus;
    char* why_bogus;
    int was_ratelimited;
    int ttl;
};

/* Encode a DNS name (e.g., "example.com" -> "\x07example\x03com\x00")
 * Returns number of bytes written, or -1 on error. */
static int _dns_encode_name(const char* name, uint8_t* buf, int buf_size) {
    int pos = 0;
    const char* p = name;

    while (*p) {
        /* Find the next dot or end of string */
        const char* dot = strchr(p, '.');
        int label_len;
        if (dot) {
            label_len = (int)(dot - p);
        } else {
            label_len = (int)strlen(p);
        }

        if (label_len == 0) {
            /* Skip empty labels (trailing dot) */
            p = dot ? dot + 1 : p + strlen(p);
            continue;
        }

        if (label_len > 63 || pos + 1 + label_len >= buf_size) {
            return -1;
        }

        buf[pos++] = (uint8_t)label_len;
        memcpy(&buf[pos], p, label_len);
        pos += label_len;

        p = dot ? dot + 1 : p + strlen(p);
    }

    if (pos + 1 >= buf_size) {
        return -1;
    }
    buf[pos++] = 0; /* Root label */
    return pos;
}

/* Build a DNS query packet.
 * Returns the length of the packet, or -1 on error. */
static int _dns_build_query(const char* name, int rrtype, int rrclass,
                            uint16_t txn_id, uint8_t* buf, int buf_size) {
    if (buf_size < DNS_HEADER_SIZE + 4) {
        return -1;
    }

    /* Header */
    memset(buf, 0, DNS_HEADER_SIZE);
    buf[0] = (txn_id >> 8) & 0xFF;
    buf[1] = txn_id & 0xFF;
    /* Flags: RD=1 (recursion desired) */
    buf[2] = (DNS_FLAG_RD >> 8) & 0xFF;
    buf[3] = DNS_FLAG_RD & 0xFF;
    /* QDCOUNT = 1 */
    buf[4] = 0;
    buf[5] = 1;
    /* ANCOUNT, NSCOUNT, ARCOUNT = 0 */

    int pos = DNS_HEADER_SIZE;

    /* Question section: QNAME */
    int name_len = _dns_encode_name(name, &buf[pos], buf_size - pos);
    if (name_len < 0) {
        return -1;
    }
    pos += name_len;

    /* QTYPE */
    if (pos + 4 > buf_size) {
        return -1;
    }
    buf[pos++] = (rrtype >> 8) & 0xFF;
    buf[pos++] = rrtype & 0xFF;

    /* QCLASS */
    buf[pos++] = (rrclass >> 8) & 0xFF;
    buf[pos++] = rrclass & 0xFF;

    return pos;
}

/* Skip a DNS name in the response (handles compression pointers).
 * Returns the number of bytes consumed, or -1 on error. */
static int _dns_skip_name(const uint8_t* buf, int buf_len, int offset) {
    int pos = offset;
    int jumped = 0;
    int consumed = 0;

    while (pos < buf_len) {
        uint8_t label_len = buf[pos];

        if (label_len == 0) {
            /* End of name */
            if (!jumped) {
                consumed = pos - offset + 1;
            }
            return consumed ? consumed : 1;
        }

        if ((label_len & 0xC0) == 0xC0) {
            /* Compression pointer */
            if (pos + 1 >= buf_len) {
                return -1;
            }
            if (!jumped) {
                consumed = pos - offset + 2;
            }
            int ptr = ((label_len & 0x3F) << 8) | buf[pos + 1];
            pos = ptr;
            jumped = 1;
            continue;
        }

        /* Normal label */
        pos += 1 + label_len;
        if (pos > buf_len) {
            return -1;
        }
    }

    return -1;
}

/* Parse DNS response and extract answer records.
 * Allocates and fills the ub_result structure.
 * Returns 0 on success, non-zero on error. */
static int _dns_parse_response(const uint8_t* resp, int resp_len,
                               const char* qname, int qtype, int qclass,
                               struct ub_result* result) {
    if (resp_len < DNS_HEADER_SIZE) {
        return -1;
    }

    /* Check QR bit (must be response) */
    uint16_t flags = (resp[2] << 8) | resp[3];
    if (!(flags & DNS_FLAG_QR)) {
        return -1;
    }

    result->rcode = flags & DNS_FLAG_RCODE_MASK;
    result->qname = strdup(qname);
    result->qtype = qtype;
    result->qclass = qclass;

    uint16_t qdcount = (resp[4] << 8) | resp[5];
    uint16_t ancount = (resp[6] << 8) | resp[7];

    /* Store the raw answer packet */
    result->answer_packet = malloc(resp_len);
    if (result->answer_packet) {
        memcpy(result->answer_packet, resp, resp_len);
        result->answer_len = resp_len;
    }

    if (result->rcode == 3) {
        /* NXDOMAIN */
        result->nxdomain = 1;
        result->havedata = 0;
        result->data = calloc(1, sizeof(char*));
        result->len = calloc(1, sizeof(int));
        return 0;
    }

    if (result->rcode != 0) {
        result->havedata = 0;
        result->data = calloc(1, sizeof(char*));
        result->len = calloc(1, sizeof(int));
        return 0;
    }

    /* Skip question section */
    int pos = DNS_HEADER_SIZE;
    for (int i = 0; i < qdcount; i++) {
        int skip = _dns_skip_name(resp, resp_len, pos);
        if (skip < 0) return -1;
        pos += skip + 4; /* +4 for QTYPE + QCLASS */
        if (pos > resp_len) return -1;
    }

    /* Parse answer section */
    /* Allocate arrays for data pointers and lengths (ancount + 1 for NULL terminator) */
    result->data = calloc(ancount + 1, sizeof(char*));
    result->len = calloc(ancount + 1, sizeof(int));
    if (!result->data || !result->len) {
        return -1;
    }

    int data_idx = 0;
    for (int i = 0; i < ancount && pos < resp_len; i++) {
        /* Skip name */
        int skip = _dns_skip_name(resp, resp_len, pos);
        if (skip < 0) break;
        pos += skip;

        if (pos + 10 > resp_len) break;

        uint16_t rtype = (resp[pos] << 8) | resp[pos + 1];
        /* uint16_t rclass = (resp[pos + 2] << 8) | resp[pos + 3]; */
        uint32_t rttl = ((uint32_t)resp[pos + 4] << 24) | ((uint32_t)resp[pos + 5] << 16) |
                        ((uint32_t)resp[pos + 6] << 8) | (uint32_t)resp[pos + 7];
        uint16_t rdlength = (resp[pos + 8] << 8) | resp[pos + 9];
        pos += 10;

        if (pos + rdlength > resp_len) break;

        if (rtype == qtype && data_idx < ancount) {
            /* Copy the RDATA */
            result->data[data_idx] = malloc(rdlength);
            if (result->data[data_idx]) {
                memcpy(result->data[data_idx], &resp[pos], rdlength);
                result->len[data_idx] = rdlength;
                data_idx++;
            }
            /* Use TTL from first matching record */
            if (data_idx == 1) {
                result->ttl = (int)rttl;
            }
        }

        pos += rdlength;
    }

    result->data[data_idx] = NULL;
    result->havedata = (data_idx > 0) ? 1 : 0;

    return 0;
}

/* Perform a DNS query over UDP.
 * Returns 0 on success, non-zero on error. */
static int _dns_udp_query(const char* server_ip, const char* name,
                          int rrtype, int rrclass, struct ub_result* result) {
    uint8_t query_buf[DNS_MAX_PACKET_SIZE];
    uint8_t resp_buf[DNS_MAX_PACKET_SIZE];

    /* Use a simple transaction ID based on name hash */
    uint16_t txn_id = 0;
    for (const char* p = name; *p; p++) {
        txn_id = txn_id * 31 + (uint8_t)*p;
    }
    txn_id |= 0x0100; /* Ensure non-zero */

    int query_len = _dns_build_query(name, rrtype, rrclass, txn_id,
                                     query_buf, sizeof(query_buf));
    if (query_len < 0) {
        warning("DNS shim: failed to build query for %s", name);
        return UB_SYNTAX;
    }

    /* Create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        warning("DNS shim: socket() failed: %s", strerror(errno));
        return UB_SERVFAIL;
    }

    /* Set timeout (5 seconds) */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, server_ip, &dns_addr.sin_addr) != 1) {
        warning("DNS shim: invalid server IP: %s", server_ip);
        close(sock);
        return UB_SYNTAX;
    }

    /* Send query */
    ssize_t sent = sendto(sock, query_buf, query_len, 0,
                          (struct sockaddr*)&dns_addr, sizeof(dns_addr));
    if (sent != query_len) {
        warning("DNS shim: sendto() failed: %s", strerror(errno));
        close(sock);
        return UB_SERVFAIL;
    }

    debug("DNS shim: sent %d byte query for %s (type %d) to %s",
          query_len, name, rrtype, server_ip);

    /* Receive response */
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t recv_len = recvfrom(sock, resp_buf, sizeof(resp_buf), 0,
                                (struct sockaddr*)&from_addr, &from_len);
    close(sock);

    if (recv_len < DNS_HEADER_SIZE) {
        warning("DNS shim: recvfrom() failed or short response: %zd bytes", recv_len);
        return UB_SERVFAIL;
    }

    /* Verify transaction ID */
    uint16_t resp_txn = (resp_buf[0] << 8) | resp_buf[1];
    if (resp_txn != txn_id) {
        warning("DNS shim: txn ID mismatch: expected %04x got %04x", txn_id, resp_txn);
        return UB_SERVFAIL;
    }

    debug("DNS shim: received %zd byte response for %s", recv_len, name);

    /* Parse response */
    int rv = _dns_parse_response(resp_buf, (int)recv_len, name, rrtype, rrclass, result);
    if (rv != 0) {
        warning("DNS shim: failed to parse response for %s", name);
        return UB_SERVFAIL;
    }

    return UB_NOERROR;
}

/*
 * Public API functions that interpose libunbound via LD_PRELOAD.
 */

struct ub_ctx* ub_ctx_create(void) {
    struct ub_ctx* ctx = calloc(1, sizeof(struct ub_ctx));
    if (ctx) {
        ctx->do_udp = 1; /* Default: UDP enabled */
        ctx->do_tcp = 0;
        debug("DNS shim: ub_ctx_create() -> %p", (void*)ctx);
    }
    return ctx;
}

void ub_ctx_delete(struct ub_ctx* ctx) {
    debug("DNS shim: ub_ctx_delete(%p)", (void*)ctx);
    free(ctx);
}

int ub_ctx_set_fwd(struct ub_ctx* ctx, const char* addr) {
    if (!ctx || !addr) return UB_SYNTAX;
    strncpy(ctx->fwd_addr, addr, sizeof(ctx->fwd_addr) - 1);
    ctx->fwd_addr[sizeof(ctx->fwd_addr) - 1] = '\0';
    ctx->has_fwd = 1;
    debug("DNS shim: ub_ctx_set_fwd(%p, \"%s\")", (void*)ctx, addr);
    return UB_NOERROR;
}

int ub_ctx_set_option(struct ub_ctx* ctx, const char* opt, const char* val) {
    if (!ctx || !opt || !val) return UB_SYNTAX;
    debug("DNS shim: ub_ctx_set_option(%p, \"%s\", \"%s\")", (void*)ctx, opt, val);
    if (strcmp(opt, "do-tcp:") == 0) {
        ctx->do_tcp = (strcmp(val, "yes") == 0) ? 1 : 0;
    } else if (strcmp(opt, "do-udp:") == 0) {
        ctx->do_udp = (strcmp(val, "yes") == 0) ? 1 : 0;
    }
    return UB_NOERROR;
}

int ub_ctx_get_option(struct ub_ctx* ctx, const char* opt, char** str) {
    (void)ctx; (void)opt;
    if (str) *str = strdup("");
    return UB_NOERROR;
}

int ub_ctx_resolvconf(struct ub_ctx* ctx, const char* fname) {
    debug("DNS shim: ub_ctx_resolvconf(%p, \"%s\")", (void*)ctx,
          fname ? fname : "(null)");
    /* If no forwarder is set yet, try to read resolv.conf */
    if (ctx && !ctx->has_fwd) {
        const char* path = fname ? fname : "/etc/resolv.conf";
        FILE* f = fopen(path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                char ns[64];
                if (sscanf(line, "nameserver %63s", ns) == 1) {
                    /* Skip loopback (won't work in Shadow) */
                    if (strncmp(ns, "127.", 4) != 0) {
                        strncpy(ctx->fwd_addr, ns, sizeof(ctx->fwd_addr) - 1);
                        ctx->fwd_addr[sizeof(ctx->fwd_addr) - 1] = '\0';
                        ctx->has_fwd = 1;
                        debug("DNS shim: read nameserver %s from %s", ns, path);
                        break;
                    }
                }
            }
            fclose(f);
        }
    }
    return UB_NOERROR;
}

int ub_ctx_hosts(struct ub_ctx* ctx, const char* fname) {
    (void)ctx; (void)fname;
    return UB_NOERROR;
}

int ub_ctx_add_ta(struct ub_ctx* ctx, const char* ta) {
    (void)ctx; (void)ta;
    /* We don't validate DNSSEC in the shim */
    return UB_NOERROR;
}

int ub_ctx_add_ta_file(struct ub_ctx* ctx, const char* fname) {
    (void)ctx; (void)fname;
    return UB_NOERROR;
}

int ub_ctx_add_ta_autr(struct ub_ctx* ctx, const char* fname) {
    (void)ctx; (void)fname;
    return UB_NOERROR;
}

int ub_ctx_trustedkeys(struct ub_ctx* ctx, const char* fname) {
    (void)ctx; (void)fname;
    return UB_NOERROR;
}

int ub_ctx_debugout(struct ub_ctx* ctx, void* out) {
    (void)ctx; (void)out;
    return UB_NOERROR;
}

int ub_ctx_debuglevel(struct ub_ctx* ctx, int d) {
    (void)ctx; (void)d;
    return UB_NOERROR;
}

int ub_ctx_async(struct ub_ctx* ctx, int dothread) {
    (void)ctx; (void)dothread;
    return UB_NOERROR;
}

int ub_ctx_config(struct ub_ctx* ctx, const char* fname) {
    (void)ctx; (void)fname;
    return UB_NOERROR;
}

int ub_ctx_set_tls(struct ub_ctx* ctx, int tls) {
    (void)ctx; (void)tls;
    return UB_NOERROR;
}

int ub_ctx_set_stub(struct ub_ctx* ctx, const char* zone, const char* addr,
                    int isprime) {
    (void)ctx; (void)zone; (void)addr; (void)isprime;
    return UB_NOERROR;
}

int ub_poll(struct ub_ctx* ctx) {
    (void)ctx;
    return 0;
}

int ub_wait(struct ub_ctx* ctx) {
    (void)ctx;
    return UB_NOERROR;
}

int ub_fd(struct ub_ctx* ctx) {
    (void)ctx;
    return -1;
}

int ub_process(struct ub_ctx* ctx) {
    (void)ctx;
    return UB_NOERROR;
}

int ub_resolve(struct ub_ctx* ctx, const char* name, int rrtype,
               int rrclass, struct ub_result** result) {
    debug("DNS shim: ub_resolve(%p, \"%s\", type=%d, class=%d)",
          (void*)ctx, name ? name : "(null)", rrtype, rrclass);

    if (!ctx || !name || !result) {
        return UB_SYNTAX;
    }

    /* Allocate result */
    struct ub_result* res = calloc(1, sizeof(struct ub_result));
    if (!res) {
        return UB_NOMEM;
    }

    *result = res;

    if (!ctx->has_fwd) {
        warning("DNS shim: no forwarder configured, returning empty result for %s", name);
        res->qname = strdup(name);
        res->qtype = rrtype;
        res->qclass = rrclass;
        res->rcode = 2; /* SERVFAIL */
        res->havedata = 0;
        res->data = calloc(1, sizeof(char*));
        res->len = calloc(1, sizeof(int));
        return UB_NOERROR;
    }

    int rv = _dns_udp_query(ctx->fwd_addr, name, rrtype, rrclass, res);
    if (rv != UB_NOERROR) {
        /* Fill in minimal result on failure */
        if (!res->qname) res->qname = strdup(name);
        res->qtype = rrtype;
        res->qclass = rrclass;
        res->rcode = 2; /* SERVFAIL */
        if (!res->data) res->data = calloc(1, sizeof(char*));
        if (!res->len) res->len = calloc(1, sizeof(int));
        /* Return 0 (no error) but with SERVFAIL rcode, matching libunbound behavior */
        return UB_NOERROR;
    }

    /* Simulate valid DNSSEC so Monero's checkpoint code accepts the records.
     * Monero checks: dnssec_available = (secure || bogus), dnssec_valid = secure && !bogus.
     * We set secure=1, bogus=0 to indicate a valid DNSSEC response. */
    res->secure = 1;

    debug("DNS shim: ub_resolve for %s: rcode=%d havedata=%d secure=%d",
          name, res->rcode, res->havedata, res->secure);

    return UB_NOERROR;
}

int ub_resolve_async(struct ub_ctx* ctx, const char* name, int rrtype,
                     int rrclass, void* mydata,
                     void (*callback)(void*, int, struct ub_result*),
                     int* async_id) {
    /* For async, just do it synchronously and call the callback */
    struct ub_result* result = NULL;
    int err = ub_resolve(ctx, name, rrtype, rrclass, &result);
    if (callback) {
        callback(mydata, err, result);
    }
    if (async_id) *async_id = 0;
    return err;
}

int ub_cancel(struct ub_ctx* ctx, int async_id) {
    (void)ctx; (void)async_id;
    return UB_NOERROR;
}

void ub_resolve_free(struct ub_result* result) {
    if (!result) return;

    free(result->qname);
    free(result->canonname);
    free(result->why_bogus);
    free(result->answer_packet);

    if (result->data) {
        for (int i = 0; result->data[i] != NULL; i++) {
            free(result->data[i]);
        }
        free(result->data);
    }
    free(result->len);
    free(result);
}

const char* ub_strerror(int err) {
    switch (err) {
        case 0: return "no error";
        case 1: return "out of memory";
        case 2: return "syntax error";
        case 3: return "server failure";
        default: return "unknown error";
    }
}

int ub_ctx_print_local_zones(struct ub_ctx* ctx) {
    (void)ctx;
    return UB_NOERROR;
}

int ub_ctx_zone_add(struct ub_ctx* ctx, const char* zone_name,
                    const char* zone_type) {
    (void)ctx; (void)zone_name; (void)zone_type;
    return UB_NOERROR;
}

int ub_ctx_zone_remove(struct ub_ctx* ctx, const char* zone_name) {
    (void)ctx; (void)zone_name;
    return UB_NOERROR;
}

int ub_ctx_data_add(struct ub_ctx* ctx, const char* data) {
    (void)ctx; (void)data;
    return UB_NOERROR;
}

int ub_ctx_data_remove(struct ub_ctx* ctx, const char* data) {
    (void)ctx; (void)data;
    return UB_NOERROR;
}

const char* ub_version(void) {
    return "shadow-shim-1.0";
}
