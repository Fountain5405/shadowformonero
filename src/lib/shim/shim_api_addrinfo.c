/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */
#include "lib/shim/shim_api_c.h"

#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/logger/logger.h"
#include "lib/shim/shim.h"
#include "lib/shim/shim_syscall.h"
#include "lib/shadow-shim-helper-rs/shim_helper.h"

// Sets `port` to the port specified by `service`, according to the criteria in
// getaddrinfo(3). Returns 0 on success or the appropriate getaddrinfo error on
// failure.
static int _getaddrinfo_service(in_port_t* port, const char* service,
                                const struct addrinfo* hints) {
    char* endptr;
    *port = htons(strtol(service, &endptr, 10));
    if (*service != '\0' && *endptr == '\0') {
        return 0;
    }

    // getaddrinfo(3): "EAI_NONAME: ... or AI_NUMERICSERV was specified in
    // hints.ai_flags and service was not a numeric port-number string."
    if (hints->ai_flags & AI_NUMERICSERV) {
        return EAI_NONAME;
    }

    // `buf` will be used for strings pointed to in `result`.
    // 1024 is the recommended size in getservbyname_r(3).
    char buf[1024];
    struct servent servent;
    struct servent* result;
    int rv = getservbyname_r(service, NULL, &servent, buf, 1024, &result);
    if (rv != 0) {
        // According to getservbyname_r(3): "On error, they return one of the
        // positive error numbers listed in errors." The only one documented as
        // possibly being returned by getserbyname_r is ERANGE, indicating that
        // the buffer was too small. We *could* retry with a bigger buffer, but
        // that really shouldn't be needed.
        //
        // getaddrinfo(3): "EAI_SYSTEM: Other system error, check errno for
        // details."
        if (rv == EBADF || rv == ENOENT) {
            // In cases where libc wasn't able to connect to a local resolver
            // (which is expected under Shadow), and the service wasn't found in
            // /etc/services, some versions of libc return non-zero rv and
            // errno=EBADF or ENOENT.
            // https://github.com/shadow/shadow/issues/1869
            // https://github.com/shadow/shadow/issues/2286
            warning("Converting err %d to EAI_SERVICE to work around #1869 or #2286", rv);
            return EAI_SERVICE;
        }
        errno = rv;
        return EAI_SYSTEM;
    }
    if (result == NULL) {
        // getaddrinfo(3): "The  requested  service  is not available for the
        // requested socket type."
        return EAI_SERVICE;
    }
    // While getaddrinfo(3) seems to indicate that we should restrict which
    // protocols we return based on the specific service, and fail if the
    // service we found was incompatible with the requested socket type or
    // protocol, experimentally glibc doesn't do this. e.g., for "80" or "http"
    // it will return UDP and RAW in addition to TCP, despite /etc/services
    // only containing a TCP entry for that protocol.
    *port = result->s_port;
    return rv;
}

// Creates an `addrinfo` pointing to `addr`, and adds it to the linked list
// specified by `head` and `tail`. An empty list can be passed in by setting
// `*head` and `*tail` to NULL.
static void _getaddrinfo_append(struct addrinfo** head, struct addrinfo** tail, int socktype,
                                struct sockaddr* addr, socklen_t addrlen) {
    int protocol = 0;
    if (socktype == SOCK_DGRAM) {
        protocol = IPPROTO_UDP;
    }
    if (socktype == SOCK_STREAM) {
        protocol = IPPROTO_TCP;
    }
    if (socktype == SOCK_RAW) {
        protocol = 0;
    }
    struct addrinfo* new_tail = malloc(sizeof(*new_tail));
    *new_tail = (struct addrinfo){.ai_flags = 0,
                                  .ai_family = AF_INET,
                                  .ai_socktype = socktype,
                                  .ai_protocol = protocol,
                                  .ai_addrlen = addrlen,
                                  .ai_addr = addr,
                                  .ai_canonname = NULL,
                                  .ai_next = NULL};
    if (*tail != NULL) {
        (*tail)->ai_next = new_tail;
    }
    *tail = new_tail;
    if (*head == NULL) {
        *head = new_tail;
    }
}

// IPv4 wrapper for _getaddrinfo_append. Appends an entry for the address and
// port for each requested socket type.
static void _getaddrinfo_appendv4(struct addrinfo** head, struct addrinfo** tail, bool add_tcp,
                                  bool add_udp, bool add_raw, uint32_t s_addr, in_port_t port) {
    if (add_tcp) {
        struct sockaddr_in* sai = malloc(sizeof(*sai));
        *sai = (struct sockaddr_in){.sin_family = AF_INET, .sin_port = port, .sin_addr = {s_addr}};
        _getaddrinfo_append(head, tail, SOCK_STREAM, (struct sockaddr*)sai, sizeof(*sai));
    }
    if (add_udp) {
        struct sockaddr_in* sai = malloc(sizeof(*sai));
        *sai = (struct sockaddr_in){.sin_family = AF_INET, .sin_port = port, .sin_addr = {s_addr}};
        _getaddrinfo_append(head, tail, SOCK_DGRAM, (struct sockaddr*)sai, sizeof(*sai));
    }
    if (add_raw) {
        struct sockaddr_in* sai = malloc(sizeof(*sai));
        *sai = (struct sockaddr_in){.sin_family = AF_INET, .sin_port = port, .sin_addr = {s_addr}};
        _getaddrinfo_append(head, tail, SOCK_RAW, (struct sockaddr*)sai, sizeof(*sai));
    }
}

// Looks for matching IPv4 addresses in /etc/hosts and them to the list
// specified by `head` and `tail`.
static void _getaddrinfo_add_matching_hosts_ipv4(struct addrinfo** head, struct addrinfo** tail,
                                                 const char* node, bool add_tcp, bool add_udp,
                                                 bool add_raw, in_port_t port) {
    // TODO: Parse hosts file once and keep it in an efficiently-searchable
    // in-memory format.
    GError* error = NULL;
    gchar* hosts = NULL;
    char* pattern = NULL;
    GMatchInfo* match_info = NULL;
    GRegex* regex = NULL;

    trace("Reading /etc/hosts file");

    g_file_get_contents("/etc/hosts", &hosts, NULL, &error);
    if (error != NULL) {
        panic("Reading /etc/hosts: %s", error->message);
        goto out;
    }
    assert(hosts != NULL);

    trace("Scanning /etc/hosts contents for name %s", node);

    {
        gchar* escaped_node = g_regex_escape_string(node, -1);
        // Build a regex to match an IPv4 address entry for the given `node` in
        // /etc/hosts. See HOSTS(5) for format specification.
        int rv = asprintf(&pattern, "^(\\d+\\.\\d+\\.\\d+\\.\\d+)[^#\n]*\\b%s\\b", escaped_node);
        g_free(escaped_node);
        if (rv < 0) {
            panic("asprintf failed: %d", rv);
            goto out;
        }
    }
    trace("Node:%s -> regex:%s", node, pattern);

    regex = g_regex_new(pattern, G_REGEX_MULTILINE, 0, &error);
    if (error != NULL) {
        panic("g_regex_new: %s", error->message);
        goto out;
    }
    assert(regex != NULL);

    g_regex_match(regex, hosts, 0, &match_info);
    // /etc/host.conf specifies whether to return all matching addresses or only
    // the first. The recommended configuration is to only return the first. For
    // now we hard-code that behavior.
    if (g_match_info_matches(match_info)) {
#ifdef DEBUG
        {
            gchar* matched_string = g_match_info_fetch(match_info, 0);
            trace("Node:%s -> match:%s", node, matched_string);
            g_free(matched_string);
        }
#endif
        gchar* address_string = g_match_info_fetch(match_info, 1);
        trace("Node:%s -> address string:%s", node, address_string);
        assert(address_string != NULL);
        uint32_t addr;
        int rv = inet_pton(AF_INET, address_string, &addr);
        if (rv != 1) {
            panic("Bad address in /etc/hosts: %s\n", address_string);
        } else {
            _getaddrinfo_appendv4(head, tail, add_tcp, add_udp, add_raw, addr, port);
        }
        g_free(address_string);
    }
out:
    if (match_info != NULL)
        g_match_info_free(match_info);
    if (regex != NULL)
        g_regex_unref(regex);
    if (pattern != NULL)
        free(pattern);
    if (hosts != NULL)
        g_free(hosts);
}

// Ask shadow to provide an ipv4 addr for a node using a custom syscall.
// Returns true if we got a valid address from shadow, false otherwise.
static bool _shim_api_hostname_to_addr_ipv4(const char* node, uint32_t* addr) {
    if (!node || !addr) {
        return false;
    }

    // Skip the Shadow syscall for localhost lookups.
    if (strcasecmp(node, "localhost") == 0) {
        // Loopback address in network order.
        *addr = htonl(INADDR_LOOPBACK);
        trace("handled localhost getaddrinfo() lookup locally");
        return true;
    }

    // Resolve the hostname (find the ipv4 `addr` associated with hostname `name`) using a custom
    // syscall that Shadow handles internally. We want to execute natively in ptrace mode so ptrace
    // can intercept it, but we want to send to Shadow through shmem in preload mode. Let
    // shim_syscall figure it out.
    trace("Performing custom shadow syscall SYS_shadow_hostname_to_addr_ipv4 for name %s", node);
    int rv = shim_api_syscall(
        SHADOW_SYSCALL_NUM_HOSTNAME_TO_ADDR_IPV4, node, strlen(node), addr, sizeof(*addr));

    if (rv == 0) {
#ifdef DEBUG
        char addr_str_buf[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, (struct in_addr*)addr, addr_str_buf, INET_ADDRSTRLEN)) {
            trace("SYS_shadow_hostname_to_addr_ipv4 returned addr %s for name %s", addr_str_buf,
                  node);
        } else {
            trace("SYS_shadow_hostname_to_addr_ipv4 succeeded for name %s", node);
        }
#endif
        return true;
    } else {
        trace("SYS_shadow_hostname_to_addr_ipv4 failed for name %s", node);
        return false;
    }
}

// DNS query constants (RFC 1035)
#define DNS_PORT 53
#define DNS_MAX_PACKET_SIZE 512
#define DNS_HEADER_SIZE 12
#define DNS_TYPE_A 1
#define DNS_CLASS_IN 1
#define DNS_FLAG_QR 0x8000      // Response flag
#define DNS_FLAG_RCODE_MASK 0x000F

// Build a DNS query packet for the given hostname.
// Returns the packet size, or -1 on error.
static int _build_dns_query(uint8_t* buf, size_t buf_size, const char* hostname, uint16_t query_id) {
    if (strlen(hostname) > 253) {
        return -1;  // Hostname too long
    }

    size_t offset = 0;

    // DNS Header (12 bytes)
    // ID (2 bytes)
    buf[offset++] = (query_id >> 8) & 0xFF;
    buf[offset++] = query_id & 0xFF;
    // Flags (2 bytes): standard query, recursion desired
    buf[offset++] = 0x01;  // RD=1
    buf[offset++] = 0x00;
    // QDCOUNT (2 bytes): 1 question
    buf[offset++] = 0x00;
    buf[offset++] = 0x01;
    // ANCOUNT, NSCOUNT, ARCOUNT (6 bytes): all 0
    for (int i = 0; i < 6; i++) {
        buf[offset++] = 0x00;
    }

    // Question section: QNAME
    // Convert hostname to DNS label format (e.g., "www.example.com" -> "\3www\7example\3com\0")
    const char* ptr = hostname;
    while (*ptr) {
        const char* dot = strchr(ptr, '.');
        size_t label_len = dot ? (size_t)(dot - ptr) : strlen(ptr);
        if (label_len > 63 || label_len == 0) {
            return -1;  // Invalid label
        }
        if (offset + label_len + 1 >= buf_size) {
            return -1;  // Buffer too small
        }
        buf[offset++] = (uint8_t)label_len;
        memcpy(&buf[offset], ptr, label_len);
        offset += label_len;
        ptr = dot ? dot + 1 : ptr + label_len;
    }
    buf[offset++] = 0x00;  // Null terminator for QNAME

    // QTYPE (2 bytes): A record
    buf[offset++] = 0x00;
    buf[offset++] = DNS_TYPE_A;
    // QCLASS (2 bytes): IN (Internet)
    buf[offset++] = 0x00;
    buf[offset++] = DNS_CLASS_IN;

    return (int)offset;
}

// Parse a DNS name from the packet, handling compression pointers.
// Returns the number of bytes consumed from the current position, or -1 on error.
static int _skip_dns_name(const uint8_t* buf, size_t buf_size, size_t offset) {
    int consumed = 0;
    bool jumped = false;

    while (offset < buf_size) {
        uint8_t len = buf[offset];
        if (len == 0) {
            // End of name
            if (!jumped) consumed++;
            return consumed;
        } else if ((len & 0xC0) == 0xC0) {
            // Compression pointer (2 bytes)
            if (!jumped) consumed += 2;
            // Follow the pointer (but we're just skipping, so don't need to)
            return consumed;
        } else if ((len & 0xC0) == 0) {
            // Regular label
            if (!jumped) consumed += 1 + len;
            offset += 1 + len;
        } else {
            return -1;  // Invalid label
        }
    }
    return -1;  // Ran off end of buffer
}

// Perform a DNS query for A records and add results to the addrinfo list.
// Returns the number of addresses added, or -1 on error.
static int _getaddrinfo_dns_query_ipv4(struct addrinfo** head, struct addrinfo** tail,
                                       const char* node, bool add_tcp, bool add_udp,
                                       bool add_raw, in_port_t port, uint32_t dns_server_ip) {
    if (dns_server_ip == 0) {
        return 0;  // No DNS server configured
    }

    uint8_t query_buf[DNS_MAX_PACKET_SIZE];
    uint8_t response_buf[DNS_MAX_PACKET_SIZE];

    // Generate a simple query ID (doesn't need to be cryptographically random)
    uint16_t query_id = (uint16_t)(((uintptr_t)node ^ (uintptr_t)head) & 0xFFFF);

    // Build the DNS query
    int query_len = _build_dns_query(query_buf, sizeof(query_buf), node, query_id);
    if (query_len < 0) {
        trace("Failed to build DNS query for %s", node);
        return -1;
    }

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        trace("Failed to create UDP socket for DNS query: %s", strerror(errno));
        return -1;
    }

    // Set socket timeout (2 seconds)
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Send query to DNS server
    struct sockaddr_in dns_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr = {.s_addr = dns_server_ip}  // Already in network byte order
    };

    trace("Sending DNS query for %s to DNS server", node);
    ssize_t sent = sendto(sock, query_buf, query_len, 0,
                          (struct sockaddr*)&dns_addr, sizeof(dns_addr));
    if (sent != query_len) {
        trace("Failed to send DNS query: %s", strerror(errno));
        close(sock);
        return -1;
    }

    // Receive response
    ssize_t recv_len = recv(sock, response_buf, sizeof(response_buf), 0);
    close(sock);

    if (recv_len < DNS_HEADER_SIZE) {
        trace("DNS response too short or recv failed: %zd", recv_len);
        return -1;
    }

    // Parse DNS response header
    uint16_t resp_id = (response_buf[0] << 8) | response_buf[1];
    uint16_t flags = (response_buf[2] << 8) | response_buf[3];
    uint16_t qdcount = (response_buf[4] << 8) | response_buf[5];
    uint16_t ancount = (response_buf[6] << 8) | response_buf[7];

    // Verify response
    if (resp_id != query_id) {
        trace("DNS response ID mismatch: expected %u, got %u", query_id, resp_id);
        return -1;
    }
    if (!(flags & DNS_FLAG_QR)) {
        trace("DNS response is not a response (QR=0)");
        return -1;
    }
    if ((flags & DNS_FLAG_RCODE_MASK) != 0) {
        trace("DNS response error code: %u", flags & DNS_FLAG_RCODE_MASK);
        return -1;
    }
    if (ancount == 0) {
        trace("DNS response has no answers");
        return 0;
    }

    // Skip question section
    size_t offset = DNS_HEADER_SIZE;
    for (int i = 0; i < qdcount; i++) {
        int skip = _skip_dns_name(response_buf, recv_len, offset);
        if (skip < 0) return -1;
        offset += skip;
        offset += 4;  // QTYPE + QCLASS
        if (offset > (size_t)recv_len) return -1;
    }

    // Parse answer section
    int addresses_added = 0;
    for (int i = 0; i < ancount && offset < (size_t)recv_len; i++) {
        // Skip NAME
        int skip = _skip_dns_name(response_buf, recv_len, offset);
        if (skip < 0) break;
        offset += skip;

        if (offset + 10 > (size_t)recv_len) break;  // Need TYPE, CLASS, TTL, RDLENGTH

        uint16_t type = (response_buf[offset] << 8) | response_buf[offset + 1];
        offset += 2;
        uint16_t class = (response_buf[offset] << 8) | response_buf[offset + 1];
        offset += 2;
        offset += 4;  // Skip TTL
        uint16_t rdlength = (response_buf[offset] << 8) | response_buf[offset + 1];
        offset += 2;

        if (offset + rdlength > (size_t)recv_len) break;

        // Only process A records (IPv4)
        if (type == DNS_TYPE_A && class == DNS_CLASS_IN && rdlength == 4) {
            uint32_t addr;
            memcpy(&addr, &response_buf[offset], 4);
            _getaddrinfo_appendv4(head, tail, add_tcp, add_udp, add_raw, addr, port);
            addresses_added++;
            trace("DNS query for %s: got address %u.%u.%u.%u", node,
                  response_buf[offset], response_buf[offset+1],
                  response_buf[offset+2], response_buf[offset+3]);
        }

        offset += rdlength;
    }

    trace("DNS query for %s returned %d addresses", node, addresses_added);
    return addresses_added;
}

int shimc_api_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints,
                         struct addrinfo** res) {
    // Quoted text is from the man page.

    // "Either node or service, but not both, may be NULL."
    // "EAI_NONAME...both node and service are NULL"
    if (node == NULL && service == NULL) {
        return EAI_NONAME;
    }

    // "Specifying  hints  as  NULL  is  equivalent  to setting ai_socktype and
    // ai_protocol to 0; ai_family to AF_UNSPEC; and ai_flags to (AI_V4MAPPED |
    // AI_ADDRCONFIG).
    static const struct addrinfo default_hints = {.ai_socktype = 0,
                                                  .ai_protocol = 0,
                                                  .ai_family = AF_UNSPEC,
                                                  .ai_flags = AI_V4MAPPED | AI_ADDRCONFIG};
    if (hints == NULL) {
        hints = &default_hints;
    }

    // "`service` sets the port in each returned address structure."
    in_port_t port = 0;
    if (service != NULL) {
        int rv = _getaddrinfo_service(&port, service, hints);
        if (rv != 0) {
            return rv;
        }
    }

    // "There are several reasons why the linked list may have more than one
    // addrinfo structure, including: the network host is ... the same service
    // is available from multiple socket types (one SOCK_STREAM address and
    // another SOCK_DGRAM address, for example)."
    //
    // Experimentally, glibc doesn't pay attention to which protocols are
    // specified for the given port in /etc/services; it returns all protocols
    // that are compatible with `hints`. We do the same for compatibility.
    bool add_tcp = (hints->ai_socktype == 0 || hints->ai_socktype == SOCK_STREAM) &&
                   (hints->ai_protocol == 0 || hints->ai_protocol == IPPROTO_TCP);
    bool add_udp = (hints->ai_socktype == 0 || hints->ai_socktype == SOCK_DGRAM) &&
                   (hints->ai_protocol == 0 || hints->ai_protocol == IPPROTO_UDP);
    bool add_raw =
        (hints->ai_socktype == 0 || hints->ai_socktype == SOCK_RAW) && (hints->ai_protocol == 0);

    // "If hints.ai_flags includes the AI_ADDRCONFIG flag, then IPv4 addresses
    // are returned in the list pointed to by  res  only  if  the local  system
    // has at least one IPv4 address configured, and IPv6 addresses are
    // returned only if the local system has at least one IPv6 address
    // configured."
    //
    // Determining what kind of addresses the local system has configured is
    // unimplemented. For now we assume it has IPv4 and not IPv6.
    const bool system_has_an_ipv4_address = true;
    const bool system_has_an_ipv6_address = false;

    // "There are several reasons why the linked list may have more than one
    // addrinfo structure, including: the network host is ... accessible  over
    // multiple  protocols  (e.g., both AF_INET and AF_INET6)"
    //
    // Here we constrain which protocols to consider, so that we can not bother
    // doing lookups for other protocols.
    const bool add_ipv4 = hints->ai_family == AF_UNSPEC ||
                          (hints->ai_family == AF_INET &&
                           !((hints->ai_flags & AI_ADDRCONFIG) && !system_has_an_ipv4_address));
    const bool add_ipv6 = hints->ai_family == AF_UNSPEC ||
                          (hints->ai_family == AF_INET6 &&
                           !((hints->ai_flags & AI_ADDRCONFIG) && !system_has_an_ipv6_address));

    // "EAI_ADDRFAMILY: The specified network host does not have any network
    // addresses in the requested address family."
    if (!add_ipv4 && !add_ipv6) {
        return EAI_ADDRFAMILY;
    }

    // *res will be the head of the linked lists of results. For efficiency we
    // also keep track of the tail of the list.
    *res = NULL;
    struct addrinfo* tail = NULL;

    // No address lookups needed if `node` is NULL.
    if (node == NULL) {
        if (hints->ai_flags & AI_PASSIVE) {
            // "If the AI_PASSIVE flag is specified in hints.ai_flags, and node
            // is NULL, then the returned socket addresses will be suitable  for
            // bind(2)ing a socket that will accept(2) connections.  The
            // returned socket address will contain the "wildcard address"
            // (INADDR_ANY for IPv4 addresses, IN6ADDR_ANY_INIT for IPv6
            // address)."
            if (add_ipv4) {
                _getaddrinfo_appendv4(
                    res, &tail, add_tcp, add_udp, add_raw, ntohl(INADDR_ANY), port);
            }
            if (add_ipv6) {
                // TODO: IPv6
            }
        } else {
            // "If the AI_PASSIVE flag is not set in hints.ai_flags, then the
            // returned socket addresses will be suitable for use with
            // connect(2), sendto(2), or sendmsg(2). If node is NULL, then the
            // network address will be set to the loopback interface address
            // (INADDR_LOOP‐ BACK  for  IPv4  addresses, IN6ADDR_LOOPBACK_INIT
            // for IPv6 address);"
            if (add_ipv4) {
                _getaddrinfo_appendv4(
                    res, &tail, add_tcp, add_udp, add_raw, ntohl(INADDR_LOOPBACK), port);
            }
            if (add_ipv6) {
                // TODO: IPv6
            }
        }
        // We've finished adding all relevant addresses.
        if (*res != NULL) {
            return 0;
        } else {
            return EAI_NONAME;
        }
    }

    // "`node` specifies either a numerical network address..."
    if (add_ipv6) {
        // TODO: try parsing as IPv6
    }
    if (add_ipv4) {
        uint32_t addr;
        if (inet_pton(AF_INET, node, &addr) == 1) {
            _getaddrinfo_appendv4(res, &tail, add_tcp, add_udp, add_raw, addr, port);
        }
    }
    // If we successfully parsed as a numeric address, there's no need to
    // continue on to doing name-based lookups.
    if (*res != NULL) {
        return 0;
    }
    // "If  hints.ai_flags  contains the  AI_NUMERICHOST  flag,  then  node
    // must be a numerical network address."
    if (hints->ai_flags & AI_NUMERICHOST) {
        // "The node or service is not known; or both node and service are NULL;
        // or AI_NUMERICSERV was specified in hints.ai_flags and service was not
        // a numeric port-number string."
        //
        // The man page isn't 100% explicit about which error to return in this
        // case, but EAI_NONAME is plausible based on the above, and it's what
        // glibc returns.
        return EAI_NONAME;
    }

    // "node specifies either a  numerical network  address...or a network
    // hostname, whose network addresses are looked up and resolved."
    //
    // Name lookup order:
    // 1. Configured DNS server (if set) - takes precedence for simulation
    // 2. Shadow's internal hostname database
    // 3. /etc/hosts file
    if (add_ipv6) {
        // TODO: look for IPv6 addresses in /etc/hosts.
    }
    if (add_ipv4) {
        // First, try the configured DNS server if one is set.
        // This takes precedence for simulation purposes.
        uint32_t dns_server = shimshmem_getDnsServer(shim_hostSharedMem());
        if (dns_server != 0) {
            trace("Attempting DNS query for %s", node);
            _getaddrinfo_dns_query_ipv4(res, &tail, node, add_tcp, add_udp, add_raw, port, dns_server);
        }

        // If DNS query didn't find anything, try Shadow's internal database.
        if (*res == NULL) {
            uint32_t addr;
            if (_shim_api_hostname_to_addr_ipv4(node, &addr)) {
                // We got the address we needed.
                _getaddrinfo_appendv4(res, &tail, add_tcp, add_udp, add_raw, addr, port);
            }
        }

        // Finally, fall back to scanning /etc/hosts.
        if (*res == NULL) {
            trace("Falling back to /etc/hosts scan for %s", node);
            _getaddrinfo_add_matching_hosts_ipv4(res, &tail, node, add_tcp, add_udp, add_raw, port);
        }
    }

    if (*res == NULL) {
        // "EAI_NONAME: The node or service is not known"
        return EAI_NONAME;
    }
    return 0;
}

void shimc_api_freeaddrinfo(struct addrinfo* res) {
    while (res != NULL) {
        struct addrinfo* next = res->ai_next;
        assert(res->ai_addr != NULL);
        free(res->ai_addr);
        // We don't support canonname lookups, so shouldn't have been set.
        assert(res->ai_canonname == NULL);
        free(res);
        res = next;
    }
}
