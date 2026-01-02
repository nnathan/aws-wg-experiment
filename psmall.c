#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>


#define PROB_BIG 26 // ≈ 90% (230 / 256 ≈ 0.898)

/* ---------- rng ---------------*/

static inline uint8_t xorshift8(uint8_t *state)
{
    uint8_t x = *state;
    x ^= x << 3;
    x ^= x >> 5;
    x ^= x << 1;
    *state = x;
    return x;
}

unsigned long mix(unsigned long a, unsigned long b, unsigned long c)
{
    a=a-b;  a=a-c;  a=a^(c >> 13);
    b=b-c;  b=b-a;  b=b^(a << 8);
    c=c-a;  c=c-b;  c=c^(b >> 13);
    a=a-b;  a=a-c;  a=a^(c >> 12);
    b=b-c;  b=b-a;  b=b^(a << 16);
    c=c-a;  c=c-b;  c=c^(b >> 5);
    a=a-b;  a=a-c;  a=a^(c >> 3);
    b=b-c;  b=b-a;  b=b^(a << 10);
    c=c-a;  c=c-b;  c=c^(b >> 15);
    return c;
}

/* ---------- helpers ---------- */

static uint16_t csum16(const void *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *p = data;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len)
        sum += *(uint8_t *)p;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

static uint16_t udp_checksum(const struct iphdr *ip,
                             const struct udphdr *udp,
                             const uint8_t *payload,
                             size_t payload_len) {
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } pseudo;

    pseudo.src  = ip->saddr;
    pseudo.dst  = ip->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_UDP;
    pseudo.len  = udp->len;

    uint32_t sum = 0;

    sum += csum16(&pseudo, sizeof(pseudo));
    sum += csum16(udp, sizeof(*udp));
    sum += csum16(payload, payload_len);

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

/* ---------- packet builder ---------- */

static size_t build_packet(uint8_t *buf,
                           size_t payload_len,
                           uint16_t sport,
                           uint16_t dport) {
    struct iphdr  *ip  = (struct iphdr *)buf;
    struct udphdr *udp = (struct udphdr *)(buf + sizeof(*ip));
    uint8_t       *pl  = buf + sizeof(*ip) + sizeof(*udp);

    memset(buf, 0, sizeof(*ip) + sizeof(*udp) + payload_len);
    memset(pl, 0xaa, payload_len);

    /* IP */
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(*ip) + sizeof(*udp) + payload_len);
    ip->id       = htons(0);
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr    = inet_addr("172.16.100.10");
    ip->daddr    = inet_addr("192.168.100.10");
    ip->check    = csum16(ip, sizeof(*ip));

    /* UDP */
    udp->source = htons(sport);
    udp->dest   = htons(dport);
    udp->len    = htons(sizeof(*udp) + payload_len);
    udp->check  = udp_checksum(ip, udp, pl, payload_len);

    return sizeof(*ip) + sizeof(*udp) + payload_len;
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = if_nametoindex("wg0"),
    };

    if (!sll.sll_ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        return 1;
    }

    uint8_t pkt_big[1500];
    uint8_t pkt_small[512];

    size_t len_big   = build_packet(pkt_big,   1300 - sizeof(struct iphdr) - sizeof(struct udphdr),
                                     10000, 10000);
    size_t len_small = build_packet(pkt_small, 300  - sizeof(struct iphdr) - sizeof(struct udphdr),
                                     20000, 20000);

    uint8_t rng_state;

    unsigned long seed = mix(clock(), getpid(), time(NULL));
    rng_state = (uint8_t)seed;
    if (rng_state == 0)
        rng_state = 1;

    unsigned long limit = 0;

    if (argc > 1) {
        limit = strtoul(argv[1], NULL, 10);
    }

    if (limit == 0) {
        for (;;) {
            uint8_t r = xorshift8(&rng_state);

            if (r < PROB_BIG) {
                if (send(fd, pkt_big, len_big, 0) < 0) {
                    perror("send big");
                    break;
                }
            } else {
                if (send(fd, pkt_small, len_small, 0) < 0) {
                    perror("send small");
                    break;
                }
            }
        }
    }

    for (int64_t i = 0; i < limit; i++) {
        uint8_t r = xorshift8(&rng_state);

        if (r < PROB_BIG) {
            if (send(fd, pkt_big, len_big, 0) < 0) {
                perror("send big");
                break;
            }
        } else {
            if (send(fd, pkt_small, len_small, 0) < 0) {
                perror("send small");
                break;
            }
        }
    }


    close(fd);
    return 0;
}
