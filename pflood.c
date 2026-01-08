#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---------- rng ---------------*/

static inline uint8_t xorshift8(uint8_t *state) {
  uint8_t x = *state;
  x ^= x << 3;
  x ^= x >> 5;
  x ^= x << 1;
  *state = x;
  return x;
}

unsigned long mix(unsigned long a, unsigned long b, unsigned long c) {
  a = a - b;
  a = a - c;
  a = a ^ (c >> 13);
  b = b - c;
  b = b - a;
  b = b ^ (a << 8);
  c = c - a;
  c = c - b;
  c = c ^ (b >> 13);
  a = a - b;
  a = a - c;
  a = a ^ (c >> 12);
  b = b - c;
  b = b - a;
  b = b ^ (a << 16);
  c = c - a;
  c = c - b;
  c = c ^ (b >> 5);
  a = a - b;
  a = a - c;
  a = a ^ (c >> 3);
  b = b - c;
  b = b - a;
  b = b ^ (a << 10);
  c = c - a;
  c = c - b;
  c = c ^ (b >> 15);
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

static uint16_t udp_checksum(const struct iphdr *ip, const struct udphdr *udp,
                             const uint8_t *payload, size_t payload_len) {
  struct {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
  } pseudo;

  pseudo.src = ip->saddr;
  pseudo.dst = ip->daddr;
  pseudo.zero = 0;
  pseudo.proto = IPPROTO_UDP;
  pseudo.len = udp->len;

  uint32_t sum = 0;

  sum += csum16(&pseudo, sizeof(pseudo));
  sum += csum16(udp, sizeof(*udp));
  sum += csum16(payload, payload_len);

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}

static int parse_mac(const char *s, uint8_t mac[ETH_ALEN]) {
  return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &mac[0], &mac[1], &mac[2],
                &mac[3], &mac[4], &mac[5]) == 6;
}

/* ---------- packet builder ---------- */

static size_t build_packet(uint8_t *buf, size_t payload_len,
		           const char *src_addr, const char *dst_addr,
		           uint16_t sport, uint16_t dport) {
  struct iphdr *ip = (struct iphdr *)buf;
  struct udphdr *udp = (struct udphdr *)(buf + sizeof(*ip));
  uint8_t *pl = buf + sizeof(*ip) + sizeof(*udp);

  memset(buf, 0, sizeof(*ip) + sizeof(*udp) + payload_len);
  memset(pl, 0xaa, payload_len);

  /* IP */
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = htons(sizeof(*ip) + sizeof(*udp) + payload_len);
  ip->id = htons(0);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = inet_addr(src_addr);
  ip->daddr = inet_addr(dst_addr);
  ip->check = csum16(ip, sizeof(*ip));

  /* UDP */
  udp->source = htons(sport);
  udp->dest = htons(dport);
  udp->len = htons(sizeof(*udp) + payload_len);
  udp->check = udp_checksum(ip, udp, pl, payload_len);

  return sizeof(*ip) + sizeof(*udp) + payload_len;
}

static int is_l3_interface(const char *ifname) {
  return strncmp(ifname, "wg", 2) == 0 || strncmp(ifname, "xfrm", 4) == 0;
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
  uint8_t rng_state;

  unsigned long seed = mix(clock(), getpid(), time(NULL));
  rng_state = (uint8_t)seed;
  if (rng_state == 0)
    rng_state = 1;

  const char *ifname = NULL;
  unsigned long limit = 0;      /* default: infinite */
  double p_big = 128.0 / 256.0; /* default: 50% */
  uint8_t prob_big = 128;
  char *src_addr = "172.16.100.10";
  char *dst_addr = "192.168.100.10";
  uint8_t dst_mac[ETH_ALEN] = {0};

  int opt;
  while ((opt = getopt(argc, argv, "i:c:p:s:d:m:")) != -1) {
    switch (opt) {
    case 'i':
      ifname = optarg;
      break;
    case 'c':
      limit = strtoul(optarg, NULL, 10);
      break;
    case 'p':
      p_big = strtod(optarg, NULL);
      if (p_big < 0.0 || p_big > 1.0) {
        fprintf(stderr, "-p must be between 0.0 and 1.0\n");
        return 1;
      }
      prob_big = (uint8_t)(p_big * 256.0);
      break;
    case 's':
      src_addr = optarg;
      break;
    case 'd':
      dst_addr = optarg;
      break;
    case 'm':
      if (!parse_mac(optarg, dst_mac)) {
        fprintf(stderr, "invalid MAC address: %s\n", optarg);
        return 1;
      }
      break;

    default:
      fprintf(stderr, "usage: %s -i <ifname> [-c count] [-s src_ip] [-d dst_ip] [-m dst_mac]\n", argv[0]);
      return 1;
    }
  }

  if (!ifname) {
    fprintf(stderr, "-i <ifname> is required\n");
    return 1;
  }

  uint8_t pkt_big[2048];
  uint8_t pkt_small[1024];

  size_t len_big =
      build_packet(pkt_big, 1300 + sizeof(struct iphdr) + sizeof(struct udphdr),
                   src_addr, dst_addr,
                   10000, 10000);

  size_t len_small = build_packet(
      pkt_small, 300 + sizeof(struct iphdr) + sizeof(struct udphdr),
      src_addr, dst_addr,
      20000, 20000);


  /* socket setup */

  int fd = -1;
  int l3 = is_l3_interface(ifname);

  struct sockaddr_ll sll_out = {0};
  struct sockaddr_in sin_out = {0};

  if (!l3) {
    /* ---------- Layer 2 (AF_PACKET) ---------- */
    fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0) {
      perror("socket(AF_PACKET)");
      return 1;
    }

    sll_out.sll_family = AF_PACKET;
    sll_out.sll_protocol = htons(ETH_P_IP);
    sll_out.sll_ifindex = if_nametoindex(ifname);

    if (!sll_out.sll_ifindex) {
      perror("if_nametoindex");
      return 1;
    }

    sll_out.sll_halen = ETH_ALEN;
    memcpy(sll_out.sll_addr, dst_mac, ETH_ALEN);

    /* Optional but fine: bind to device */
    if (bind(fd, (struct sockaddr *)&sll_out, sizeof(sll_out)) < 0) {
      perror("bind(AF_PACKET)");
      return 1;
    }

  } else {
    /* ---------- Layer 3 (raw IP) ---------- */
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
      perror("socket(AF_INET)");
      return 1;
    }

    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
      perror("IP_HDRINCL");
      return 1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) <
        0) {
      perror("SO_BINDTODEVICE");
      return 1;
    }

    sin_out.sin_family = AF_INET;
    sin_out.sin_addr.s_addr = inet_addr(dst_addr);
  }

  /* core loop */

  if (limit == 0) {
    for (;;) {
      uint8_t r = xorshift8(&rng_state);

      if (r < prob_big) {
        if (!l3) {
          if (sendto(fd, pkt_big, len_big, 0, (const struct sockaddr *)&sll_out,
                     sizeof(sll_out)) < 0) {
            perror("send big");
            break;
          }
        } else {
          if (sendto(fd, pkt_big, len_big, 0, (const struct sockaddr *)&sin_out,
                     sizeof(sin_out)) < 0) {
            perror("send big");
            break;
          }
        }
      } else {
        if (!l3) {
          if (sendto(fd, pkt_small, len_small, 0,
                     (const struct sockaddr *)&sll_out, sizeof(sll_out)) < 0) {
            perror("send small");
            break;
          }
        } else {
          if (sendto(fd, pkt_small, len_small, 0,
                     (const struct sockaddr *)&sin_out, sizeof(sin_out)) < 0) {
            perror("send small");
            break;
          }
        }
      }
    }
  }

  for (int64_t i = 0; i < limit; i++) {
    uint8_t r = xorshift8(&rng_state);

    if (r < prob_big) {
      if (!l3) {
        if (sendto(fd, pkt_big, len_big, 0, (const struct sockaddr *)&sll_out,
                   sizeof(sll_out)) < 0) {
          perror("send big");
          break;
        }
      } else {
        if (sendto(fd, pkt_big, len_big, 0, (const struct sockaddr *)&sin_out,
                   sizeof(sin_out)) < 0) {
          perror("send big");
          break;
        }
      }
    } else {
      if (!l3) {
        if (sendto(fd, pkt_small, len_small, 0,
                   (const struct sockaddr *)&sll_out, sizeof(sll_out)) < 0) {
          perror("send small");
          break;
        }
      } else {
        if (sendto(fd, pkt_small, len_small, 0,
                   (const struct sockaddr *)&sin_out, sizeof(sin_out)) < 0) {
          perror("send small");
          break;
        }
      }
    }
  }

  close(fd);
  return 0;
}
