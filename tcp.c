#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "tcp.h"

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

struct pseudo_hdr
{
    uint32_t src; // source address
    uint32_t dst; // destination address
    uint8_t zero; // zero
    uint8_t protocol;
    uint16_t len; // tcp length
};

struct tcp_hdr
{
    uint16_t src; // source port
    uint16_t dst; // destination port
    uint32_t seq; // sequence number
    uint32_t ack; // acknowledgement number
    uint8_t off;  // data offset
    uint8_t flg;  // flags
    uint16_t wnd; // windos
    uint16_t sum; // checksum
    uint16_t up;  // urgent pointer
};

static char *tcp_flg_ntoa(uint8_t flg)
{
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
             TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}

static void tcp_dump(const uint8_t *data, size_t len)
{
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, "\tsrc: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "\tdst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "\tseq: %u\n", ntoh16(hdr->seq));
    fprintf(stderr, "\tack: %u\n", ntoh16(hdr->ack));
    fprintf(stderr, "\toff: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "\tflg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, "\twnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "\tsum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "\tup:%u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    if (len < sizeof(*hdr))
    {
        errorf("too short");
        return;
    }

    hdr = (struct tcp_hdr *)data;
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0)
    {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }

    if (src == IP_ADDR_BROADCAST || dst == IP_ADDR_BROADCAST)
    {
        errorf("src/dst address must not be BROADCAST address(255.255.255.255)");
        return;
    }

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));

    tcp_dump(data, len);
    return;
}

int tcp_init(void)
{
    return ip_protocol_register(IP_PROTOCOL_TCP, tcp_input);
}