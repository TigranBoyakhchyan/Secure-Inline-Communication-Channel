/*
 * pktutil.c - Internet checksums and AAD construction.
 *
 * The Internet checksum: add the data up as 16-bit numbers, fold the
 * carries back in, then flip all the bits. Routers/hosts recompute it to
 * detect corruption, so after we change a packet we must recompute it.
 */
#include "pktutil.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static uint32_t sum16(uint32_t sum, const uint8_t *p, size_t len)
{
    while (len > 1) {
        sum += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) sum += (uint32_t)(p[0] << 8);    /* odd byte, padded with 0 */
    return sum;
}

static uint16_t fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

void ip_fix_checksum(struct iphdr *ip)
{
    ip->check = 0;
    ip->check = htons(fold(sum16(0, (const uint8_t *)ip, ip->ihl * 4u)));
}

void tcp_fix_checksum(struct iphdr *ip, struct tcphdr *tcp, size_t tcp_len)
{
    uint32_t sum = 0;
    /* pseudo-header: src IP, dst IP, zero, protocol, TCP length */
    sum = sum16(sum, (const uint8_t *)&ip->saddr, 4);
    sum = sum16(sum, (const uint8_t *)&ip->daddr, 4);
    sum += IPPROTO_TCP;
    sum += (uint32_t)tcp_len;

    tcp->check = 0;
    sum = sum16(sum, (const uint8_t *)tcp, tcp_len);
    tcp->check = htons(fold(sum));
}

size_t build_aad(const struct iphdr *ip, const struct tcphdr *tcp,
                 size_t tcp_hdr_len, uint8_t *aad)
{
    memcpy(aad,     &ip->saddr, 4);
    memcpy(aad + 4, &ip->daddr, 4);
    memcpy(aad + 8, tcp, tcp_hdr_len);
    aad[8 + 16] = 0;              /* TCP checksum lives at offset 16-17;  */
    aad[8 + 17] = 0;              /* it changes, so leave it out of AAD   */
    return 8 + tcp_hdr_len;
}
