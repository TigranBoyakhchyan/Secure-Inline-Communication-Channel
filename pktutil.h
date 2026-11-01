/*
 * pktutil.h - helpers for IPv4/TCP headers (checksums, AAD)
 */
#ifndef PKTUTIL_H
#define PKTUTIL_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* Recalculate the IPv4 header checksum */
void   ip_fix_checksum(struct iphdr *ip);

/* Recalculate the TCP checksum (pseudo-header + TCP header + payload).
 * tcp_len = TCP header + payload length in bytes. */
void   tcp_fix_checksum(struct iphdr *ip, struct tcphdr *tcp, size_t tcp_len);

/* Build the "additional authenticated data" (AAD) for AES-GCM:
 * src IP | dst IP | TCP header (with checksum field zeroed).
 * aad must have room for 8 + 60 bytes. Returns AAD length. */
size_t build_aad(const struct iphdr *ip, const struct tcphdr *tcp,
                 size_t tcp_hdr_len, uint8_t *aad);

#endif
