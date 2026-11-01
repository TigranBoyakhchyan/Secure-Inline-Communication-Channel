/*
 * secgw.c - "secure gateway" that runs on Device1 and Device2.
 *
 *   PC1 ---> [Device1] =====encrypted=====> [Device2] ---> PC2
 *        lan0        wan0               wan0        lan0
 *
 * How it works:
 *   1. Do the Diffie-Hellman handshake with the other device.
 *   2. Ask the Linux kernel (via NFQUEUE) to hand us the selected TCP packets.
 *   3. For each packet:
 *        came in on the LAN side  -> encrypt payload, append tag+counter
 *        came in on the WAN side  -> verify tag, decrypt, strip tag+counter
 *      then fix IP total length + IP checksum + TCP checksum, and send it on.
 *
 * Build: make     Run: see README.md
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netfilter.h>                 /* NF_ACCEPT, NF_DROP */
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "crypto.h"
#include "pktutil.h"

#define MAX_IP_LEN 65535

static session_t     g_sess;
static unsigned int  g_lan_ifindex;
static int           g_verbose;
static volatile sig_atomic_t g_stop;
static uint8_t       g_out[MAX_IP_LEN + OVERHEAD];   /* modified packet  */
static uint8_t       g_rxbuf[MAX_IP_LEN + 4096];     /* netlink messages */
static unsigned long g_enc, g_dec, g_fail, g_pass;

enum { V_ACCEPT_ORIG, V_ACCEPT_NEW, V_DROP };

static void log_pkt(const char *tag, const struct iphdr *ip,
                    const struct tcphdr *tcp, size_t in_len, size_t out_len)
{
    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, s, sizeof s);
    inet_ntop(AF_INET, &ip->daddr, d, sizeof d);
    printf("%s %s:%u -> %s:%u  payload %zu -> %zu bytes\n", tag,
           s, ntohs(tcp->source), d, ntohs(tcp->dest), in_len, out_len);
    fflush(stdout);
}

/* Returns what to do with the packet. If V_ACCEPT_NEW, the new packet is
 * in g_out and its length in *newlen. */
static int process(const uint8_t *pkt, size_t len, int encrypt, size_t *newlen)
{
    if (len < sizeof(struct iphdr) || len > MAX_IP_LEN) return V_DROP;
    memcpy(g_out, pkt, len);

    /* ---- 1. Parse the IPv4 header ---- */
    struct iphdr *ip = (struct iphdr *)g_out;
    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) return V_ACCEPT_ORIG;
    size_t ihl = ip->ihl * 4u;
    size_t tot = ntohs(ip->tot_len);
    if (ihl < 20 || tot > len || tot < ihl + 20) return V_DROP;
    if (ntohs(ip->frag_off) & (IP_MF | IP_OFFMASK)) {
        fprintf(stderr, "[!] IP fragment - not supported, dropped\n");
        return V_DROP;
    }

    /* ---- 2. Parse the TCP header ---- */
    struct tcphdr *tcp = (struct tcphdr *)(g_out + ihl);
    size_t thl = tcp->doff * 4u;
    if (thl < 20 || ihl + thl > tot) return V_DROP;

    size_t hdrs = ihl + thl;          /* IP header + TCP header (unchanged) */
    size_t plen = tot - hdrs;         /* TCP payload length                 */
    if (plen == 0) {                  /* SYN / ACK / FIN with no data:      */
        g_pass++;                     /* nothing to encrypt, pass as is     */
        return V_ACCEPT_ORIG;
    }

    /* ---- 3. Bind the payload to its headers (AAD) ---- */
    uint8_t aad[8 + 60];
    size_t aad_len = build_aad(ip, tcp, thl, aad);

    /* ---- 4. Encrypt or decrypt ONLY the payload ---- */
    long n;
    if (encrypt) {
        if (tot + OVERHEAD > MAX_IP_LEN) return V_DROP;
        n = session_seal(&g_sess, aad, aad_len, g_out + hdrs, plen);
        if (n < 0) {
            fprintf(stderr, "[!] encryption failed (counter exhausted?)\n");
            return V_DROP;
        }
        g_enc++;
    } else {
        n = session_open(&g_sess, aad, aad_len, g_out + hdrs, plen);
        if (n < 0) {
            g_fail++;
            log_pkt("[DROP: bad tag/replay]", ip, tcp, plen, 0);
            return V_DROP;
        }
        g_dec++;
    }

    /* ---- 5. Fix the headers: new length + both checksums ---- */
    size_t newtot = hdrs + (size_t)n;
    ip->tot_len = htons((uint16_t)newtot);
    ip_fix_checksum(ip);
    tcp_fix_checksum(ip, tcp, newtot - ihl);

    if (g_verbose)
        log_pkt(encrypt ? "[ENC]" : "[DEC]", ip, tcp, plen, (size_t)n);

    *newlen = newtot;
    return V_ACCEPT_NEW;
}

/* Called by libnetfilter_queue for every queued packet */
static int on_packet(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                     struct nfq_data *nfa, void *data)
{
    (void)msg; (void)data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    unsigned char *pkt;
    int len = nfq_get_payload(nfa, &pkt);
    if (len < 0) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

    /* Direction: arrived from our LAN (a PC) => encrypt, else => decrypt */
    int encrypt = (nfq_get_indev(nfa) == g_lan_ifindex);
    size_t newlen = 0;

    switch (process(pkt, (size_t)len, encrypt, &newlen)) {
    case V_ACCEPT_NEW:
        return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)newlen, g_out);
    case V_ACCEPT_ORIG:
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    default:
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void usage(const char *p)
{
    fprintf(stderr,
        "Usage: %s -r client|server -a ADDR -l LAN_IFACE -k PSK [options]\n"
        "  -r  role: 'client' on Device1, 'server' on Device2\n"
        "  -a  server: IP to listen on; client: Device2's IP to connect to\n"
        "  -P  handshake TCP port (default 7000)\n"
        "  -l  interface facing the local PC (e.g. lan0)\n"
        "  -q  NFQUEUE number (default 0)\n"
        "  -k  pre-shared key (same on both devices, >= 8 chars)\n"
        "  -v  print every processed packet\n", p);
    exit(1);
}

int main(int argc, char **argv)
{
    const char *role = NULL, *addr = NULL, *lan = NULL, *psk = NULL;
    uint16_t port = 7000, qnum = 0;
    int opt;

    while ((opt = getopt(argc, argv, "r:a:P:l:q:k:vh")) != -1) {
        switch (opt) {
        case 'r': role = optarg; break;
        case 'a': addr = optarg; break;
        case 'P': port = (uint16_t)atoi(optarg); break;
        case 'l': lan  = optarg; break;
        case 'q': qnum = (uint16_t)atoi(optarg); break;
        case 'k': psk  = optarg; break;
        case 'v': g_verbose = 1; break;
        default:  usage(argv[0]);
        }
    }
    if (!role || !addr || !lan || !psk) usage(argv[0]);
    int is_server = !strcmp(role, "server");
    if (!is_server && strcmp(role, "client")) usage(argv[0]);
    if (strlen(psk) < 8) { fprintf(stderr, "PSK too short\n"); return 1; }
    if (!(g_lan_ifindex = if_nametoindex(lan))) {
        fprintf(stderr, "Unknown interface '%s'\n", lan);
        return 1;
    }

    /* ---------- Phase 1: secure session (DH handshake) ---------- */
    printf("[*] %s: starting Diffie-Hellman handshake...\n",
           is_server ? "Device2" : "Device1");
    if (handshake(&g_sess, is_server, addr, port, psk) != 0) {
        fprintf(stderr, "[x] Handshake failed - no traffic will pass.\n");
        return 1;
    }
    printf("[+] Secure session established. Protected traffic may flow now.\n");

    /* ---------- Phase 2: attach to the kernel packet queue ---------- */
    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); return 1; }
    struct nfq_q_handle *qh = nfq_create_queue(h, qnum, &on_packet, NULL);
    if (!qh) { perror("nfq_create_queue (is another program using it?)"); return 1; }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode"); return 1;
    }
    nfq_set_queue_maxlen(qh, 4096);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;          /* no SA_RESTART: recv() returns */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    printf("[*] Listening on NFQUEUE %u (LAN iface %s). Ctrl+C to stop.\n",
           qnum, lan);
    int fd = nfq_fd(h);
    while (!g_stop) {
        int rv = (int)recv(fd, g_rxbuf, sizeof g_rxbuf, 0);
        if (rv >= 0) { nfq_handle_packet(h, (char *)g_rxbuf, rv); continue; }
        if (errno == EINTR) continue;
        if (errno == ENOBUFS) { fprintf(stderr, "[!] queue overrun\n"); continue; }
        perror("recv");
        break;
    }

    printf("\n[*] Stats: encrypted=%lu decrypted=%lu rejected=%lu "
           "passed(no payload)=%lu\n", g_enc, g_dec, g_fail, g_pass);
    nfq_destroy_queue(qh);
    nfq_close(h);
    session_wipe(&g_sess);
    return 0;
}
