/*
 * crypto.c - the "security" half of the project.
 *
 * 1. handshake(): Diffie-Hellman (ffdhe2048) between Device1 and Device2,
 *    then HKDF turns the shared DH secret into AES keys.
 * 2. session_seal()/session_open(): AES-256-GCM on one TCP payload.
 *
 * Needs OpenSSL 3 (Kali ships it):  -lcrypto
 */
#include "crypto.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/dh.h>

#define DH_GROUP   "ffdhe2048"   /* standard 2048-bit DH group (RFC 7919) */
#define DH_PUB_LEN 256           /* 2048 bits = 256 bytes                 */

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */
static void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

static uint64_t get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n == 0) return -1;                       /* peer closed */
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

/* Handshake messages are sent as: [2-byte length][bytes] */
static int send_msg(int fd, const uint8_t *buf, size_t len)
{
    uint8_t hdr[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xff) };
    if (write_all(fd, hdr, 2)) return -1;
    return write_all(fd, buf, len);
}

static int recv_msg(int fd, uint8_t *buf, size_t max)
{
    uint8_t hdr[2];
    if (read_all(fd, hdr, 2)) return -1;
    size_t len = ((size_t)hdr[0] << 8) | hdr[1];
    if (len > max) return -1;
    if (read_all(fd, buf, len)) return -1;
    return (int)len;
}

static int tcp_connect_retry(const char *ip, uint16_t port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) return -1;

    for (;;) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) return fd;
        close(fd);
        fprintf(stderr, "[handshake] peer %s:%u not ready, retrying in 1s...\n",
                ip, port);
        sleep(1);
    }
}

static int tcp_accept_one(const char *ip, uint16_t port)
{
    struct sockaddr_in a;
    int one = 1;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) return -1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1 ||
        bind(ls, (struct sockaddr *)&a, sizeof a) < 0 || listen(ls, 1) < 0) {
        close(ls);
        return -1;
    }
    fprintf(stderr, "[handshake] waiting for peer on %s:%u ...\n", ip, port);
    int fd = accept(ls, NULL, NULL);
    close(ls);
    return fd;
}

/* ------------------------------------------------------------------ */
/* Diffie-Hellman pieces                                               */
/* ------------------------------------------------------------------ */

/* Make a brand-new (ephemeral) DH key pair: private x, public g^x mod p */
static EVP_PKEY *dh_generate(void)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                         (char *)DH_GROUP, 0),
        OSSL_PARAM_construct_end()
    };
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
        EVP_PKEY_generate(ctx, &key) <= 0)
        key = NULL;
    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Our public value as exactly 256 big-endian bytes */
static int dh_export_pub(EVP_PKEY *key, uint8_t out[DH_PUB_LEN])
{
    BIGNUM *bn = NULL;
    int ok = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PUB_KEY, &bn) > 0 &&
             BN_bn2binpad(bn, out, DH_PUB_LEN) == DH_PUB_LEN;
    BN_free(bn);
    return ok ? 0 : -1;
}

/* Turn the peer's 256 bytes back into a key object, and sanity-check it */
static EVP_PKEY *dh_import_pub(const uint8_t *pub, size_t len)
{
    EVP_PKEY *peer = NULL;
    BIGNUM *bn = BN_bin2bn(pub, (int)len, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL, *chk = NULL;

    if (!bn || !bld ||
        !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                         DH_GROUP, 0) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bn) ||
        !(params = OSSL_PARAM_BLD_to_param(bld)) ||
        !(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)) ||
        EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(peer);
        peer = NULL;
        goto out;
    }
    /* Reject weak/invalid public values (e.g. 0, 1, p-1) */
    chk = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL);
    if (!chk || EVP_PKEY_public_check(chk) <= 0) {
        fprintf(stderr, "[handshake] peer public key is invalid\n");
        EVP_PKEY_free(peer);
        peer = NULL;
    }
out:
    EVP_PKEY_CTX_free(chk);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn);
    return peer;
}

/* shared secret = peer_pub ^ my_priv mod p  (same value on both sides) */
static int dh_derive(EVP_PKEY *mine, EVP_PKEY *peer,
                     uint8_t *secret, size_t *secret_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, mine, NULL);
    int ok = ctx &&
             EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_CTX_set_dh_pad(ctx, 1) > 0 &&   /* always 256 bytes */
             EVP_PKEY_derive_set_peer(ctx, peer) > 0 &&
             EVP_PKEY_derive(ctx, secret, secret_len) > 0;
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* HKDF-SHA256: stretch/clean the DH secret into several independent keys */
static int hkdf(const uint8_t *ikm, size_t ikm_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    EVP_KDF_free(kdf);
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,  (void *)ikm,  ikm_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len),
        OSSL_PARAM_construct_end()
    };
    int ok = kctx && EVP_KDF_derive(kctx, out, out_len, p) > 0;
    EVP_KDF_CTX_free(kctx);
    return ok ? 0 : -1;
}

/* "Finished" proof = HMAC(k_conf, label || transcript_hash) */
static void finished_mac(const uint8_t *k_conf, const char *label,
                         const uint8_t th[32], uint8_t out[32])
{
    uint8_t data[64];
    size_t l = strlen(label);
    unsigned int outl = 32;
    memcpy(data, label, l);
    memcpy(data + l, th, 32);
    HMAC(EVP_sha256(), k_conf, 32, data, l + 32, out, &outl);
}

/* ------------------------------------------------------------------ */
/* The handshake                                                       */
/* ------------------------------------------------------------------ */
int handshake(session_t *s, int is_server, const char *ip, uint16_t port,
              const char *psk)
{
    int ret = -1, fd = -1, n;
    EVP_PKEY *mine = NULL, *peer = NULL;
    uint8_t my_pub[DH_PUB_LEN], peer_pub[DH_PUB_LEN + 16];
    uint8_t secret[DH_PUB_LEN];
    size_t secret_len = sizeof secret;
    uint8_t th[32];
    uint8_t info[64];
    /* okm = k_c2s(32) | k_s2c(32) | salt_c2s(4) | salt_s2c(4) | k_conf(32) */
    uint8_t okm[2 * KEY_LEN + 2 * SALT_LEN + 32];
    uint8_t my_fin[32], peer_fin[32], exp_fin[32];

    memset(s, 0, sizeof *s);

    /* Step A: open the control connection between the two devices */
    fd = is_server ? tcp_accept_one(ip, port) : tcp_connect_retry(ip, port);
    if (fd < 0) { perror("[handshake] socket"); goto out; }

    /* Step B: make a fresh DH key pair (new one every run => fresh keys) */
    if (!(mine = dh_generate()) || dh_export_pub(mine, my_pub)) {
        fprintf(stderr, "[handshake] DH key generation failed\n");
        goto out;
    }

    /* Step C: swap public values. Client (Device1) speaks first. */
    if (!is_server && send_msg(fd, my_pub, DH_PUB_LEN)) goto io_err;
    n = recv_msg(fd, peer_pub, sizeof peer_pub);
    if (n != DH_PUB_LEN) goto io_err;
    if (is_server && send_msg(fd, my_pub, DH_PUB_LEN)) goto io_err;

    /* Step D: compute the shared secret */
    if (!(peer = dh_import_pub(peer_pub, DH_PUB_LEN)) ||
        dh_derive(mine, peer, secret, &secret_len)) {
        fprintf(stderr, "[handshake] DH derivation failed\n");
        goto out;
    }

    /* Step E: transcript hash = SHA256(client_pub || server_pub) */
    {
        const uint8_t *cpub = is_server ? peer_pub : my_pub;
        const uint8_t *spub = is_server ? my_pub   : peer_pub;
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        int ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) &&
                 EVP_DigestUpdate(md, cpub, DH_PUB_LEN) &&
                 EVP_DigestUpdate(md, spub, DH_PUB_LEN) &&
                 EVP_DigestFinal_ex(md, th, NULL);
        EVP_MD_CTX_free(md);
        if (!ok) goto out;
    }

    /* Step F: HKDF(secret, salt = PSK, info = label || transcript) -> keys */
    memcpy(info, "secgw-v1 keys", 13);
    memcpy(info + 13, th, 32);
    if (hkdf(secret, secret_len, (const uint8_t *)psk, strlen(psk),
             info, 13 + 32, okm, sizeof okm)) {
        fprintf(stderr, "[handshake] HKDF failed\n");
        goto out;
    }
    {
        const uint8_t *k_c2s = okm, *k_s2c = okm + 32;
        const uint8_t *salt_c2s = okm + 64, *salt_s2c = okm + 68;
        /* Separate keys per direction => the two devices can never
         * produce the same (key, nonce) pair. */
        memcpy(s->tx_key,  is_server ? k_s2c : k_c2s, KEY_LEN);
        memcpy(s->rx_key,  is_server ? k_c2s : k_s2c, KEY_LEN);
        memcpy(s->tx_salt, is_server ? salt_s2c : salt_c2s, SALT_LEN);
        memcpy(s->rx_salt, is_server ? salt_c2s : salt_s2c, SALT_LEN);
    }

    /* Step G: key confirmation - prove we both got the same keys
     * (fails if the PSK differs or someone tampered with the exchange) */
    {
        const uint8_t *k_conf = okm + 72;
        if (!is_server) {
            finished_mac(k_conf, "client finished", th, my_fin);
            if (send_msg(fd, my_fin, 32)) goto io_err;
            if (recv_msg(fd, peer_fin, 32) != 32) goto confirm_err;
            finished_mac(k_conf, "server finished", th, exp_fin);
            if (CRYPTO_memcmp(peer_fin, exp_fin, 32)) goto confirm_err;
        } else {
            if (recv_msg(fd, peer_fin, 32) != 32) goto io_err;
            finished_mac(k_conf, "client finished", th, exp_fin);
            if (CRYPTO_memcmp(peer_fin, exp_fin, 32)) goto confirm_err;
            finished_mac(k_conf, "server finished", th, my_fin);
            if (send_msg(fd, my_fin, 32)) goto io_err;
        }
    }

    s->tx_ctr = 0;          /* first packet will use counter 1 */
    s->rx_highest = 0;
    s->rx_window = 0;
    fprintf(stderr, "[handshake] DH (%s) complete, keys confirmed.\n", DH_GROUP);
    ret = 0;
    goto out;

io_err:
    fprintf(stderr, "[handshake] connection error during handshake\n");
    goto out;
confirm_err:
    fprintf(stderr, "[handshake] key confirmation FAILED "
                    "(different PSK on the two devices, or an attacker?)\n");
out:
    OPENSSL_cleanse(secret, sizeof secret);
    OPENSSL_cleanse(okm, sizeof okm);
    EVP_PKEY_free(mine);
    EVP_PKEY_free(peer);
    if (fd >= 0) close(fd);
    if (ret != 0) session_wipe(s);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Replay protection (64-packet sliding window, like IPsec)            */
/* ------------------------------------------------------------------ */
static int replay_ok(const session_t *s, uint64_t ctr)
{
    if (ctr == 0) return 0;
    if (ctr > s->rx_highest) return 1;                 /* new, higher: OK */
    uint64_t diff = s->rx_highest - ctr;
    if (diff >= 64) return 0;                          /* too old         */
    return !(s->rx_window & (1ULL << diff));           /* seen already?   */
}

static void replay_mark(session_t *s, uint64_t ctr)
{
    if (ctr > s->rx_highest) {
        uint64_t shift = ctr - s->rx_highest;
        s->rx_window = (shift >= 64) ? 0 : (s->rx_window << shift);
        s->rx_window |= 1;
        s->rx_highest = ctr;
    } else {
        s->rx_window |= 1ULL << (s->rx_highest - ctr);
    }
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM                                                         */
/* ------------------------------------------------------------------ */
/* Output layout:  [ciphertext (same size as plaintext)][tag 16][counter 8] */
long session_seal(session_t *s, const uint8_t *aad, size_t aad_len,
                  uint8_t *buf, size_t pt_len)
{
    uint8_t iv[IV_LEN];
    int len, ok = 0;

    /* Never reuse a nonce: if the counter would wrap, refuse (re-handshake) */
    if (s->tx_ctr == UINT64_MAX) return -1;
    uint64_t ctr = ++s->tx_ctr;

    /* nonce = salt (4 bytes, secret, per direction) || counter (8 bytes) */
    memcpy(iv, s->tx_salt, SALT_LEN);
    put_be64(iv + SALT_LEN, ctr);

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c &&
        EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, s->tx_key, iv) > 0 &&
        EVP_EncryptUpdate(c, NULL, &len, aad, (int)aad_len) > 0 &&   /* AAD  */
        EVP_EncryptUpdate(c, buf, &len, buf, (int)pt_len) > 0 &&     /* data */
        EVP_EncryptFinal_ex(c, buf + len, &len) > 0 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, buf + pt_len) > 0)
        ok = 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return -1;

    put_be64(buf + pt_len + TAG_LEN, ctr);   /* receiver needs the counter */
    return (long)(pt_len + OVERHEAD);
}

long session_open(session_t *s, const uint8_t *aad, size_t aad_len,
                  uint8_t *buf, size_t len)
{
    uint8_t iv[IV_LEN], tag[TAG_LEN];
    int outl, ok = 0;

    if (len <= OVERHEAD) return -1;
    size_t ct_len = len - OVERHEAD;
    uint64_t ctr  = get_be64(buf + ct_len + TAG_LEN);
    memcpy(tag, buf + ct_len, TAG_LEN);

    if (!replay_ok(s, ctr)) return -1;            /* replayed / too old */

    memcpy(iv, s->rx_salt, SALT_LEN);
    put_be64(iv + SALT_LEN, ctr);

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c &&
        EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, s->rx_key, iv) > 0 &&
        EVP_DecryptUpdate(c, NULL, &outl, aad, (int)aad_len) > 0 &&
        EVP_DecryptUpdate(c, buf, &outl, buf, (int)ct_len) > 0 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) > 0 &&
        EVP_DecryptFinal_ex(c, buf + outl, &outl) > 0)   /* <- tag check */
        ok = 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return -1;                            /* tampered / wrong key */

    replay_mark(s, ctr);
    return (long)ct_len;
}

void session_wipe(session_t *s)
{
    OPENSSL_cleanse(s, sizeof *s);
}
