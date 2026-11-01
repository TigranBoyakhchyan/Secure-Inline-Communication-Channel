/*
 * crypto.h - Diffie-Hellman handshake + AES-256-GCM packet protection
 *
 * Simple picture:
 *   handshake()     -> Device1 and Device2 agree on secret keys (Diffie-Hellman)
 *   session_seal()  -> encrypt one TCP payload and append  [tag][counter]
 *   session_open()  -> check the tag, decrypt, and remove  [tag][counter]
 */
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define KEY_LEN   32                 /* AES-256 key = 32 bytes                */
#define SALT_LEN  4                  /* fixed part of the 12-byte nonce       */
#define IV_LEN    12                 /* AES-GCM nonce size                    */
#define TAG_LEN   16                 /* AES-GCM authentication tag            */
#define CTR_LEN   8                  /* 64-bit packet counter (nonce part)    */
#define OVERHEAD  (TAG_LEN + CTR_LEN) /* bytes added to each protected payload */

typedef struct {
    uint8_t  tx_key[KEY_LEN];   /* key for packets WE send to the peer       */
    uint8_t  rx_key[KEY_LEN];   /* key for packets we RECEIVE from the peer  */
    uint8_t  tx_salt[SALT_LEN];
    uint8_t  rx_salt[SALT_LEN];
    uint64_t tx_ctr;            /* +1 for every packet we encrypt            */
    uint64_t rx_highest;        /* highest counter accepted so far           */
    uint64_t rx_window;         /* bitmap of the last 64 counters (replay)   */
} session_t;

/* Run the DH handshake over a small TCP control connection.
 * is_server = 1 -> listen on ip:port (Device2)
 * is_server = 0 -> connect to ip:port (Device1)
 * psk = shared password both devices know (prevents man-in-the-middle). */
int  handshake(session_t *s, int is_server, const char *ip, uint16_t port,
               const char *psk);

/* Encrypt pt_len bytes in place. buf must have room for pt_len + OVERHEAD.
 * Returns the new length (pt_len + OVERHEAD) or -1. */
long session_seal(session_t *s, const uint8_t *aad, size_t aad_len,
                  uint8_t *buf, size_t pt_len);

/* Verify + decrypt in place. Returns plaintext length, or -1 on failure. */
long session_open(session_t *s, const uint8_t *aad, size_t aad_len,
                  uint8_t *buf, size_t len);

void session_wipe(session_t *s);

#endif
