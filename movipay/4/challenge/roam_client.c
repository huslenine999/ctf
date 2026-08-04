/*
 * MoviPay roaming reference client.
 *
 * The normal client authenticates as EVU-1001 and starts settlement for the
 * same account. Reversing the static configuration and packet code reveals the
 * key material and TLV protocol, but not the server-side rebinding bug.
 */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sha256.h"

#define SERVER_PORT 31336

#define TYPE_HELLO     0x01
#define TYPE_CHALLENGE 0x02
#define TYPE_AUTH      0x03
#define TYPE_START     0x04
#define TYPE_SETTLE    0x05
#define TYPE_RESPONSE  0x06

#define TAG_CLIENT_ID  0x01
#define TAG_NONCE      0x02
#define TAG_HMAC       0x03
#define TAG_ACCOUNT_ID 0x04

static volatile unsigned char encrypted_identity[] = {
    0x67, 0x74, 0x77, 0x0f, 0x13, 0x12, 0x12, 0x13
};

static volatile unsigned char encrypted_key[] = {
    0x10, 0x0d, 0x03, 0x0f, 0x1d, 0x09, 0x07, 0x1b,
    0x1d, 0x11, 0x07, 0x01, 0x10, 0x07, 0x16
};

struct session {
    int sock;
    char identity[32];
    char account[32];
    unsigned char key[32];
    unsigned char nonce[32];
    int nonce_len;
};

__attribute__((noinline))
static void decode_identity(char *out) {
    size_t n = sizeof(encrypted_identity);
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)(encrypted_identity[i] ^ 0x22);
    }
    out[n] = 0;
}

__attribute__((noinline))
static void recover_key(unsigned char *out) {
    size_t n = sizeof(encrypted_key);
    for (size_t i = 0; i < n; i++) {
        out[i] = encrypted_key[i] ^ 0x42;
    }
}

static int tlv_add(unsigned char *buf, int off, uint8_t tag, const void *data, uint8_t len) {
    buf[off++] = tag;
    buf[off++] = len;
    memcpy(buf + off, data, len);
    return off + len;
}

static int send_frame(int sock, uint8_t type, const unsigned char *payload, uint16_t len) {
    unsigned char frame[2048];
    uint16_t be_len = htons(len);
    frame[0] = 'M';
    frame[1] = 'V';
    frame[2] = 1;
    frame[3] = type;
    memcpy(frame + 4, &be_len, 2);
    memcpy(frame + 6, payload, len);
    return (int)send(sock, frame, len + 6, 0);
}

static int recv_frame(int sock, uint8_t *type, unsigned char *payload, uint16_t *len) {
    unsigned char header[6];
    if (recv(sock, header, sizeof(header), MSG_WAITALL) != sizeof(header)) {
        return -1;
    }
    if (header[0] != 'M' || header[1] != 'V' || header[2] != 1) {
        return -1;
    }
    *type = header[3];
    memcpy(len, header + 4, 2);
    *len = ntohs(*len);
    if (*len > 1024) {
        return -1;
    }
    if (recv(sock, payload, *len, MSG_WAITALL) != *len) {
        return -1;
    }
    return 0;
}

static void make_auth(struct session *s, unsigned char out[8]) {
    unsigned char msg[128];
    unsigned char digest[32];
    int id_len = (int)strlen(s->identity);
    memcpy(msg, s->identity, id_len);
    memcpy(msg + id_len, s->nonce, s->nonce_len);
    hmac_sha256(s->key, 15, msg, id_len + s->nonce_len, digest);
    memcpy(out, digest, 8);
}

static int run_protocol(struct session *s) {
    unsigned char payload[1024];
    uint8_t type = 0;
    uint16_t len = 0;

    len = (uint16_t)tlv_add(payload, 0, TAG_CLIENT_ID, s->identity, strlen(s->identity));
    send_frame(s->sock, TYPE_HELLO, payload, len);

    if (recv_frame(s->sock, &type, payload, &len) < 0 || type != TYPE_CHALLENGE) {
        return 1;
    }
    for (uint16_t i = 0; i + 2 <= len;) {
        uint8_t tag = payload[i];
        uint8_t tl = payload[i + 1];
        if (tag == TAG_NONCE) {
            memcpy(s->nonce, payload + i + 2, tl);
            s->nonce_len = tl;
        }
        i += (uint16_t)(2 + tl);
    }

    unsigned char sig[8];
    make_auth(s, sig);
    len = (uint16_t)tlv_add(payload, 0, TAG_HMAC, sig, sizeof(sig));
    send_frame(s->sock, TYPE_AUTH, payload, len);
    if (recv_frame(s->sock, &type, payload, &len) < 0 || type != TYPE_RESPONSE) {
        return 1;
    }

    len = (uint16_t)tlv_add(payload, 0, TAG_ACCOUNT_ID, s->account, strlen(s->account));
    send_frame(s->sock, TYPE_START, payload, len);
    if (recv_frame(s->sock, &type, payload, &len) < 0 || type != TYPE_RESPONSE) {
        return 1;
    }

    send_frame(s->sock, TYPE_SETTLE, payload, 0);
    if (recv_frame(s->sock, &type, payload, &len) < 0 || type != TYPE_RESPONSE) {
        return 1;
    }
    printf("%.*s\n", len, payload);
    return 0;
}

int main(int argc, char **argv) {
    struct session s;
    struct sockaddr_in addr;
    const char *host = "127.0.0.1";
    int port = SERVER_PORT;
    memset(&s, 0, sizeof(s));

    if (argc > 3) {
        fprintf(stderr, "usage: %s [HOST] [PORT]\n", argv[0]);
        return 1;
    }
    if (argc >= 2) {
        host = argv[1];
    }
    if (argc == 3) {
        port = atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "bad port: %s\n", argv[2]);
            return 1;
        }
    }

    decode_identity(s.identity);
    recover_key(s.key);
    strcpy(s.account, s.identity);

    s.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s.sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "bad IPv4 host: %s\n", host);
        close(s.sock);
        return 1;
    }

    if (connect(s.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(s.sock);
        return 1;
    }

    int rc = run_protocol(&s);
    close(s.sock);
    return rc;
}
