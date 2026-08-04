#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FLAG_LEN 32

static const uint32_t key[4] = {
    0x13371337, 0x9e3779b9, 0x41414141, 0xdeadbeef
};

static const uint32_t expected[8] = {
    0x0b47fdf5, 0xefa4b3ff, 0x9ef010bb, 0x7404ab9a,
    0xa1ab3dd2, 0x78dcc22b, 0x4b76b54a, 0xe9addf9b
};

static uint32_t load32_le(const unsigned char *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void tea_encrypt(uint32_t *v0, uint32_t *v1)
{
    uint32_t a = *v0;
    uint32_t b = *v1;
    uint32_t sum = 0;
    const uint32_t delta = 0x9e3779b9;

    for (int round = 0; round < 32; round++) {
        sum += delta;

        a += (((b << 4) + key[0]) ^ (b + sum)) + ((b >> 5) + key[1]);
        b += (((a << 4) + key[2]) ^ (a + sum)) + ((a >> 5) + key[3]);
    }

    *v0 = a;
    *v1 = b;
}

static int check_license(const unsigned char *input)
{
    if (strlen((const char *)input) != FLAG_LEN) {
        return 0;
    }

    for (int block = 0; block < FLAG_LEN / 8; block++) {
        uint32_t a = load32_le(input + block * 8);
        uint32_t b = load32_le(input + block * 8 + 4);

        tea_encrypt(&a, &b);

        if (a != expected[block * 2] || b != expected[block * 2 + 1]) {
            return 0;
        }
    }

    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        puts("usage: ./tea_party <license>");
        return 1;
    }

    if (check_license((const unsigned char *)argv[1])) {
        puts("accepted");
        return 0;
    }

    puts("rejected");
    return 1;
}
