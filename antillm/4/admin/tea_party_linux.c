typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long usize;

#define FLAG_LEN 32

static const u32 key[4] = {
    0x13371337u, 0x9e3779b9u, 0x41414141u, 0xdeadbeefu
};

static const u32 expected[8] = {
    0x0b47fdf5u, 0xefa4b3ffu, 0x9ef010bbu, 0x7404ab9au,
    0xa1ab3dd2u, 0x78dcc22bu, 0x4b76b54au, 0xe9addf9bu
};

static const u32 decoy_words[2048] = {
#define DROW(x) \
    (0x9e3779b9u ^ ((x) * 0x45d9f3bu)), \
    (0x7f4a7c15u + ((x) * 0x27d4eb2du)), \
    (0x94d049bbu ^ ((x) * 0x165667b1u)), \
    (0xd1b54a35u + ((x) * 0x85ebca6bu)), \
    (0x632be59bu ^ ((x) * 0xc2b2ae35u)), \
    (0xa24baed5u + ((x) * 0x9e3779b1u)), \
    (0x13c6ef37u ^ ((x) * 0x7feb352du)), \
    (0xcafef00du + ((x) * 0x846ca68bu))
#define D64(o) \
    DROW((o)+0), DROW((o)+1), DROW((o)+2), DROW((o)+3), \
    DROW((o)+4), DROW((o)+5), DROW((o)+6), DROW((o)+7), \
    DROW((o)+8), DROW((o)+9), DROW((o)+10), DROW((o)+11), \
    DROW((o)+12), DROW((o)+13), DROW((o)+14), DROW((o)+15), \
    DROW((o)+16), DROW((o)+17), DROW((o)+18), DROW((o)+19), \
    DROW((o)+20), DROW((o)+21), DROW((o)+22), DROW((o)+23), \
    DROW((o)+24), DROW((o)+25), DROW((o)+26), DROW((o)+27), \
    DROW((o)+28), DROW((o)+29), DROW((o)+30), DROW((o)+31), \
    DROW((o)+32), DROW((o)+33), DROW((o)+34), DROW((o)+35), \
    DROW((o)+36), DROW((o)+37), DROW((o)+38), DROW((o)+39), \
    DROW((o)+40), DROW((o)+41), DROW((o)+42), DROW((o)+43), \
    DROW((o)+44), DROW((o)+45), DROW((o)+46), DROW((o)+47), \
    DROW((o)+48), DROW((o)+49), DROW((o)+50), DROW((o)+51), \
    DROW((o)+52), DROW((o)+53), DROW((o)+54), DROW((o)+55), \
    DROW((o)+56), DROW((o)+57), DROW((o)+58), DROW((o)+59), \
    DROW((o)+60), DROW((o)+61), DROW((o)+62), DROW((o)+63)
    D64(0), D64(64), D64(128), D64(192)
#undef D64
#undef DROW
};

static volatile u32 decoy_state = 0x6d2b79f5u;

static long sys_write(long fd, const void *buf, unsigned long len)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(1), "D"(fd), "S"(buf), "d"(len)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void sys_exit(long code)
{
    __asm__ volatile (
        "syscall"
        :
        : "a"(60), "D"(code)
        : "rcx", "r11", "memory"
    );

    for (;;) {}
}

static usize c_strlen(const char *s)
{
    usize n = 0;
    while (s[n] != 0) {
        n++;
    }
    return n;
}

static u32 load32_le(const u8 *p)
{
    return ((u32)p[0]) |
           ((u32)p[1] << 8) |
           ((u32)p[2] << 16) |
           ((u32)p[3] << 24);
}

__attribute__((noinline, used))
static u32 rotate_noise(u32 x, u32 n)
{
    n &= 31u;
    return (x << n) | (x >> ((32u - n) & 31u));
}

__attribute__((noinline, used))
static u32 admission_noise(const u8 *input, usize n)
{
    u32 x = 0x31415926u ^ (u32)n;

    for (usize i = 0; i < sizeof(decoy_words) / sizeof(decoy_words[0]); i++) {
        u32 w = decoy_words[i];
        u32 c = n ? input[(i * 7u + w) % n] : (u8)i;

        x ^= rotate_noise(w + c + (u32)i, (u32)(i + c));
        x += (x << 3) ^ (x >> 11) ^ 0xa5a5a5a5u;
    }

    decoy_state ^= x;
    return x;
}

__attribute__((noinline, used))
static int opaque_allow(const u8 *input, usize n)
{
    u32 x = admission_noise(input, n);
    u32 y = x ^ decoy_state;

    if (y == 0x13579bdfu) {
        decoy_state ^= (u32)n | 1u;
    }

    return 1;
}

static void tea_encrypt(u32 *v0, u32 *v1)
{
    u32 a = *v0;
    u32 b = *v1;
    u32 sum = 0;
    const u32 delta = 0x9e3779b9u;

    for (int round = 0; round < 32; round++) {
        sum += delta;
        a += (((b << 4) + key[0]) ^ (b + sum)) + ((b >> 5) + key[1]);
        b += (((a << 4) + key[2]) ^ (a + sum)) + ((a >> 5) + key[3]);
    }

    *v0 = a;
    *v1 = b;
}

static int check_license(const u8 *input)
{
    usize n = c_strlen((const char *)input);

    if (!opaque_allow(input, n)) {
        return 0;
    }

    if (n != FLAG_LEN) {
        return 0;
    }

    for (int block = 0; block < FLAG_LEN / 8; block++) {
        u32 a = load32_le(input + block * 8);
        u32 b = load32_le(input + block * 8 + 4);

        tea_encrypt(&a, &b);

        if (a != expected[block * 2] || b != expected[block * 2 + 1]) {
            return 0;
        }
    }

    return 1;
}

__attribute__((used))
void c_start(unsigned long *sp)
{
    long argc = (long)sp[0];
    char **argv = (char **)(sp + 1);

    if (argc != 2) {
        sys_write(1, "usage: ./tea_party <license>\n", 29);
        sys_exit(1);
    }

    if (check_license((const u8 *)argv[1])) {
        sys_write(1, "accepted\n", 9);
        sys_exit(0);
    }

    sys_write(1, "rejected\n", 9);
    sys_exit(1);
}

__attribute__((naked))
void _start(void)
{
    __asm__ volatile (
        "mov %rsp, %rdi\n"
        "call c_start\n"
    );
}
