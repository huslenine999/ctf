typedef unsigned char u8;
typedef unsigned long usize;

#define FLAG_LEN 32

#define OP_LEN 0x10
#define OP_LOAD 0x22
#define OP_ADD_POS 0x35
#define OP_XOR 0x46
#define OP_ROL_POS 0x57
#define OP_CMP 0x68
#define OP_NEXT 0x79
#define OP_HALT 0x8a

typedef struct {
    const u8 *input;
    u8 pos;
    u8 acc;
    u8 ok;
} Vm;

static const u8 expected[FLAG_LEN] = {
    0xf1,0x85,0x0b,0xe6,0x81,0x8d,0x1d,0xb8,0x57,0xba,0xfe,0xc5,0xf9,0xbc,0xf1,0xea,
    0xc8,0x44,0xc0,0x70,0xa1,0x8e,0x1f,0xa0,0xab,0x79,0x22,0xc4,0x3e,0x35,0x2e,0x95
};

static const u8 bytecode[] = {
    OP_LEN, FLAG_LEN,
    OP_LOAD,
    OP_ADD_POS,
    OP_XOR, 0xa7,
    OP_ROL_POS,
    OP_CMP,
    OP_NEXT,
    OP_HALT
};

static const unsigned int dispatch_noise[2048] = {
#define VROW(x) \
    (0x243f6a88u + ((x) * 0x9e3779b9u)), \
    (0x85a308d3u ^ ((x) * 0x7f4a7c15u)), \
    (0x13198a2eu + ((x) * 0x94d049bbu)), \
    (0x03707344u ^ ((x) * 0x27d4eb2du)), \
    (0xa4093822u + ((x) * 0x165667b1u)), \
    (0x299f31d0u ^ ((x) * 0x85ebca6bu)), \
    (0x082efa98u + ((x) * 0xc2b2ae35u)), \
    (0xec4e6c89u ^ ((x) * 0x9e3779b1u))
#define V64(o) \
    VROW((o)+0), VROW((o)+1), VROW((o)+2), VROW((o)+3), \
    VROW((o)+4), VROW((o)+5), VROW((o)+6), VROW((o)+7), \
    VROW((o)+8), VROW((o)+9), VROW((o)+10), VROW((o)+11), \
    VROW((o)+12), VROW((o)+13), VROW((o)+14), VROW((o)+15), \
    VROW((o)+16), VROW((o)+17), VROW((o)+18), VROW((o)+19), \
    VROW((o)+20), VROW((o)+21), VROW((o)+22), VROW((o)+23), \
    VROW((o)+24), VROW((o)+25), VROW((o)+26), VROW((o)+27), \
    VROW((o)+28), VROW((o)+29), VROW((o)+30), VROW((o)+31), \
    VROW((o)+32), VROW((o)+33), VROW((o)+34), VROW((o)+35), \
    VROW((o)+36), VROW((o)+37), VROW((o)+38), VROW((o)+39), \
    VROW((o)+40), VROW((o)+41), VROW((o)+42), VROW((o)+43), \
    VROW((o)+44), VROW((o)+45), VROW((o)+46), VROW((o)+47), \
    VROW((o)+48), VROW((o)+49), VROW((o)+50), VROW((o)+51), \
    VROW((o)+52), VROW((o)+53), VROW((o)+54), VROW((o)+55), \
    VROW((o)+56), VROW((o)+57), VROW((o)+58), VROW((o)+59), \
    VROW((o)+60), VROW((o)+61), VROW((o)+62), VROW((o)+63)
    V64(0), V64(64), V64(128), V64(192)
#undef V64
#undef VROW
};

static volatile unsigned int vm_noise_state = 0x8badf00du;

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

static void c_memzero(void *ptr, usize size)
{
    u8 *p = (u8 *)ptr;
    for (usize i = 0; i < size; i++) {
        p[i] = 0;
    }
}

static u8 rol8(u8 x, u8 n)
{
    n &= 7;
    if (n == 0) {
        return x;
    }

    return (u8)((x << n) | (x >> (8 - n)));
}

__attribute__((noinline, used))
static unsigned int fold_noise(const u8 *input, usize n)
{
    unsigned int x = 0xfeed1234u + (unsigned int)n;

    for (usize i = 0; i < sizeof(dispatch_noise) / sizeof(dispatch_noise[0]); i++) {
        unsigned int w = dispatch_noise[i];
        unsigned int c = n ? input[(i * 5u + (w >> 3)) % n] : (unsigned int)i;

        x ^= (w + c + (unsigned int)i);
        x = (x << 7) | (x >> 25);
        x += 0x6a09e667u ^ (x >> 9);
    }

    vm_noise_state ^= x;
    return x;
}

__attribute__((noinline, used))
static u8 translate_opcode(u8 op, const u8 *input, usize n)
{
    unsigned int x = fold_noise(input, n);
    u8 mask = (u8)((x ^ vm_noise_state) & 0xffu);

    return (u8)((op ^ mask) ^ mask);
}

static int run_vm(const u8 *input)
{
    Vm vm;
    usize pc = 0;
    usize input_len = c_strlen((const char *)input);

    if (input_len != FLAG_LEN) {
        return 0;
    }

    c_memzero(&vm, sizeof(vm));
    vm.input = input;
    vm.ok = 1;

    for (;;) {
        u8 op = translate_opcode(bytecode[pc++], input, input_len);

        switch (op) {
        case OP_LEN:
            if (c_strlen((const char *)input) != bytecode[pc++]) {
                vm.ok = 0;
            }
            break;

        case OP_LOAD:
            vm.acc = vm.input[vm.pos];
            break;

        case OP_ADD_POS:
            vm.acc = (u8)(vm.acc + (u8)(vm.pos * 17));
            break;

        case OP_XOR:
            vm.acc ^= bytecode[pc++];
            break;

        case OP_ROL_POS:
            vm.acc = rol8(vm.acc, vm.pos);
            break;

        case OP_CMP:
            if (vm.acc != expected[vm.pos]) {
                vm.ok = 0;
            }
            break;

        case OP_NEXT:
            vm.pos++;
            if (vm.pos < FLAG_LEN) {
                pc = 2;
            }
            break;

        case OP_HALT:
            return vm.ok;

        default:
            return 0;
        }
    }
}

__attribute__((used))
void c_start(unsigned long *sp)
{
    long argc = (long)sp[0];
    char **argv = (char **)(sp + 1);

    if (argc != 2) {
        sys_write(1, "usage: ./tiny_vm <input>\n", 25);
        sys_exit(1);
    }

    if (run_vm((const u8 *)argv[1])) {
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
