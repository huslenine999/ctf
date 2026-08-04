#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
    const uint8_t *input;
    uint8_t pos;
    uint8_t acc;
    uint8_t ok;
} Vm;

static const uint8_t expected[FLAG_LEN] = {
    0xf1,0x85,0x0b,0xe6,0x81,0x8d,0x1d,0xb8,0x57,0xba,0xfe,0xc5,0xf9,0xbc,0xf1,0xea,
    0xc8,0x44,0xc0,0x70,0xa1,0x8e,0x1f,0xa0,0xab,0x79,0x22,0xc4,0x3e,0x35,0x2e,0x95
};

static const uint8_t bytecode[] = {
    OP_LEN, FLAG_LEN,
    OP_LOAD,
    OP_ADD_POS,
    OP_XOR, 0xa7,
    OP_ROL_POS,
    OP_CMP,
    OP_NEXT,
    OP_HALT
};

static uint8_t rol8(uint8_t x, uint8_t n)
{
    n &= 7;
    if (n == 0) {
        return x;
    }

    return (uint8_t)((x << n) | (x >> (8 - n)));
}

static int run_vm(const uint8_t *input)
{
    Vm vm;
    size_t pc = 0;

    if (strlen((const char *)input) != FLAG_LEN) {
        return 0;
    }

    memset(&vm, 0, sizeof(vm));
    vm.input = input;
    vm.ok = 1;

    for (;;) {
        uint8_t op = bytecode[pc++];

        switch (op) {
        case OP_LEN:
            if (strlen((const char *)input) != bytecode[pc++]) {
                vm.ok = 0;
            }
            break;

        case OP_LOAD:
            vm.acc = vm.input[vm.pos];
            break;

        case OP_ADD_POS:
            vm.acc = (uint8_t)(vm.acc + (uint8_t)(vm.pos * 17));
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

int main(int argc, char **argv)
{
    if (argc != 2) {
        puts("usage: ./tiny_vm <input>");
        return 1;
    }

    if (run_vm((const uint8_t *)argv[1])) {
        puts("accepted");
        return 0;
    }

    puts("rejected");
    return 1;
}
