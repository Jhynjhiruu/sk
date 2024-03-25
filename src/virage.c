#include <bcp.h>

#include "virage.h"

BbVirage2 *virage2_offset = (BbVirage2 *)PHYS_TO_K1(VIRAGE2_BASE_ADDR);

void delay(u32 count) {
    for (u32 i = 0; i < count; i++) {
        __asm__ volatile("nop");
    }
}

void initialise_virage_controller(u32 ctrlReg) {
    u32 baseAddr = ctrlReg & 0xFFFF0000;

    IO_WRITE(baseAddr + 0x8000, 0x8A);
    IO_WRITE(baseAddr + 0x8004, 0x13);
    IO_WRITE(baseAddr + 0x8008, 0x80);
    IO_WRITE(baseAddr + 0x800C, 0x92);
    IO_WRITE(baseAddr + 0x8010, 0x18);
    IO_WRITE(baseAddr + 0x8014, 5);
}

void initialise_virage_controllers(void) {
    IO_WRITE(VIRAGE2_STATUS_REG, 0);
    initialise_virage_controller(VIRAGE0_STATUS_REG);
    initialise_virage_controller(VIRAGE1_STATUS_REG);
    initialise_virage_controller(VIRAGE2_STATUS_REG);
}

s32 write_virage_data(u32 controller, u32 *data, u32 size) {
    u32 addr = controller & 0xFFFF0000;
    u32 clock = get_clock();
    u32 temp;

    IO_WRITE(controller, 0);
    IO_WRITE(MI_1C_REG, (1000 / clock) + 1);
    delay(640000 / clock);

    temp = IO_READ(controller);
    if (temp & 1) {
        delay(20000 / clock);
        delay(20000 / clock);

        temp = IO_READ(controller);
        if (temp & 1) {
            return 1;
        }
    }

    temp = IO_READ(controller);
    if ((temp & 0x40000000) == 0) {
        return 1;
    }

    for (u32 i = 0; i < size; i++) {
        IO_WRITE(addr + (i * 4), data[i]);
        temp = IO_READ(addr + (i * 4));
        if (temp != data[i]) {
            return 1;
        }
    }

    if (write_virage_data_raw(controller)) {
        return 1;
    }

    for (u32 i = 0; i < size; i++) {
        IO_WRITE(addr + (i * 4), 0);
        temp = IO_READ(addr + (i * 4));
        if (temp != 0) {
            return 1;
        }
    }

    if (read_virage(controller)) {
        return 1;
    }

    for (u32 i = 0; i < size; i++) {
        temp = IO_READ(addr + (i * 4));
        if (temp != data[i]) {
            return 1;
        }
    }

    return 0;
}

u32 get_clock(void) {
    u32 temp = (IO_READ(PI_MISC_REG) >> 25) & 3;

    if (temp == 0) {
        return 1000 / 62.5;
    } else if (temp == 1) {
        return 1000 / 80;
    } else {
        return 1000 / 96;
    }
}

s32 read_virage(u32 controller) {
    u32 addr = controller | 0x2000;
    u32 base_delay;

    base_delay = 44018 / get_clock();
    IO_WRITE(addr, 0x03000000);
    delay(base_delay + 100);
    delay(base_delay + 400);
    if (!(IO_READ(controller) & 0x40000000)) {
        return 1;
    }
    return 0;
}

s32 write_virage_data_raw(u32 controller) {
    u32 addr = controller | 0x2000;
    u32 temp;

    IO_WRITE(addr, 0x02000000);
    delay(100);

    temp = IO_READ(controller);
    if (temp & 0x40000000) {
        return 1;
    }

    while (((temp = IO_READ(controller)) & 0x40000000) == 0) {
        delay(100);
    }

    if ((temp & 0x20000000) == 0) {
        return 1;
    }

    return 0;
}
