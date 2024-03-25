#include <bcp.h>
#include <libcrypto/aes.h>
#include <libcrypto/bsl.h>
#include <libcrypto/sha1.h>
#include <macros.h>

#include "misc.h"
#include "rand.h"
#include "virage.h"

Virage01Selector sel = NONE;

void flip_sel(void) {
    switch (sel) {
        case V0:
            sel = V1;
            break;

        case V1:
            sel = V0;
            break;

        default:
            break;
    }
}

void set_proc_permissions(BbContentMetaDataHead *cmdHead) {
    u32 temp;

    IO_WRITE(PI_ALLOWED_IO, cmdHead->hwAccessRights & 0xFF);
    temp = ((cmdHead->hwAccessRights & 0x0000FF00) >> 8) & 1;
    IO_WRITE(USB0_CTRL_REG, temp);
    IO_WRITE(USB1_CTRL_REG, temp);
    temp = IO_READ(MI_SK_EXCEPTION_REG) & ~0x01000000;
    if (cmdHead->hwAccessRights & 0x200) {
        temp |= 0x01000000;
    }
    IO_WRITE(MI_SK_EXCEPTION_REG, temp);
    // all processes are allowed all SKCs
}

s32 SHAnanigans(u32 *random_out, u32 num_words) {
    SHA1Context sha1ctx;
    u8 random_bytes[0x200];
    u8 sp270[125][0x14];
    union {
        u32 words[5];
        u8 bytes[0x14];
    } spC38;
    u8 random_byte;

    if (num_words > 8) {
        return 1;
    }

    do {
        for (u32 i = 0; i < 125; i++) {
            for (u32 j = 0; j < 0x200; j++) {
                random_byte = 0;
                for (u32 k = 0; k < 8; k++) {
                    random_byte += ((IO_READ(MI_RANDOM_BIT) & 1) << k);
                }
                random_bytes[j] = random_byte;
            }
            SHA1Reset(&sha1ctx);
            SHA1Input(&sha1ctx, random_bytes, ARRAY_COUNT(random_bytes));
            SHA1Result(&sha1ctx, spC38.bytes);
            memcpy(&sp270[i], spC38.bytes, 0x14);
        }
    } while (do_randomness((u8 *)sp270, 0x9C4) == -1);
    SHA1Reset(&sha1ctx);
    SHA1Input(&sha1ctx, (u8 *)sp270, sp270[0][0] + 1);
    SHA1Input(&sha1ctx, (u8 *)virage2_offset->appStateKey, 0x10);
    SHA1Input(&sha1ctx, (u8 *)virage2_offset->selfMsgKey, 0x10);
    SHA1Result(&sha1ctx, spC38.bytes);

    if (num_words > 4) {
        wordcopy(random_out, spC38.words, 4);
        SHA1Reset(&sha1ctx);
        SHA1Input(&sha1ctx, (u8 *)sp270, sp270[0][1] + 1);
        SHA1Result(&sha1ctx, spC38.bytes);
        wordcopy(&random_out[4], spC38.words, num_words - 4);
    } else {
        wordcopy(random_out, spC38.words, num_words);
    }
    return 0;
}

s32 gen_random_words(u32 *random_out, u32 num_words) {
    u32 num_chunks = num_words / 8;
    u32 remainder = num_words % 8;

    if (remainder > 0 && SHAnanigans(random_out, remainder) != 0) {
        return 1;
    }
    random_out = &random_out[remainder];

    for (u32 i = 0; i < num_chunks; i++) {
        if (SHAnanigans(&random_out[i * 8], 8) != 0) {
            return 1;
        }
    }
    return 0;
}

void ecc_sign(u8 *data, u32 datasize, u32 *private_key, BbEccSig *signature, u32 identity) {
    u32 random_data[8];

    do {
        gen_random_words(random_data, ARRAY_COUNT(random_data));
    } while (bsl_compute_ecc_sig(data, datasize, private_key, random_data, (u32 *)signature, identity) != BSL_OK);
}

s32 wait_pi_ready(void) {
    while (IO_READ(PI_STATUS_REG) & ((1 << 1) | (1 << 0))) {
        if ((IO_READ(PI_STATUS_REG) & (1 << 2))) {
            return 1;
        }
    }
    IO_WRITE(PI_STATUS_REG, (1 << 1));
    return 0;
}

s32 dma_from_pibuf(void *outBuf, s32 length, s32 direction) {
    IO_WRITE(PI_DRAM_ADDR_REG, outBuf);
    IO_WRITE(PI_CART_ADDR_REG, 0);

    if (direction == OS_READ) {
        IO_WRITE(PI_EX_WR_LEN_REG, length - 1);
    } else {
        IO_WRITE(PI_EX_RD_LEN_REG, length - 1);
    }

    return wait_pi_ready();
}

void aes_cbc_set_key_iv(BbAesKey *key, BbAesIv *iv) {
    u32 expandedKey[AES_EXPANDED_KEY_LEN / 4];

    aes_HwKeyExpand((u8 *)key, (u8 *)expandedKey);
    wordcopy((void *)PHYS_TO_K1(PI_AES_EXPANDED_KEY_BUF(0)), &expandedKey, ARRAY_COUNT(expandedKey));
    wordcopy((void *)PHYS_TO_K1(PI_AES_IV_BUF(0)), iv, ARRAY_COUNT(*iv));
}

void AES_Run(s32 continuation) {
    u32 ctrl = PI_AES_EXEC_CMD;
    if (continuation) {
        ctrl |= 1;
    } else {
        ctrl |= 0x9A;
    }
    ctrl |= (0x200 / 0x10 - 1) << 16;

    IO_WRITE(PI_AES_CTRL_REG, ctrl);
}

s32 card_read_page(u32 block) {
    IO_WRITE(PI_CARD_BLK_OFFSET_REG, block * 512);

    IO_WRITE(PI_CARD_CNT_REG, 0x9F008A10);

    do {
        if ((IO_READ(MI_HW_INTR_REG) & 0x02000000) != 0) {
            IO_WRITE(PI_CARD_CNT_REG, 0);
            return 2;
        }
    } while ((IO_READ(PI_CARD_CNT_REG) & (1 << 31)));

    if (IO_READ(PI_CARD_CNT_REG) & (1 << 10)) {
        return 1;
    }
    return 0;
}

char *strchr(char *str, char c) {
    for (; *str != c; str++) {
        if (*str == '\0')
            return NULL;
    }

    return str;
}

size_t strlen(const char *str) {
    const char *end = str;

    while (*end != '\0') {
        end++;
    }
    return end - str;
}

int strcmp(const char *str1, const char *str2) {
    while (*str1 == *str2) {
        if (*str1 == '\0') {
            return 0;
        }
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

int strncmp(const char *str1, const char *str2, int num) { // num is signed?
    int ret = 0;
    int n;

    for (n = 0; n < num; n++) {
        if (str1[n] != str2[n]) {
            ret = -1;
        }
        // no null termination check
    }
    return ret;
}

const char *strstr(const char *str1, const char *str2) {
    int len1;
    int len2;

    len2 = strlen(str2);
    if (len2 == 0) {
        return str1;
    }

    len1 = strlen(str1);
    if (len1 < len2) {
        return NULL;
    }

    while (len1 >= len2) {
        len1--;
        if (memcmp(str1, str2, len2) == 0) {
            return str1;
        }
        str1++;
    }
    return NULL;
}

void *memcpy(void *dst, const void *src, size_t num) {
    u8 *dstp = (u8 *)dst;
    u8 *srcp = (u8 *)src;

    while (num != 0) {
        *(dstp++) = *(srcp++);
        num--;
    }
    return dst;
}

void *wordcopy(void *dst, const void *src, s32 nWords) {
    s32 *srcp = (s32 *)src;
    s32 *dstp = (s32 *)dst;

    while (nWords != 0) {
        *(dstp++) = *(srcp++);
        nWords--;
    }
    return dst;
}

void *memset(void *ptr, int value, size_t num) {
    size_t n;

    for (n = 0; n < num; n++) {
        ((u8 *)ptr)[n] = value;
    }
    return ptr;
}

void memclear(void *ptr, size_t num) {
    memset(ptr, 0, num);
}

int memcmp(const void *ptr1, const void *ptr2, size_t num) {
    u8 v1;
    u8 v2;
    const u8 *p1 = ptr1;
    const u8 *p2 = ptr2;

    while (num-- > 0) {
        v2 = *(p2++);
        v1 = *(p1++);
        if (v1 != v2) {
            return v1 - v2;
        }
    }
    return 0;
}

u16 calc_virage01_checksum(void *d) {
    u16 *data = d;
    u16 sum;

    sum = 0;
    for (u32 i = 0; i < (sizeof(BbVirage01) / sizeof(u16)); i++) {
        sum += data[i];
    }
    return sum;
}

s32 read_virage01(u16 *seq_out, void *controller, BbVirage01 *virage_data) {
    // Read virage data from specified virage controller. 0x10 words, 0x40 bytes
    wordcopy(virage_data, (void *)PHYS_TO_K1((u32)controller), 0x10);

    // Check that checksum is correct
    if (calc_virage01_checksum(virage_data) == V01_MAGIC) {
        *seq_out = virage_data->seq;
        return 0;
    }

    return 1;
}

s32 write_virage01_data(BbVirage01 *virage_data) {
    u32 controller;

    virage_data->sum = 0;
    virage_data->seq++;
    virage_data->sum = V01_MAGIC - calc_virage01_checksum(virage_data);

    if (sel == V0) {
        controller = VIRAGE0_BASE_ADDR;
    } else {
        controller = VIRAGE1_BASE_ADDR;
    }

    if (write_virage_data(controller | 0xC000, (void *)virage_data, 0x10)) {
        return 1;
    }

    flip_sel();

    return 0;
}

s32 set_virage01_selector(BbVirage01 *virage_data) {
    s32 v0_status, v1_status;

    u16 v0_write_count;
    u16 v1_write_count;

    initialise_virage_controllers();

    // read v0
    if (read_virage(VIRAGE0_STATUS_REG)) {
        return 1;
    }

    v0_status = read_virage01(&v0_write_count, (void *)PHYS_TO_K1(VIRAGE0_BASE_ADDR), virage_data);

    // read v1
    if (read_virage(VIRAGE1_STATUS_REG)) {
        return 1;
    }

    v1_status = read_virage01(&v1_write_count, (void *)PHYS_TO_K1(VIRAGE1_BASE_ADDR), virage_data);

    // if both failed the checksum, clear the data and use v1 for writes
    if ((v0_status) && (v1_status)) {
        memset(virage_data, 0, sizeof(BbVirage01));
        sel = V1;
        return write_virage01_data(virage_data);
    }

    if (v1_write_count < v0_write_count) {
        // if the v1 write count is less than the v0 write count (or if v1 failed the checksum), use v0 data but use v1
        // for writes
        if ((read_virage(VIRAGE0_STATUS_REG)) || (read_virage01(&v0_write_count, (void *)PHYS_TO_K1(VIRAGE0_BASE_ADDR), virage_data))) {
            return 1;
        }
        sel = V1;
    } else {
        // if the v0 write count is less than the v1 write count (or if v0 failed the checksum), use v1 data but use v0
        // for writes
        sel = V0;
    }

    return 0;
}

void bzero(void *, size_t) __attribute__((alias("memclear")));

void set_error_led(u32 value) {
    u32 mask = IO_READ(PI_MISC_REG);
    mask &= ~2;
    mask &= ~(2 << 4);
    IO_WRITE(PI_MISC_REG, mask | (value == 0 ? 2 : 0) | (2 << 4));
}