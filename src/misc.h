#ifndef _MISC_H
#define _MISC_H

#include <bbtypes.h>

typedef enum {
    V0,
    V1,
    NONE,
} Virage01Selector;

#define V01_MAGIC (0x7ADC)

void set_proc_permissions(BbContentMetaDataHead *);

s32 SHAnanigans(u32 *, u32);

s32 gen_random_words(u32 *, u32);

void ecc_sign(u8 *, u32, u32 *, BbEccSig *, u32);

s32 dma_from_pibuf(void *, s32, s32);

void aes_cbc_set_key_iv(BbAesKey *, BbAesIv *);

void AES_Run(s32);

s32 card_read_page(u32);

s32 set_virage01_selector(BbVirage01 *);

char *strchr(char *, char);
size_t strlen(const char *);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, int);
const char *strstr(const char *, const char *);
void *memcpy(void *, const void *, size_t);
void *wordcopy(void *, const void *, s32);
void *memset(void *, int, size_t);
void memclear(void *, size_t);
int memcmp(const void *, const void *, size_t);

void set_error_led(u32 value);

#endif