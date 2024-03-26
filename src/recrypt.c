#include <libcrypto/aes.h>
#include <macros.h>

#include "misc.h"
#include "recrypt.h"
#include "virage.h"

#define RECRYPT_LIST_ECC_IDENTITY (0x06091968)

void recrypt_list_sign(RecryptList *list) {
    ecc_sign((u8 *)&list->numEntries, list->numEntries * sizeof(RecryptListEntry) + sizeof(u32), virage2_offset->privateKey, &list->signature, RECRYPT_LIST_ECC_IDENTITY);
}

void recrypt_list_decrypt_entry(RecryptListEntry *entry, RecryptList *list, u32 index) {
    BbAesIv recrypt_list_entry_iv;

    for (u32 i = 0; i < ARRAY_COUNT(recrypt_list_entry_iv); i++) {
        recrypt_list_entry_iv[i] = virage2_offset->bbId + i;
    }

    aes_SwDecrypt((u8 *)virage2_offset->recryptListKey, (u8 *)recrypt_list_entry_iv, (u8 *)&list->entries[index], sizeof(RecryptListEntry), (u8 *)entry);
}

void recrypt_list_add_entry(RecryptListEntry *entry, RecryptList *list, u32 index) {
    RecryptListEntry encrypted_entry;
    BbAesIv recrypt_list_entry_iv;

    for (u32 i = 0; i < ARRAY_COUNT(recrypt_list_entry_iv); i++) {
        recrypt_list_entry_iv[i] = virage2_offset->bbId + i;
    }

    aes_SwEncrypt((u8 *)virage2_offset->recryptListKey, (u8 *)recrypt_list_entry_iv, (u8 *)entry, sizeof(RecryptListEntry), (u8 *)&encrypted_entry);

    memcpy(&list->entries[index], &encrypted_entry, sizeof(RecryptListEntry));
}

s32 recrypt_list_get_entry_for_cid(RecryptList *list, BbContentId cid, RecryptListEntry *entry_out, u32 *index_out) {
    for (u32 i = 0; i < list->numEntries; i++) {
        recrypt_list_decrypt_entry(entry_out, list, i);
        if (entry_out->contentId == cid) {
            *index_out = i;
            return 0;
        }
    }

    return 1;
}

s32 recrypt_list_add_new_entry(RecryptList *list, BbContentId cid, u32 state) {
    s32 ret;

    RecryptListEntry entry;
    u32 index;

    ret = recrypt_list_get_entry_for_cid(list, cid, &entry, &index);
    if (ret) {
        return 1;
    }

    entry.state = state;
    recrypt_list_add_entry(&entry, list, index);
    recrypt_list_sign(list);

    return 0;
}

s32 recrypt_list_get_key_for_cid(RecryptList *list, BbAesKey *key, BbContentId cid) {
    RecryptListEntry entry;
    u32 index;

    if (recrypt_list_get_entry_for_cid(list, cid, &entry, &index)) {
        // not found, need to create an entry

        entry.contentId = cid;
#ifdef NO_RECRYPT
        memcpy(entry.contentKey, key, sizeof(BbAesKey));
#else
        gen_random_words(entry.contentKey, sizeof(entry.contentKey) / sizeof(u32));
#endif
        entry.state = 3;

        recrypt_list_add_entry(&entry, list, list->numEntries);
        list->numEntries++;

        recrypt_list_sign(list);

#ifndef NO_RECRYPT
        memcpy(key, entry.contentKey, sizeof(BbAesKey));
#endif

        return 4;
    } else {
        // found

        memcpy(key, entry.contentKey, sizeof(BbAesKey));

        return entry.state;
    }
}