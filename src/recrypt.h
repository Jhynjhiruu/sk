#ifndef _RECRYPT_H
#define _RECRYPT_H

#include <bbtypes.h>

s32 recrypt_list_add_new_entry(RecryptList *, BbContentId, u32);

s32 recrypt_list_get_key_for_cid(RecryptList *, BbAesKey *, BbContentId);

#endif