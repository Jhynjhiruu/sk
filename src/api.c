#include <macros.h>

#include "api.h"

s32 __dummy(void);

const void *skc_table[] = {skGetId, __dummy, __dummy, __dummy, __dummy, __dummy, __dummy, __dummy, __dummy, __dummy, __dummy, __dummy, __dummy, skExit, __dummy};

const u32 skc_table_size = ARRAY_COUNT(skc_table);

s32 __dummy(void) {
    return 0;
}

s32 skGetId(BbId *id) {
    *id = virage2_offset->bbId;

    return 0;
}

s32 skExit(void) {
    startup();
    return 0;
}
