#ifndef _VIRAGE_H
#define _VIRAGE_H

#include <bbtypes.h>

void initialise_virage_controllers(void);

s32 write_virage_data(u32 controller, u32 *data, u32 size);

u32 get_clock(void);

s32 read_virage(u32 controller);

s32 write_virage_data_raw(u32 controller);

#endif