#include <bcp.h>

#include "except.h"

void __sk_exception_handler(ExceptionCallback cb) {
    cb((char *)PHYS_TO_K1("Entering exception handler"));
    IO_WRITE(PI_MISC_REG, 0x30);
    while (TRUE)
        ;
}

void __dummy_callback(const char *message) {
    // do nothing
}