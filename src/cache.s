#include "asm.h"
#include "regdef.h"
#include "bcp.h"

.set mips3

.balign 32

LEAF(icache_reset)
    // resets the instruction cache when coming from untrusted code
    la      t0, K0BASE
    addiu   t1, t0, ICACHE_SIZE
    addiu   t1, t1, -ICACHE_LINESIZE
    mtc0    zero, C0_TAGLO
    mtc0    zero, C0_TAGHI
1:
    cache   (CACH_PI | C_IST), (t0)
.set noreorder
    bltu    t0, t1, 1b
     addiu  t0, t0, ICACHE_LINESIZE
.set reorder
    jr      ra
END(icache_reset)
.if . - icache_reset > 2*ICACHE_LINESIZE
  .error "icache_reset is expected to fit in two icache lines"
.endif

LEAF(dcache_reset)
    // invalidates the cache in the bootrom address space
    la      t0, __bootrom_start
    addiu   t1, t0, DCACHE_SIZE
    addiu   t1, t1, -DCACHE_LINESIZE
    la      t5, __boot_protected_start
    la      t6, __boot_protected_end
1:
    // load the tag of the cache line that the address in t0 uses into TagLo
    cache   (CACH_PD | C_ILT), (t0)
    nop
    mfc0    t4, C0_TAGLO
    andi    t2, t4, PSTATEMASK
.set noreorder
    // skip if cache line is invalid
    beqz    t2, 2f
     and    t4, t4, PADDRMASK // NOTE: macro expansion in delay slot
.set reorder
    sll     t4, t4, PADDR_SHIFT

    // skip if not in the relevant address range
    bltu    t4, t5, 2f
    bltu    t6, t4, 2f

    // invalidate this cache line
    mtc0    zero, C0_TAGLO
    cache   (CACH_PD | C_IST), (t0)
2:
.set noreorder
    bltu    t0, t1, 1b
     addiu  t0, t0, DCACHE_LINESIZE
.set reorder

    jr      ra
END(dcache_reset)

LEAF(wipe_sk_stack)
    // clear the stack
    la      t0, __skram_start
    la      t1, __sk_stack_end_k0_adj
1:
    sd      zero, (t0)
    addiu   t0, 8
    bltu    t0, t1, 1b

    // write back the cache
    la      t0, __skram_start
    addiu   t1, t0, DCACHE_SIZE
2:
    cache   (CACH_PD | C_IWBINV), (t0)
    addiu   t0, DCACHE_LINESIZE
    bltu    t0, t1, 2b

    jr      ra
END(wipe_sk_stack)
