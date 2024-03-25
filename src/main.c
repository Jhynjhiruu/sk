#include <bbtypes.h>
#include <bcp.h>
#include <libcrypto/aes.h>

#include "blocks.h"
#include "cache.h"
#include "misc.h"
#include "virage.h"

#define THROW_EXCEPTION() ((void (*)())PHYS_TO_K1(R_VEC + 0x200 + E_VEC))()

u32 app_flags = 0;

BbVirage01 v01;

u8 cmd_buf[BYTES_PER_BLOCK] __attribute__((section(".skram")));

#define SK_SIZE (4)

#define N64_ROM_HEADER_SIZE (0x1000)
#define N64_ROM_HEADER_LOADADDR_OFFSET (8)

typedef void (*SA1Entry)(u32);

void dram_init(void) {
    IO_READ(PI_MISC_REG);

    IO_WRITE(RI_MODE_REG, RI_MODE_CMD_PRECHARGE_ALL);
    IO_READ(RI_MODE_REG);
    IO_WRITE(RI_MODE_REG, RI_MODE_EXTENDED | RI_MODE_DIC_WEAK | RI_MODE_DLL_ENABLE);
    IO_READ(RI_MODE_REG);
    IO_WRITE(RI_MODE_REG, RI_MODE_DLL_RESET);
    IO_READ(RI_MODE_REG);
    IO_WRITE(RI_MODE_REG, RI_MODE_CMD_PRECHARGE_ALL);
    IO_READ(RI_MODE_REG);
    IO_WRITE(RI_MODE_REG, RI_MODE_CMD_AUTO_REFRESH);
    IO_READ(RI_MODE_REG);
    IO_WRITE(RI_MODE_REG, RI_MODE_CMD_AUTO_REFRESH);
    IO_READ(RI_MODE_REG);
    IO_WRITE(RI_MODE_REG, RI_MODE_DLL_NRESET | RI_MODE_CAS_LATENCY_3 | RI_MODE_BT_INTERL | RI_MODE_BURST_LEN_4);
    IO_READ(RI_MODE_REG);
    IO_WRITE(RI_40_REG, 0x031111E4);
    IO_READ(RI_30_REG);
    IO_READ(RI_30_REG);
    IO_WRITE(RI_60_REG, 1);
    IO_READ(RI_30_REG);
    IO_WRITE(RI_80_REG, 1);
    IO_READ(RI_30_REG);

    for (u32 i = 0; i < 100; i++) {
        IO_READ(RI_30_REG);
    }
    IO_WRITE(RI_30_REG, 0x000011E0);
    IO_READ(RI_30_REG);
}

s32 find_next_good_block(u16 *out_block, u16 start_block) {
    s32 ret;
    u32 block_status;

    while (TRUE) {
        s32 num_bad_bits = 0;

        ret = card_read_page(start_block * PAGES_PER_BLOCK);
        if (ret == 2) {
            // fatal error
            return 1;
        }

        block_status = IO_READ(PI_10404_REG);

        for (u32 i = 0; i < 8; i++) {
            if (((block_status >> (i + 16)) & 1) == 0) {
                num_bad_bits++;
            }
        }

        start_block++;

        if (num_bad_bits < 2) {
            break;
        }
    }

    if (ret == 0) {
        *out_block = start_block - 1;
    }

    return ret;
}

s32 block_link(u32 spare) {
    // the link is stored in the spare data 3 times, so get the best 2 of 3
    u8 a = (spare >> 8), b = (spare >> 16), c = (spare >> 24);
    if (a == b) {
        return a;
    } else {
        return c;
    }
}

s32 load_sa_ticket(u16 *sa_start_block, u16 start_block) {
    s32 ret;
    u16 ticket_block;

    ret = find_next_good_block(&ticket_block, start_block);
    if (ret) {
        return ret;
    }

    for (u32 i = 0; i < PAGES_PER_BLOCK; i++) {
        ret = card_read_page((ticket_block * PAGES_PER_BLOCK) + i);
        if (ret) {
            return ret;
        }

        if (i == 0) {
            *sa_start_block = block_link(IO_READ(PI_10400_REG));
        }

        for (u32 j = 0; j < BYTES_PER_PAGE; j += 4) {
            *(u32 *)(cmd_buf + i * BYTES_PER_PAGE + j) = IO_READ(PI_10000_BUF(j));
        }
    }

    return ret;
}

s32 load_page(u32 block, s32 continuation, SA1Entry *dram_addr_out, u32 length, s32 first) {
    s32 ret;

    ret = card_read_page(block);
    if (ret) {
        return 1;
    }

    AES_Run(continuation);

    while (IO_READ(PI_AES_STATUS_REG) & PI_AES_BUSY)
        ;

    if (first) {
        SA1Entry *temp = (SA1Entry *)PHYS_TO_K1(PI_10000_BUF(8));

        *dram_addr_out = (SA1Entry)KDM_TO_PHYS(*temp);
    }

    osInvalDCache((void *)PHYS_TO_K0(*dram_addr_out), BYTES_PER_PAGE);

    ret = dma_from_pibuf(*dram_addr_out, length, OS_READ);
    if (ret) {
        return 1;
    }

    return 0;
}

s32 load_system_app(SA1Entry *sa1_entry_out) {
    s32 ret;

    BbContentMetaDataHead *cmd;
    u16 sa1_start;
    u32 sa1_end_page;
    BbAesKey sa1_key;
    s32 aes_continuation = FALSE;
    u32 length = BYTES_PER_PAGE;
    SA1Entry dram_addr;
    u32 remaining;

    u32 page;

    ret = load_sa_ticket(&sa1_start, SK_SIZE);
    if (ret) {
        return 1;
    }

    cmd = (BbContentMetaDataHead *)cmd_buf;
    if (aes_SwDecrypt((u8 *)&virage2_offset->bootAppKey, (u8 *)cmd->commonCmdIv, (u8 *)cmd->key, sizeof(cmd->key), (u8 *)&sa1_key) < 0) {
        return 1;
    }

    sa1_end_page = (cmd->size + BYTES_PER_PAGE) / BYTES_PER_PAGE;

    aes_cbc_set_key_iv(&sa1_key, &cmd->iv);

    for (page = 0; page < (N64_ROM_HEADER_SIZE / BYTES_PER_PAGE); page++) {
        ret = load_page((sa1_start * PAGES_PER_BLOCK) + page, aes_continuation, &dram_addr, length, page == 0);
        if (ret) {
            return 1;
        }

        aes_continuation = TRUE;

        if (page == 0) {
            *sa1_entry_out = *(SA1Entry *)PHYS_TO_K0(dram_addr + N64_ROM_HEADER_LOADADDR_OFFSET);
        }
    }

    remaining = cmd->size - N64_ROM_HEADER_SIZE;

    for (u32 j = page; j < sa1_end_page; j++) {
        if (remaining > BYTES_PER_PAGE) {
            length = BYTES_PER_PAGE;
            remaining -= BYTES_PER_PAGE;
        } else {
            length = remaining;
            remaining = 0;
        }

        ret = load_page((sa1_start * PAGES_PER_BLOCK) + page, aes_continuation, &dram_addr, length, FALSE);
        if (ret) {
            return 1;
        }

        if (page++ == (PAGES_PER_BLOCK - 1)) {
            page = 0;
            sa1_start = block_link(IO_READ(PI_10400_REG));
        }

        dram_addr += length;
    }

    set_proc_permissions(cmd);

    return 0;
}

SA1Entry setup_system(void) {
    SA1Entry sa1_entry;

    IO_WRITE(PI_MISC_REG, 0x31);
    IO_WRITE(MI_3C_REG, 0x01000000);
    IO_WRITE(MI_SK_EXCEPTION_REG, IO_READ(MI_SK_EXCEPTION_REG) & ~0x02000000);
    IO_WRITE(MI_18_REG, 0);
    IO_WRITE(PI_STATUS_REG, PI_CLR_INTR | PI_SET_RESET); // reset PI
    IO_WRITE(PI_CARD_CNT_REG, 0);
    IO_WRITE(PI_AES_CTRL_REG, 0);
    IO_WRITE(VI_CURRENT_REG, 0); // clears VI interrupt
    IO_WRITE(SP_STATUS_REG, SP_CLR_RSPSIGNAL | SP_CLR_INTR);
    IO_WRITE(AI_STATUS_REG, AI_CONTROL_DMA_ON);
    IO_WRITE(SI_STATUS_REG, 0); // clears SI interrupt
    IO_WRITE(MI_MODE_REG, MI_CLR_DP_INTR);
    IO_WRITE(MI_INTR_MASK_REG, MI_INTR_MASK_CLR_SP | MI_INTR_MASK_CLR_SI | MI_INTR_MASK_CLR_AI | MI_INTR_MASK_CLR_VI | MI_INTR_MASK_CLR_PI | MI_INTR_MASK_CLR_DP);
    IO_WRITE(MI_3C_REG, 0x05555000); // clears ique specific interrupts

    // ignore the return value
    set_virage01_selector(&v01);

    if ((IO_READ(MI_SK_EXCEPTION_REG) & 0xFC) == 0) {
        // coldboot

        dram_init();
    }

    // retail SK tries to lock V2 here
    // let's not do that

    if (load_system_app(&sa1_entry)) {
        THROW_EXCEPTION();
    }

    IO_WRITE(PI_MISC_REG, 0x33);

    // no trials

    return sa1_entry;
}

s32 check_trial_timer(void) {
    // infinite timers!
    IO_WRITE(MI_18_REG, 0x7530C800);
    return 0;
}
