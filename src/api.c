#include <bcp.h>
#include <libcrypto/aes.h>
#include <libcrypto/bsl.h>
#include <macros.h>

#include "api.h"
#include "blocks.h"
#include "misc.h"
#include "recrypt.h"
#include "virage.h"

const void *skc_table[] = {
    skGetId,
    skLaunchSetup,
    skLaunch,
    skRecryptListValid,
    skRecryptBegin,
    skRecryptData,
    skRecryptComputeState,
    skRecryptEnd,
    skSignHash,
    skVerifyHash,
    skGetConsumption,
    skAdvanceTicketWindow,
    skSetLimit,
    skExit,
    skKeepAlive,

    // unknown debug SKCs
    skGetRandomKeyData,
    skDumpVirage,
    skTest2,
    skTest3,
    skResetWindow,
    skValidateRls,

    // custom SKCs
    skMemCopy,
};

const u32 skc_table_size = ARRAY_COUNT(skc_table);

// variables used for launching

BbContentMetaDataHead launch_cmd_head;

BbTicketHead launch_ticket_head;

u32 recrypt_state = 0;

AesCipherInstance launch_aes_instance;

AesKeyInstance launch_aes_key;

u32 bytes_processed = 0;

s32 recrypt_aes_chaining = FALSE;

BbAesIv recrypt_aes_iv;

// end of variables used for launching

// helper functions for launching

s32 load_ticket_bundle(BbTicketBundle *bundle) {
    BbAesKey ecc_aes_key, real_key;
    BbTicketHead *head = &bundle->ticket->head;
    BbContentMetaDataHead *cmd_head = &bundle->ticket->cmd.head;

    memcpy(&launch_cmd_head, cmd_head, sizeof(BbContentMetaDataHead));

    if (eccGenAesKey(head->serverKey, virage2_offset->privateKey, ecc_aes_key)) {
        return 1;
    }

    aes_SwDecrypt((u8 *)ecc_aes_key, (u8 *)head->cmdIv, (u8 *)cmd_head->key, sizeof(BbAesKey), (u8 *)launch_cmd_head.key);
    aes_SwDecrypt((u8 *)virage2_offset->bootAppKey, (u8 *)cmd_head->commonCmdIv, (u8 *)launch_cmd_head.key, sizeof(BbAesKey), (u8 *)real_key);
    memcpy(launch_cmd_head.key, real_key, sizeof(BbAesKey));

    return 0;
}

// end of helper functions for launching

s32 skGetId(BbId *id) {
    *id = virage2_offset->bbId;

    return 0;
}

s32 skLaunchSetup(BbTicketBundle *bundle, BbAppLaunchCrls *crls, RecryptList *recrypt_list) {
    s32 ret;
    BbAesKey recrypt_key;
    BbTicketHead *head = &bundle->ticket->head;

    ret = load_ticket_bundle(bundle);
    if (ret) {
        return 1;
    }

#ifdef NO_RECRYPT
    memcpy(&recrypt_key, &launch_cmd_head.key, sizeof(BbAesKey));
#endif

    if (launch_cmd_head.execFlags & 2) {
        // needs recrypt

        ret = recrypt_list_get_key_for_cid(recrypt_list, &recrypt_key, launch_cmd_head.id);

        if (ret != 2) {
            return ret;
        }

        aes_cbc_set_key_iv(&recrypt_key, &launch_cmd_head.iv);
    } else {
        aes_cbc_set_key_iv(&launch_cmd_head.key, &launch_cmd_head.iv);
    }

    memcpy(&launch_ticket_head, head, sizeof(BbTicketHead));
    IO_WRITE(PI_AES_CTRL_REG, 0);

    return 0;
}

s32 skLaunch(void *app_entrypoint) {
    set_proc_permissions(&launch_cmd_head);

    // never check hash

    if (IO_READ(PI_MISC_REG) & 0xc0000000) {
        IO_WRITE(MI_3C_REG, 0x01000000);
        IO_WRITE(MI_3C_REG, 0x02000000);
        IO_WRITE(MI_SK_EXCEPTION_REG, IO_READ(MI_SK_EXCEPTION_REG) | 0x02000000);
    }

    // don't set timer

    // launch the app, this does not return
    __asm__("move $v0, %0;"
            "la   $t0, %1;"
            "jr   $t0;"
            :
            : "r"(app_entrypoint), "i"(launch_app_trampoline)
            : "v0", "t0");

    return -1;
}

s32 skRecryptListValid(RecryptList *recrypt_list) {
    // always return true
    return 0;
}

s32 skRecryptBegin(BbTicketBundle *bundle, BbAppLaunchCrls *crls, RecryptList *recrypt_list) {
    s32 ret;
    BbAesKey recrypt_key;
    BbTicketHead *head = &bundle->ticket->head;

    ret = load_ticket_bundle(bundle);
    if (ret) {
        return 1;
    }

#ifdef NO_RECRYPT
    memcpy(&recrypt_key, &launch_cmd_head.key, sizeof(BbAesKey));
#endif

    ret = recrypt_list_get_key_for_cid(recrypt_list, &recrypt_key, launch_cmd_head.id);

    if (ret == 3) {
        // incomplete
        recrypt_state = 1;

        aes_cbc_set_key_iv(&recrypt_key, &launch_cmd_head.iv);
    } else {
        // data
        recrypt_state = 0;

        aes_cbc_set_key_iv(&launch_cmd_head.key, &launch_cmd_head.iv);
        aesCipherInit(&launch_aes_instance, 2, (u8 *)&launch_cmd_head.iv);
        recrypt_list_add_new_entry(recrypt_list, launch_cmd_head.id, 3);
    }

    aesMakeKey(&launch_aes_key, 0, 128, (u8 *)recrypt_key);
    memcpy(&launch_ticket_head, head, sizeof(BbTicketHead));

    bytes_processed = 0;
    recrypt_aes_chaining = FALSE;

    return ret;
}

s32 recrypt_block(u8 *buf, u32 size, s32 is_recrypt) {
    u32 chunk_size = BYTES_PER_PAGE;
    u32 left;

    for (u32 i = 0; i < size; i += chunk_size) {
        if (pibuf_dma((void *)K0_TO_PHYS((u32)buf), chunk_size, OS_WRITE)) {
            return 1;
        }

        AES_Run(recrypt_aes_chaining);
        recrypt_aes_chaining = TRUE;

        while (IO_READ(PI_AES_STATUS_REG) & PI_AES_BUSY)
            ;

        left = launch_cmd_head.size - bytes_processed;

        if (left >= chunk_size) {
            bytes_processed += chunk_size;
        } else {
            bytes_processed = launch_cmd_head.size;
        }

        if (is_recrypt) {
            aesBlockEncrypt(&launch_aes_instance, &launch_aes_key, (u8 *)PHYS_TO_K1(PI_10000_BUF_START), chunk_size * 8, buf);
        }

        buf += chunk_size;
    }

    return 0;
}

s32 skRecryptData(u8 *buf, u32 size) {
    if (recrypt_state == 1) {
        aesCipherInit(&launch_aes_instance, 2, (u8 *)((buf == NULL) ? &launch_cmd_head.iv : &recrypt_aes_iv));
        aes_cbc_set_key_iv(&launch_cmd_head.key, (buf == NULL) ? &launch_cmd_head.iv : (BbAesIv *)(buf + size - sizeof(BbAesIv)));

        recrypt_aes_chaining = FALSE;
        recrypt_state = 0;
    } else {
        recrypt_block(buf, size, TRUE);
    }

    return 0;
}

s32 skRecryptComputeState(u8 *buf, u32 size) {
    BbAesIv *src = (BbAesIv *)(buf + size - sizeof(BbAesIv));

    memcpy(&recrypt_aes_iv, src, sizeof(BbAesIv));

    recrypt_block(buf, size, FALSE);

    return 0;
}

s32 skRecryptEnd(RecryptList *recrypt_list) {
    if (recrypt_list_add_new_entry(recrypt_list, launch_cmd_head.id, 2)) {
        return -1;
    }

    return 0;
}

s32 skSignHash(BbShaHash *hash, BbEccSig *out_signature) {
    ecc_sign((u8 *)hash, sizeof(*hash), virage2_offset->privateKey, out_signature, 1);

    return 0;
}

s32 skVerifyHash(BbShaHash *hash, BbGenericSig *signature, BbCertBase **cert_chain, BbAppLaunchCrls *crls) {
    // always return true
    return 0;
}

s32 skGetConsumption(u16 *tid_window, u16 *cc) {
    *tid_window = 0;
    *cc = 0;
    // need to figure out how to handle this
    return 0;
}

s32 skAdvanceTicketWindow(void) {
    // do nothing
    return 0;
}

s32 skSetLimit(u16 limit, u16 code) {
    // do nothing
    return 0;
}

s32 skExit(void) {
    startup();
    return 0;
}

s32 skKeepAlive(void) {
    // let's try doing nothing for now?
    return 0;
}

// maybe these can be implemented some day

s32 skGetRandomKeyData() {
    return 0;
}

s32 skDumpVirage() {
    return 0;
}

s32 skTest2() {
    return 0;
}

s32 skTest3() {
    return 0;
}

s32 skResetWindow() {
    return 0;
}

s32 skValidateRls() {
    return 0;
}

// custom SKCs let's gooooo

s32 skMemCopy(void *dst, const void *src, size_t size) {
    memcpy(dst, src, size);

    return 0;
}
