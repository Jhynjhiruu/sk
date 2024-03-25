#ifndef _API_H
#define _API_H

#include <bbtypes.h>

s32 skGetId(BbId *);

s32 skLaunchSetup(BbTicketBundle *, BbAppLaunchCrls *, RecryptList *);

s32 skLaunch(void *);

s32 skRecryptListValid(RecryptList *);

s32 skRecryptBegin(BbTicketBundle *, BbAppLaunchCrls *, RecryptList *);

s32 skRecryptData(u8 *, u32);

s32 skRecryptComputeState(u8 *, u32);

s32 skRecryptEnd(RecryptList *);

s32 skSignHash(BbShaHash *, BbEccSig *);

s32 skVerifyHash(BbShaHash *, BbGenericSig *, BbCertBase **, BbAppLaunchCrls *);

s32 skGetConsumption(u16 *, u16 *);

s32 skAdvanceTicketWindow(void);

s32 skSetLimit(u16, u16);

s32 skExit(void);

s32 skKeepAlive(void);

// signatures for the debug calls can't be determined

s32 skGetRandomKeyData();

s32 skDumpVirage();

s32 skTest2();

s32 skTest3();

s32 skResetWindow();

s32 skValidateRls();

// custom SKCs!

s32 skMemCopy(void *, const void *, size_t);

#endif