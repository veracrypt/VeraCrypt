/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2009 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */


#include "Crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RNG defines & pool pointers */
#define RNG_POOL_SIZE	320	// Must be divisible by the size of the output of each of the implemented hash functions. (in bytes)

#if RNG_POOL_SIZE % SHA512_DIGESTSIZE || RNG_POOL_SIZE % WHIRLPOOL_DIGESTSIZE || RNG_POOL_SIZE % RIPEMD160_DIGESTSIZE
#error RNG_POOL_SIZE must be divisible by the size of the output of each of the implemented hash functions.
#endif

#define RANDOMPOOL_ALLOCSIZE	RNG_POOL_SIZE

// After every RANDMIX_BYTE_INTERVAL-th byte written to the pool, the pool mixing function is applied to the entire pool
#define RANDMIX_BYTE_INTERVAL	16

// FastPoll interval (in milliseconds)
#define FASTPOLL_INTERVAL		500

void RandAddInt ( unsigned __int32 x );
int Randinit ( void );
void RandStop (BOOL freePool);
BOOL IsRandomNumberGeneratorStarted ();
void RandSetHashFunction ( int hash_algo_id );
int RandGetHashFunction (void);
void SetRandomPoolEnrichedByUserStatus (BOOL enriched);
BOOL IsRandomPoolEnrichedByUser ();
BOOL Randmix ( void );
void RandaddBuf ( void *buf , int len );
BOOL FastPoll ( void );
BOOL SlowPoll ( void );
BOOL RandpeekBytes ( unsigned char *buf , int len );
BOOL RandgetBytes ( unsigned char *buf , int len, BOOL forceSlowPoll );

#ifdef _WIN32

extern BOOL volatile bFastPollEnabled;
extern BOOL volatile bRandmixEnabled;

LRESULT CALLBACK MouseProc ( int nCode , WPARAM wParam , LPARAM lParam );
LRESULT CALLBACK KeyboardProc ( int nCode , WPARAM wParam , LPARAM lParam );
static unsigned __stdcall PeriodicFastPollThreadProc (void *dummy);

#endif

#ifdef __cplusplus
}
#endif
