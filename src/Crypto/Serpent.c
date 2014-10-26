// serpent.cpp - written and placed in the public domain by Wei Dai

/* Adapted for TrueCrypt */

#ifdef TC_WINDOWS_BOOT
#pragma optimize ("t", on)
#endif

#include "Serpent.h"
#include "Common/Endian.h"

#include <memory.h>

#if defined(_WIN32) && !defined(_DEBUG)
#include <stdlib.h>
#define rotlFixed _rotl
#define rotrFixed _rotr
#else
#define rotlFixed(x,n)   (((x) << (n)) | ((x) >> (32 - (n))))
#define rotrFixed(x,n)   (((x) >> (n)) | ((x) << (32 - (n))))
#endif

// linear transformation
#define LT(i,a,b,c,d,e)	{\
	a = rotlFixed(a, 13);	\
	c = rotlFixed(c, 3); 	\
	d = rotlFixed(d ^ c ^ (a << 3), 7); 	\
	b = rotlFixed(b ^ a ^ c, 1); 	\
	a = rotlFixed(a ^ b ^ d, 5); 		\
	c = rotlFixed(c ^ d ^ (b << 7), 22);}

// inverse linear transformation
#define ILT(i,a,b,c,d,e)	{\
	c = rotrFixed(c, 22);	\
	a = rotrFixed(a, 5); 	\
	c ^= d ^ (b << 7);	\
	a ^= b ^ d; 		\
	b = rotrFixed(b, 1); 	\
	d = rotrFixed(d, 7) ^ c ^ (a << 3);	\
	b ^= a ^ c; 		\
	c = rotrFixed(c, 3); 	\
	a = rotrFixed(a, 13);}

// order of output from S-box functions
#define beforeS0(f) f(0,a,b,c,d,e)
#define afterS0(f) f(1,b,e,c,a,d)
#define afterS1(f) f(2,c,b,a,e,d)
#define afterS2(f) f(3,a,e,b,d,c)
#define afterS3(f) f(4,e,b,d,c,a)
#define afterS4(f) f(5,b,a,e,c,d)
#define afterS5(f) f(6,a,c,b,e,d)
#define afterS6(f) f(7,a,c,d,b,e)
#define afterS7(f) f(8,d,e,b,a,c)

// order of output from inverse S-box functions
#define beforeI7(f) f(8,a,b,c,d,e)
#define afterI7(f) f(7,d,a,b,e,c)
#define afterI6(f) f(6,a,b,c,e,d)
#define afterI5(f) f(5,b,d,e,c,a)
#define afterI4(f) f(4,b,c,e,a,d)
#define afterI3(f) f(3,a,b,e,c,d)
#define afterI2(f) f(2,b,d,e,c,a)
#define afterI1(f) f(1,a,b,c,e,d)
#define afterI0(f) f(0,a,d,b,e,c)

// The instruction sequences for the S-box functions 
// come from Dag Arne Osvik's paper "Speeding up Serpent".

#define S0(i, r0, r1, r2, r3, r4) \
       {           \
    r3 ^= r0;   \
    r4 = r1;   \
    r1 &= r3;   \
    r4 ^= r2;   \
    r1 ^= r0;   \
    r0 |= r3;   \
    r0 ^= r4;   \
    r4 ^= r3;   \
    r3 ^= r2;   \
    r2 |= r1;   \
    r2 ^= r4;   \
    r4 = ~r4;      \
    r4 |= r1;   \
    r1 ^= r3;   \
    r1 ^= r4;   \
    r3 |= r0;   \
    r1 ^= r3;   \
    r4 ^= r3;   \
            }

#define I0(i, r0, r1, r2, r3, r4) \
       {           \
    r2 = ~r2;      \
    r4 = r1;   \
    r1 |= r0;   \
    r4 = ~r4;      \
    r1 ^= r2;   \
    r2 |= r4;   \
    r1 ^= r3;   \
    r0 ^= r4;   \
    r2 ^= r0;   \
    r0 &= r3;   \
    r4 ^= r0;   \
    r0 |= r1;   \
    r0 ^= r2;   \
    r3 ^= r4;   \
    r2 ^= r1;   \
    r3 ^= r0;   \
    r3 ^= r1;   \
    r2 &= r3;   \
    r4 ^= r2;   \
            }

#define S1(i, r0, r1, r2, r3, r4) \
       {           \
    r0 = ~r0;      \
    r2 = ~r2;      \
    r4 = r0;   \
    r0 &= r1;   \
    r2 ^= r0;   \
    r0 |= r3;   \
    r3 ^= r2;   \
    r1 ^= r0;   \
    r0 ^= r4;   \
    r4 |= r1;   \
    r1 ^= r3;   \
    r2 |= r0;   \
    r2 &= r4;   \
    r0 ^= r1;   \
    r1 &= r2;   \
    r1 ^= r0;   \
    r0 &= r2;   \
    r0 ^= r4;   \
            }

#define I1(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r1;   \
    r1 ^= r3;   \
    r3 &= r1;   \
    r4 ^= r2;   \
    r3 ^= r0;   \
    r0 |= r1;   \
    r2 ^= r3;   \
    r0 ^= r4;   \
    r0 |= r2;   \
    r1 ^= r3;   \
    r0 ^= r1;   \
    r1 |= r3;   \
    r1 ^= r0;   \
    r4 = ~r4;      \
    r4 ^= r1;   \
    r1 |= r0;   \
    r1 ^= r0;   \
    r1 |= r4;   \
    r3 ^= r1;   \
            }

#define S2(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r0;   \
    r0 &= r2;   \
    r0 ^= r3;   \
    r2 ^= r1;   \
    r2 ^= r0;   \
    r3 |= r4;   \
    r3 ^= r1;   \
    r4 ^= r2;   \
    r1 = r3;   \
    r3 |= r4;   \
    r3 ^= r0;   \
    r0 &= r1;   \
    r4 ^= r0;   \
    r1 ^= r3;   \
    r1 ^= r4;   \
    r4 = ~r4;      \
            }

#define I2(i, r0, r1, r2, r3, r4) \
       {           \
    r2 ^= r3;   \
    r3 ^= r0;   \
    r4 = r3;   \
    r3 &= r2;   \
    r3 ^= r1;   \
    r1 |= r2;   \
    r1 ^= r4;   \
    r4 &= r3;   \
    r2 ^= r3;   \
    r4 &= r0;   \
    r4 ^= r2;   \
    r2 &= r1;   \
    r2 |= r0;   \
    r3 = ~r3;      \
    r2 ^= r3;   \
    r0 ^= r3;   \
    r0 &= r1;   \
    r3 ^= r4;   \
    r3 ^= r0;   \
            }

#define S3(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r0;   \
    r0 |= r3;   \
    r3 ^= r1;   \
    r1 &= r4;   \
    r4 ^= r2;   \
    r2 ^= r3;   \
    r3 &= r0;   \
    r4 |= r1;   \
    r3 ^= r4;   \
    r0 ^= r1;   \
    r4 &= r0;   \
    r1 ^= r3;   \
    r4 ^= r2;   \
    r1 |= r0;   \
    r1 ^= r2;   \
    r0 ^= r3;   \
    r2 = r1;   \
    r1 |= r3;   \
    r1 ^= r0;   \
            }

#define I3(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r2;   \
    r2 ^= r1;   \
    r1 &= r2;   \
    r1 ^= r0;   \
    r0 &= r4;   \
    r4 ^= r3;   \
    r3 |= r1;   \
    r3 ^= r2;   \
    r0 ^= r4;   \
    r2 ^= r0;   \
    r0 |= r3;   \
    r0 ^= r1;   \
    r4 ^= r2;   \
    r2 &= r3;   \
    r1 |= r3;   \
    r1 ^= r2;   \
    r4 ^= r0;   \
    r2 ^= r4;   \
            }

#define S4(i, r0, r1, r2, r3, r4) \
       {           \
    r1 ^= r3;   \
    r3 = ~r3;      \
    r2 ^= r3;   \
    r3 ^= r0;   \
    r4 = r1;   \
    r1 &= r3;   \
    r1 ^= r2;   \
    r4 ^= r3;   \
    r0 ^= r4;   \
    r2 &= r4;   \
    r2 ^= r0;   \
    r0 &= r1;   \
    r3 ^= r0;   \
    r4 |= r1;   \
    r4 ^= r0;   \
    r0 |= r3;   \
    r0 ^= r2;   \
    r2 &= r3;   \
    r0 = ~r0;      \
    r4 ^= r2;   \
            }

#define I4(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r2;   \
    r2 &= r3;   \
    r2 ^= r1;   \
    r1 |= r3;   \
    r1 &= r0;   \
    r4 ^= r2;   \
    r4 ^= r1;   \
    r1 &= r2;   \
    r0 = ~r0;      \
    r3 ^= r4;   \
    r1 ^= r3;   \
    r3 &= r0;   \
    r3 ^= r2;   \
    r0 ^= r1;   \
    r2 &= r0;   \
    r3 ^= r0;   \
    r2 ^= r4;   \
    r2 |= r3;   \
    r3 ^= r0;   \
    r2 ^= r1;   \
            }

#define S5(i, r0, r1, r2, r3, r4) \
       {           \
    r0 ^= r1;   \
    r1 ^= r3;   \
    r3 = ~r3;      \
    r4 = r1;   \
    r1 &= r0;   \
    r2 ^= r3;   \
    r1 ^= r2;   \
    r2 |= r4;   \
    r4 ^= r3;   \
    r3 &= r1;   \
    r3 ^= r0;   \
    r4 ^= r1;   \
    r4 ^= r2;   \
    r2 ^= r0;   \
    r0 &= r3;   \
    r2 = ~r2;      \
    r0 ^= r4;   \
    r4 |= r3;   \
    r2 ^= r4;   \
            }

#define I5(i, r0, r1, r2, r3, r4) \
       {           \
    r1 = ~r1;      \
    r4 = r3;   \
    r2 ^= r1;   \
    r3 |= r0;   \
    r3 ^= r2;   \
    r2 |= r1;   \
    r2 &= r0;   \
    r4 ^= r3;   \
    r2 ^= r4;   \
    r4 |= r0;   \
    r4 ^= r1;   \
    r1 &= r2;   \
    r1 ^= r3;   \
    r4 ^= r2;   \
    r3 &= r4;   \
    r4 ^= r1;   \
    r3 ^= r0;   \
    r3 ^= r4;   \
    r4 = ~r4;      \
            }

#define S6(i, r0, r1, r2, r3, r4) \
       {           \
    r2 = ~r2;      \
    r4 = r3;   \
    r3 &= r0;   \
    r0 ^= r4;   \
    r3 ^= r2;   \
    r2 |= r4;   \
    r1 ^= r3;   \
    r2 ^= r0;   \
    r0 |= r1;   \
    r2 ^= r1;   \
    r4 ^= r0;   \
    r0 |= r3;   \
    r0 ^= r2;   \
    r4 ^= r3;   \
    r4 ^= r0;   \
    r3 = ~r3;      \
    r2 &= r4;   \
    r2 ^= r3;   \
            }

#define I6(i, r0, r1, r2, r3, r4) \
       {           \
    r0 ^= r2;   \
    r4 = r2;   \
    r2 &= r0;   \
    r4 ^= r3;   \
    r2 = ~r2;      \
    r3 ^= r1;   \
    r2 ^= r3;   \
    r4 |= r0;   \
    r0 ^= r2;   \
    r3 ^= r4;   \
    r4 ^= r1;   \
    r1 &= r3;   \
    r1 ^= r0;   \
    r0 ^= r3;   \
    r0 |= r2;   \
    r3 ^= r1;   \
    r4 ^= r0;   \
            }

#define S7(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r2;   \
    r2 &= r1;   \
    r2 ^= r3;   \
    r3 &= r1;   \
    r4 ^= r2;   \
    r2 ^= r1;   \
    r1 ^= r0;   \
    r0 |= r4;   \
    r0 ^= r2;   \
    r3 ^= r1;   \
    r2 ^= r3;   \
    r3 &= r0;   \
    r3 ^= r4;   \
    r4 ^= r2;   \
    r2 &= r0;   \
    r4 = ~r4;      \
    r2 ^= r4;   \
    r4 &= r0;   \
    r1 ^= r3;   \
    r4 ^= r1;   \
            }

#define I7(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r2;   \
    r2 ^= r0;   \
    r0 &= r3;   \
    r2 = ~r2;      \
    r4 |= r3;   \
    r3 ^= r1;   \
    r1 |= r0;   \
    r0 ^= r2;   \
    r2 &= r4;   \
    r1 ^= r2;   \
    r2 ^= r0;   \
    r0 |= r2;   \
    r3 &= r4;   \
    r0 ^= r3;   \
    r4 ^= r1;   \
    r3 ^= r4;   \
    r4 |= r0;   \
    r3 ^= r2;   \
    r4 ^= r2;   \
            }

// key xor
#define KX(r, a, b, c, d, e)	{\
	a ^= k[4 * r + 0]; \
	b ^= k[4 * r + 1]; \
	c ^= k[4 * r + 2]; \
	d ^= k[4 * r + 3];}


#ifdef TC_MINIMIZE_CODE_SIZE

static void S0f (unsigned __int32 *r0, unsigned __int32 *r1, unsigned __int32 *r2, unsigned __int32 *r3, unsigned __int32 *r4)
{
	*r3 ^= *r0;
	*r4 = *r1;
	*r1 &= *r3;
	*r4 ^= *r2;
	*r1 ^= *r0;
	*r0 |= *r3;
	*r0 ^= *r4;
	*r4 ^= *r3;
	*r3 ^= *r2;
	*r2 |= *r1;
	*r2 ^= *r4;
	*r4 = ~*r4;
	*r4 |= *r1;
	*r1 ^= *r3;
	*r1 ^= *r4;
	*r3 |= *r0;
	*r1 ^= *r3;
	*r4 ^= *r3;
}

static void S1f (unsigned __int32 *r0, unsigned __int32 *r1, unsigned __int32 *r2, unsigned __int32 *r3, unsigned __int32 *r4)
{        
    *r0 = ~*r0;   
    *r2 = ~*r2;   
    *r4 = *r0;
    *r0 &= *r1;
    *r2 ^= *r0;
    *r0 |= *r3;
    *r3 ^= *r2;
    *r1 ^= *r0;
    *r0 ^= *r4;
    *r4 |= *r1;
    *r1 ^= *r3;
    *r2 |= *r0;
    *r2 &= *r4;
    *r0 ^= *r1;
    *r1 &= *r2;
    *r1 ^= *r0;
    *r0 &= *r2;
    *r0 ^= *r4;
}

static void S2f (unsigned __int32 *r0, unsigned __int32 *r1, unsigned __int32 *r2, unsigned __int32 *r3, unsigned __int32 *r4)
{        
	*r4 = *r0;
	*r0 &= *r2;
	*r0 ^= *r3;
	*r2 ^= *r1;
	*r2 ^= *r0;
	*r3 |= *r4;
	*r3 ^= *r1;
	*r4 ^= *r2;
	*r1 = *r3;
	*r3 |= *r4;
	*r3 ^= *r0;
	*r0 &= *r1;
	*r4 ^= *r0;
	*r1 ^= *r3;
	*r1 ^= *r4;
	*r4 = ~*r4;   
}

static void S3f (unsigned __int32 *r0, unsigned __int32 *r1, unsigned __int32 *r2, unsigned __int32 *r3, unsigned __int32 *r4)
{        
	*r4 = *r0;
	*r0 |= *r3;
	*r3 ^= *r1;
	*r1 &= *r4;
	*r4 ^= *r2;
	*r2 ^= *r3;
	*r3 &= *r0;
	*r4 |= *r1;
	*r3 ^= *r4;
	*r0 ^= *r1;
	*r4 &= *r0;
	*r1 ^= *r3;
	*r4 ^= *r2;
	*r1 |= *r0;
	*r1 ^= *r2;
	*r0 ^= *r3;
	*r2 = *r1;
	*r1 |= *r3;
	*r1 ^= *r0;
}

static void S4f (unsigned __int32 *r0, unsigned __int32 *r1, unsigned __int32 *r2, unsigned __int32 *r3, unsigned __int32 *r4)
{        
	*r1 ^= *r3;
	*r3 = ~*r3;   
	*r2 ^= *r3;
	*r3 ^= *r0;
	*r4 = *r1;
	*r1 &= *r3;
	*r1 ^= *r2;
	*r4 ^= *r3;
	*r0 ^= *r4;
	*r2 &= *r4;
	*r2 ^= *r0;
	*r0 &= *r1;
	*r3 ^= *r0;
	*r4 |= *r1;
	*r4 ^= *r0;
	*r0 |= *r3;
	*r0 ^= *r2;
	*r2 &= *r3;
	*r0 = ~*r0;   
	*r4 ^= *r2;
}

static void S5f (unsigned __int32 *r0, unsigned __int32 *r1, unsigned __int32 *r2, unsigned __int32 *r3, unsigned __int32 *r4)
{        
	*r0 ^= *r1;
	*r1 ^= *r3;
	*r3 = ~*r3;   
	*r4 = *r1;
	*r1 &= *r0;
	*r2 ^= *r3;
	*r1 ^= *r2;
	*r2 |= *r4;
	*r4 ^= *r3;
	*r3 &= *r1;
	*r3 ^= *r0;
	*r4 ^= *r1;
	*r4 ^= *r2;
	*r2 ^= *r0;
	*r0 &= *r3;
	*r2 = ~*r2;   
	*r0 ^= *r4;
	*r4 |= *r3;
	*r2 ^= *r4;
}

static void S6f (unsigned __int32 *r0, unsigned __int32 *r1, unsigned __int32 *r2, unsigned __int32 *r3, unsigned __int32 *r4)
{        
	*r2 = ~*r2;   
	*r4 = *r3;
	*r3 &= *r0;
	*r0 ^= *r4;
	*r3 ^= *r2;
	*r2 |= *r4;
	*r1 ^= *r3;
	*r2 ^= *r0;
	*r0 |= *r1;
	*r2 ^= *r1;
	*r4 ^= *r0;
	*r0 |= *r3;
	*r0 ^= *r2;
	*r4 ^= *r3;
	*r4 ^= *r0;
	*r3 = ~*r3;   
	*r2 &= *r4;
	*r2 ^= *r3;
}

static void S7f (unsigned __int32 *r0, unsigned __int32 *r1, unsigned __int32 *r2, unsigned __int32 *r3, unsigned __int32 *r4)
{        
	*r4 = *r2;
	*r2 &= *r1;
	*r2 ^= *r3;
	*r3 &= *r1;
	*r4 ^= *r2;
	*r2 ^= *r1;
	*r1 ^= *r0;
	*r0 |= *r4;
	*r0 ^= *r2;
	*r3 ^= *r1;
	*r2 ^= *r3;
	*r3 &= *r0;
	*r3 ^= *r4;
	*r4 ^= *r2;
	*r2 &= *r0;
	*r4 = ~*r4;   
	*r2 ^= *r4;
	*r4 &= *r0;
	*r1 ^= *r3;
	*r4 ^= *r1;
}

static void KXf (const unsigned __int32 *k, unsigned int r, unsigned __int32 *a, unsigned __int32 *b, unsigned __int32 *c, unsigned __int32 *d)
{
	*a ^= k[r];
	*b ^= k[r + 1];
	*c ^= k[r + 2];
	*d ^= k[r + 3];
}

#endif // TC_MINIMIZE_CODE_SIZE

#ifndef TC_MINIMIZE_CODE_SIZE

void serpent_set_key(const unsigned __int8 userKey[],unsigned __int8 *ks)
{
	unsigned __int32 a,b,c,d,e;
	unsigned __int32 *k = (unsigned __int32 *)ks;
	unsigned __int32 t;
	int i;

	for (i = 0; i < 8; i++)
		k[i] = LE32(((unsigned __int32*)userKey)[i]);

	k += 8;
	t = k[-1];
	for (i = 0; i < 132; ++i)
		k[i] = t = rotlFixed(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i, 11);
	k -= 20;

#define LK(r, a, b, c, d, e)	{\
	a = k[(8-r)*4 + 0];		\
	b = k[(8-r)*4 + 1];		\
	c = k[(8-r)*4 + 2];		\
	d = k[(8-r)*4 + 3];}

#define SK(r, a, b, c, d, e)	{\
	k[(8-r)*4 + 4] = a;		\
	k[(8-r)*4 + 5] = b;		\
	k[(8-r)*4 + 6] = c;		\
	k[(8-r)*4 + 7] = d;}	\

	for (i=0; i<4; i++)
	{
		afterS2(LK); afterS2(S3); afterS3(SK);
		afterS1(LK); afterS1(S2); afterS2(SK);
		afterS0(LK); afterS0(S1); afterS1(SK);
		beforeS0(LK); beforeS0(S0); afterS0(SK);
		k += 8*4;
		afterS6(LK); afterS6(S7); afterS7(SK);
		afterS5(LK); afterS5(S6); afterS6(SK);
		afterS4(LK); afterS4(S5); afterS5(SK);
		afterS3(LK); afterS3(S4); afterS4(SK);
	}
	afterS2(LK); afterS2(S3); afterS3(SK);
}

#else // TC_MINIMIZE_CODE_SIZE

static void LKf (unsigned __int32 *k, unsigned int r, unsigned __int32 *a, unsigned __int32 *b, unsigned __int32 *c, unsigned __int32 *d)
{
	*a = k[r];
	*b = k[r + 1];
	*c = k[r + 2];
	*d = k[r + 3];
}

static void SKf (unsigned __int32 *k, unsigned int r, unsigned __int32 *a, unsigned __int32 *b, unsigned __int32 *c, unsigned __int32 *d)
{
	k[r + 4] = *a;
	k[r + 5] = *b;
	k[r + 6] = *c;
	k[r + 7] = *d;
}

void serpent_set_key(const unsigned __int8 userKey[], unsigned __int8 *ks)
{
	unsigned __int32 a,b,c,d,e;
	unsigned __int32 *k = (unsigned __int32 *)ks;
	unsigned __int32 t;
	int i;

	for (i = 0; i < 8; i++)
		k[i] = LE32(((unsigned __int32*)userKey)[i]);

	k += 8;
	t = k[-1];
	for (i = 0; i < 132; ++i)
		k[i] = t = rotlFixed(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i, 11);
	k -= 20;

	for (i=0; i<4; i++)
	{
		LKf (k, 20, &a, &e, &b, &d); S3f (&a, &e, &b, &d, &c); SKf (k, 16, &e, &b, &d, &c);
		LKf (k, 24, &c, &b, &a, &e); S2f (&c, &b, &a, &e, &d); SKf (k, 20, &a, &e, &b, &d);
		LKf (k, 28, &b, &e, &c, &a); S1f (&b, &e, &c, &a, &d); SKf (k, 24, &c, &b, &a, &e);
		LKf (k, 32, &a, &b, &c, &d); S0f (&a, &b, &c, &d, &e); SKf (k, 28, &b, &e, &c, &a);
		k += 8*4;
		LKf (k,  4, &a, &c, &d, &b); S7f (&a, &c, &d, &b, &e); SKf (k,  0, &d, &e, &b, &a);
		LKf (k,  8, &a, &c, &b, &e); S6f (&a, &c, &b, &e, &d); SKf (k,  4, &a, &c, &d, &b);
		LKf (k, 12, &b, &a, &e, &c); S5f (&b, &a, &e, &c, &d); SKf (k,  8, &a, &c, &b, &e);
		LKf (k, 16, &e, &b, &d, &c); S4f (&e, &b, &d, &c, &a); SKf (k, 12, &b, &a, &e, &c);
	}
	LKf (k, 20, &a, &e, &b, &d); S3f (&a, &e, &b, &d, &c); SKf (k, 16, &e, &b, &d, &c);
}

#endif // TC_MINIMIZE_CODE_SIZE


#ifndef TC_MINIMIZE_CODE_SIZE

void serpent_encrypt(const unsigned __int8 *inBlock, unsigned __int8 *outBlock, unsigned __int8 *ks)
{
	unsigned __int32 a, b, c, d, e;
	unsigned int i=1;
	const unsigned __int32 *k = (unsigned __int32 *)ks + 8;
	unsigned __int32 *in = (unsigned __int32 *) inBlock;
	unsigned __int32 *out = (unsigned __int32 *) outBlock;

    a = LE32(in[0]);
	b = LE32(in[1]);
	c = LE32(in[2]);
	d = LE32(in[3]);

	do
	{
		beforeS0(KX); beforeS0(S0); afterS0(LT);
		afterS0(KX); afterS0(S1); afterS1(LT);
		afterS1(KX); afterS1(S2); afterS2(LT);
		afterS2(KX); afterS2(S3); afterS3(LT);
		afterS3(KX); afterS3(S4); afterS4(LT);
		afterS4(KX); afterS4(S5); afterS5(LT);
		afterS5(KX); afterS5(S6); afterS6(LT);
		afterS6(KX); afterS6(S7);

		if (i == 4)
			break;

		++i;
		c = b;
		b = e;
		e = d;
		d = a;
		a = e;
		k += 32;
		beforeS0(LT);
	}
	while (1);

	afterS7(KX);
	
    out[0] = LE32(d);
	out[1] = LE32(e);
	out[2] = LE32(b);
	out[3] = LE32(a);
}

#else // TC_MINIMIZE_CODE_SIZE

typedef unsigned __int32 uint32;

static void LTf (uint32 *a, uint32 *b, uint32 *c, uint32 *d)
{
	*a = rotlFixed(*a, 13);
	*c = rotlFixed(*c, 3);
	*d = rotlFixed(*d ^ *c ^ (*a << 3), 7);
	*b = rotlFixed(*b ^ *a ^ *c, 1);
	*a = rotlFixed(*a ^ *b ^ *d, 5);
	*c = rotlFixed(*c ^ *d ^ (*b << 7), 22);
}

void serpent_encrypt(const unsigned __int8 *inBlock, unsigned __int8 *outBlock, unsigned __int8 *ks)
{
	unsigned __int32 a, b, c, d, e;
	unsigned int i=1;
	const unsigned __int32 *k = (unsigned __int32 *)ks + 8;
	unsigned __int32 *in = (unsigned __int32 *) inBlock;
	unsigned __int32 *out = (unsigned __int32 *) outBlock;

    a = LE32(in[0]);
	b = LE32(in[1]);
	c = LE32(in[2]);
	d = LE32(in[3]);

	do
	{
		KXf (k,  0, &a, &b, &c, &d); S0f (&a, &b, &c, &d, &e); LTf (&b, &e, &c, &a);
		KXf (k,  4, &b, &e, &c, &a); S1f (&b, &e, &c, &a, &d); LTf (&c, &b, &a, &e);
		KXf (k,  8, &c, &b, &a, &e); S2f (&c, &b, &a, &e, &d); LTf (&a, &e, &b, &d);
		KXf (k, 12, &a, &e, &b, &d); S3f (&a, &e, &b, &d, &c); LTf (&e, &b, &d, &c);
		KXf (k, 16, &e, &b, &d, &c); S4f (&e, &b, &d, &c, &a); LTf (&b, &a, &e, &c);
		KXf (k, 20, &b, &a, &e, &c); S5f (&b, &a, &e, &c, &d); LTf (&a, &c, &b, &e);
		KXf (k, 24, &a, &c, &b, &e); S6f (&a, &c, &b, &e, &d); LTf (&a, &c, &d, &b);
		KXf (k, 28, &a, &c, &d, &b); S7f (&a, &c, &d, &b, &e);

		if (i == 4)
			break;

		++i;
		c = b;
		b = e;
		e = d;
		d = a;
		a = e;
		k += 32;
		LTf (&a,&b,&c,&d);
	}
	while (1);

	KXf (k, 32, &d, &e, &b, &a);
	
    out[0] = LE32(d);
	out[1] = LE32(e);
	out[2] = LE32(b);
	out[3] = LE32(a);
}

#endif // TC_MINIMIZE_CODE_SIZE

#if !defined (TC_MINIMIZE_CODE_SIZE)

void serpent_decrypt(const unsigned __int8 *inBlock, unsigned __int8 *outBlock, unsigned __int8 *ks)
{
	unsigned __int32 a, b, c, d, e;
	const unsigned __int32 *k = (unsigned __int32 *)ks + 104;
	unsigned int i=4;
	unsigned __int32 *in = (unsigned __int32 *) inBlock;
	unsigned __int32 *out = (unsigned __int32 *) outBlock;

    a = LE32(in[0]);
	b = LE32(in[1]);
	c = LE32(in[2]);
	d = LE32(in[3]);

	beforeI7(KX);
	goto start;

	do
	{
		c = b;
		b = d;
		d = e;
		k -= 32;
		beforeI7(ILT);
start:
		beforeI7(I7); afterI7(KX); 
		afterI7(ILT); afterI7(I6); afterI6(KX); 
		afterI6(ILT); afterI6(I5); afterI5(KX); 
		afterI5(ILT); afterI5(I4); afterI4(KX); 
		afterI4(ILT); afterI4(I3); afterI3(KX); 
		afterI3(ILT); afterI3(I2); afterI2(KX); 
		afterI2(ILT); afterI2(I1); afterI1(KX); 
		afterI1(ILT); afterI1(I0); afterI0(KX);
	}
	while (--i != 0);
	
    out[0] = LE32(a);
	out[1] = LE32(d);
	out[2] = LE32(b);
	out[3] = LE32(e);
}

#else // TC_MINIMIZE_CODE_SIZE

static void ILTf (uint32 *a, uint32 *b, uint32 *c, uint32 *d)
{ 
	*c = rotrFixed(*c, 22);
	*a = rotrFixed(*a, 5);
	*c ^= *d ^ (*b << 7);
	*a ^= *b ^ *d;
	*b = rotrFixed(*b, 1);
	*d = rotrFixed(*d, 7) ^ *c ^ (*a << 3);
	*b ^= *a ^ *c;
	*c = rotrFixed(*c, 3);
	*a = rotrFixed(*a, 13);
}

void serpent_decrypt(const unsigned __int8 *inBlock, unsigned __int8 *outBlock, unsigned __int8 *ks)
{
	unsigned __int32 a, b, c, d, e;
	const unsigned __int32 *k = (unsigned __int32 *)ks + 104;
	unsigned int i=4;
	unsigned __int32 *in = (unsigned __int32 *) inBlock;
	unsigned __int32 *out = (unsigned __int32 *) outBlock;

    a = LE32(in[0]);
	b = LE32(in[1]);
	c = LE32(in[2]);
	d = LE32(in[3]);

	KXf (k, 32, &a, &b, &c, &d);
	goto start;

	do
	{
		c = b;
		b = d;
		d = e;
		k -= 32;
		beforeI7(ILT);
start:
		beforeI7(I7); KXf (k, 28, &d, &a, &b, &e);
		ILTf (&d, &a, &b, &e); afterI7(I6); KXf (k, 24, &a, &b, &c, &e); 
		ILTf (&a, &b, &c, &e); afterI6(I5); KXf (k, 20, &b, &d, &e, &c); 
		ILTf (&b, &d, &e, &c); afterI5(I4); KXf (k, 16, &b, &c, &e, &a); 
		ILTf (&b, &c, &e, &a); afterI4(I3); KXf (k, 12, &a, &b, &e, &c);
		ILTf (&a, &b, &e, &c); afterI3(I2); KXf (k, 8,  &b, &d, &e, &c);
		ILTf (&b, &d, &e, &c); afterI2(I1); KXf (k, 4,  &a, &b, &c, &e);
		ILTf (&a, &b, &c, &e); afterI1(I0); KXf (k, 0,  &a, &d, &b, &e);
	}
	while (--i != 0);
	
    out[0] = LE32(a);
	out[1] = LE32(d);
	out[2] = LE32(b);
	out[3] = LE32(e);
}

#endif // TC_MINIMIZE_CODE_SIZE
