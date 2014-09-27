/*
 ---------------------------------------------------------------------------
 Copyright (c) 1999, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------

 My thanks to Doug Whiting and Niels Ferguson for comments that led
 to improvements in this implementation.

 Issue Date: 14th January 1999
*/

/* Adapted for TrueCrypt */


#ifdef TC_WINDOWS_BOOT
#pragma optimize ("tl", on)
#endif

#include "Twofish.h"
#include "Common/Endian.h"

#define Q_TABLES
#define M_TABLE

#if !defined (TC_MINIMIZE_CODE_SIZE) || defined (TC_WINDOWS_BOOT_TWOFISH)
#	define MK_TABLE
#	define ONE_STEP
#endif

/* finite field arithmetic for GF(2**8) with the modular    */
/* polynomial x^8 + x^6 + x^5 + x^3 + 1 (0x169)             */

#define G_M 0x0169

static u1byte  tab_5b[4] = { 0, G_M >> 2, G_M >> 1, (G_M >> 1) ^ (G_M >> 2) };
static u1byte  tab_ef[4] = { 0, (G_M >> 1) ^ (G_M >> 2), G_M >> 1, G_M >> 2 };

#define ffm_01(x)    (x)
#define ffm_5b(x)   ((x) ^ ((x) >> 2) ^ tab_5b[(x) & 3])
#define ffm_ef(x)   ((x) ^ ((x) >> 1) ^ ((x) >> 2) ^ tab_ef[(x) & 3])

static u1byte ror4[16] = { 0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15 };
static u1byte ashx[16] = { 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7 };

static u1byte qt0[2][16] = 
{   { 8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4 },
    { 2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5 }
};

static u1byte qt1[2][16] =
{   { 14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13 }, 
    { 1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8 }
};

static u1byte qt2[2][16] = 
{   { 11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1 },
    { 4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15 }
};

static u1byte qt3[2][16] = 
{   { 13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10 },
    { 11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10 }
};
 
static u1byte qp(const u4byte n, const u1byte x)
{   u1byte  a0, a1, a2, a3, a4, b0, b1, b2, b3, b4;

    a0 = x >> 4; b0 = x & 15;
    a1 = a0 ^ b0; b1 = ror4[b0] ^ ashx[a0];
    a2 = qt0[n][a1]; b2 = qt1[n][b1];
    a3 = a2 ^ b2; b3 = ror4[b2] ^ ashx[a2];
    a4 = qt2[n][a3]; b4 = qt3[n][b3];
    return (b4 << 4) | a4;
};

#ifdef  Q_TABLES

static u4byte  qt_gen = 0;
static u1byte  q_tab[2][256];

#define q(n,x)  q_tab[n][x]

static void gen_qtab(void)
{   u4byte  i;

    for(i = 0; i < 256; ++i)
    {       
        q(0,i) = qp(0, (u1byte)i);
        q(1,i) = qp(1, (u1byte)i);
    }
};

#else

#define q(n,x)  qp(n, x)

#endif

#ifdef  M_TABLE

static u4byte  mt_gen = 0;
static u4byte  m_tab[4][256];

static void gen_mtab(void)
{   u4byte  i, f01, f5b, fef;
    
    for(i = 0; i < 256; ++i)
    {
        f01 = q(1,i); f5b = ffm_5b(f01); fef = ffm_ef(f01);
        m_tab[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24);
        m_tab[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24);

        f01 = q(0,i); f5b = ffm_5b(f01); fef = ffm_ef(f01);
        m_tab[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24);
        m_tab[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24);
    }
};

#define mds(n,x)    m_tab[n][x]

#else

#define fm_00   ffm_01
#define fm_10   ffm_5b
#define fm_20   ffm_ef
#define fm_30   ffm_ef
#define q_0(x)  q(1,x)

#define fm_01   ffm_ef
#define fm_11   ffm_ef
#define fm_21   ffm_5b
#define fm_31   ffm_01
#define q_1(x)  q(0,x)

#define fm_02   ffm_5b
#define fm_12   ffm_ef
#define fm_22   ffm_01
#define fm_32   ffm_ef
#define q_2(x)  q(1,x)

#define fm_03   ffm_5b
#define fm_13   ffm_01
#define fm_23   ffm_ef
#define fm_33   ffm_5b
#define q_3(x)  q(0,x)

#define f_0(n,x)    ((u4byte)fm_0##n(x))
#define f_1(n,x)    ((u4byte)fm_1##n(x) << 8)
#define f_2(n,x)    ((u4byte)fm_2##n(x) << 16)
#define f_3(n,x)    ((u4byte)fm_3##n(x) << 24)

#define mds(n,x)    f_0(n,q_##n(x)) ^ f_1(n,q_##n(x)) ^ f_2(n,q_##n(x)) ^ f_3(n,q_##n(x))

#endif

static u4byte h_fun(TwofishInstance *instance, const u4byte x, const u4byte key[])
{   u4byte  b0, b1, b2, b3;

#ifndef M_TABLE
    u4byte  m5b_b0, m5b_b1, m5b_b2, m5b_b3;
    u4byte  mef_b0, mef_b1, mef_b2, mef_b3;
#endif

    b0 = extract_byte(x, 0); b1 = extract_byte(x, 1); b2 = extract_byte(x, 2); b3 = extract_byte(x, 3);

    switch(instance->k_len)
    {
    case 4: b0 = q(1, (u1byte) b0) ^ extract_byte(key[3],0);
            b1 = q(0, (u1byte) b1) ^ extract_byte(key[3],1);
            b2 = q(0, (u1byte) b2) ^ extract_byte(key[3],2);
            b3 = q(1, (u1byte) b3) ^ extract_byte(key[3],3);
    case 3: b0 = q(1, (u1byte) b0) ^ extract_byte(key[2],0);
            b1 = q(1, (u1byte) b1) ^ extract_byte(key[2],1);
            b2 = q(0, (u1byte) b2) ^ extract_byte(key[2],2);
            b3 = q(0, (u1byte) b3) ^ extract_byte(key[2],3);
    case 2: b0 = q(0, (u1byte) (q(0, (u1byte) b0) ^ extract_byte(key[1],0))) ^ extract_byte(key[0],0);
            b1 = q(0, (u1byte) (q(1, (u1byte) b1) ^ extract_byte(key[1],1))) ^ extract_byte(key[0],1);
            b2 = q(1, (u1byte) (q(0, (u1byte) b2) ^ extract_byte(key[1],2))) ^ extract_byte(key[0],2);
            b3 = q(1, (u1byte) (q(1, (u1byte) b3) ^ extract_byte(key[1],3))) ^ extract_byte(key[0],3);
    }
#ifdef  M_TABLE

    return  mds(0, b0) ^ mds(1, b1) ^ mds(2, b2) ^ mds(3, b3);

#else

    b0 = q(1, (u1byte) b0); b1 = q(0, (u1byte) b1); b2 = q(1, (u1byte) b2); b3 = q(0, (u1byte) b3);
    m5b_b0 = ffm_5b(b0); m5b_b1 = ffm_5b(b1); m5b_b2 = ffm_5b(b2); m5b_b3 = ffm_5b(b3);
    mef_b0 = ffm_ef(b0); mef_b1 = ffm_ef(b1); mef_b2 = ffm_ef(b2); mef_b3 = ffm_ef(b3);
    b0 ^= mef_b1 ^ m5b_b2 ^ m5b_b3; b3 ^= m5b_b0 ^ mef_b1 ^ mef_b2;
    b2 ^= mef_b0 ^ m5b_b1 ^ mef_b3; b1 ^= mef_b0 ^ mef_b2 ^ m5b_b3;

    return b0 | (b3 << 8) | (b2 << 16) | (b1 << 24);

#endif
};

#ifdef  MK_TABLE

#ifdef  ONE_STEP
//u4byte  mk_tab[4][256];
#else
static u1byte  sb[4][256];
#endif

#define q20(x)  q(0,q(0,x) ^ extract_byte(key[1],0)) ^ extract_byte(key[0],0)
#define q21(x)  q(0,q(1,x) ^ extract_byte(key[1],1)) ^ extract_byte(key[0],1)
#define q22(x)  q(1,q(0,x) ^ extract_byte(key[1],2)) ^ extract_byte(key[0],2)
#define q23(x)  q(1,q(1,x) ^ extract_byte(key[1],3)) ^ extract_byte(key[0],3)

#define q30(x)  q(0,q(0,q(1, x) ^ extract_byte(key[2],0)) ^ extract_byte(key[1],0)) ^ extract_byte(key[0],0)
#define q31(x)  q(0,q(1,q(1, x) ^ extract_byte(key[2],1)) ^ extract_byte(key[1],1)) ^ extract_byte(key[0],1)
#define q32(x)  q(1,q(0,q(0, x) ^ extract_byte(key[2],2)) ^ extract_byte(key[1],2)) ^ extract_byte(key[0],2)
#define q33(x)  q(1,q(1,q(0, x) ^ extract_byte(key[2],3)) ^ extract_byte(key[1],3)) ^ extract_byte(key[0],3)

#define q40(x)  q(0,q(0,q(1, q(1, x) ^ extract_byte(key[3],0)) ^ extract_byte(key[2],0)) ^ extract_byte(key[1],0)) ^ extract_byte(key[0],0)
#define q41(x)  q(0,q(1,q(1, q(0, x) ^ extract_byte(key[3],1)) ^ extract_byte(key[2],1)) ^ extract_byte(key[1],1)) ^ extract_byte(key[0],1)
#define q42(x)  q(1,q(0,q(0, q(0, x) ^ extract_byte(key[3],2)) ^ extract_byte(key[2],2)) ^ extract_byte(key[1],2)) ^ extract_byte(key[0],2)
#define q43(x)  q(1,q(1,q(0, q(1, x) ^ extract_byte(key[3],3)) ^ extract_byte(key[2],3)) ^ extract_byte(key[1],3)) ^ extract_byte(key[0],3)

static void gen_mk_tab(TwofishInstance *instance, u4byte key[])
{   u4byte  i;
    u1byte  by;

	u4byte *mk_tab = instance->mk_tab;

    switch(instance->k_len)
    {
    case 2: for(i = 0; i < 256; ++i)
            {
                by = (u1byte)i;
#ifdef ONE_STEP
                mk_tab[0 + 4*i] = mds(0, q20(by)); mk_tab[1 + 4*i] = mds(1, q21(by));
                mk_tab[2 + 4*i] = mds(2, q22(by)); mk_tab[3 + 4*i] = mds(3, q23(by));
#else
                sb[0][i] = q20(by); sb[1][i] = q21(by); 
                sb[2][i] = q22(by); sb[3][i] = q23(by);
#endif
            }
            break;
    
    case 3: for(i = 0; i < 256; ++i)
            {
                by = (u1byte)i;
#ifdef ONE_STEP
                mk_tab[0 + 4*i] = mds(0, q30(by)); mk_tab[1 + 4*i] = mds(1, q31(by));
                mk_tab[2 + 4*i] = mds(2, q32(by)); mk_tab[3 + 4*i] = mds(3, q33(by));
#else
                sb[0][i] = q30(by); sb[1][i] = q31(by); 
                sb[2][i] = q32(by); sb[3][i] = q33(by);
#endif
            }
            break;
    
    case 4: for(i = 0; i < 256; ++i)
            {
                by = (u1byte)i;
#ifdef ONE_STEP
                mk_tab[0 + 4*i] = mds(0, q40(by)); mk_tab[1 + 4*i] = mds(1, q41(by));
                mk_tab[2 + 4*i] = mds(2, q42(by)); mk_tab[3 + 4*i] = mds(3, q43(by));
#else
                sb[0][i] = q40(by); sb[1][i] = q41(by); 
                sb[2][i] = q42(by); sb[3][i] = q43(by);
#endif
            }
    }
};

#  ifdef ONE_STEP
#    define g0_fun(x) ( mk_tab[0 + 4*extract_byte(x,0)] ^ mk_tab[1 + 4*extract_byte(x,1)] \
                      ^ mk_tab[2 + 4*extract_byte(x,2)] ^ mk_tab[3 + 4*extract_byte(x,3)] )
#    define g1_fun(x) ( mk_tab[0 + 4*extract_byte(x,3)] ^ mk_tab[1 + 4*extract_byte(x,0)] \
                      ^ mk_tab[2 + 4*extract_byte(x,1)] ^ mk_tab[3 + 4*extract_byte(x,2)] )


#  else
#    define g0_fun(x) ( mds(0, sb[0][extract_byte(x,0)]) ^ mds(1, sb[1][extract_byte(x,1)]) \
                      ^ mds(2, sb[2][extract_byte(x,2)]) ^ mds(3, sb[3][extract_byte(x,3)]) )
#    define g1_fun(x) ( mds(0, sb[0][extract_byte(x,3)]) ^ mds(1, sb[1][extract_byte(x,0)]) \
                      ^ mds(2, sb[2][extract_byte(x,1)]) ^ mds(3, sb[3][extract_byte(x,2)]) )
#  endif

#else

#define g0_fun(x)   h_fun(instance, x, instance->s_key)
#define g1_fun(x)   h_fun(instance, rotl(x,8), instance->s_key)

#endif

/* The (12,8) Reed Soloman code has the generator polynomial

  g(x) = x^4 + (a + 1/a) * x^3 + a * x^2 + (a + 1/a) * x + 1

where the coefficients are in the finite field GF(2^8) with a
modular polynomial a^8 + a^6 + a^3 + a^2 + 1. To generate the
remainder we have to start with a 12th order polynomial with our
eight input bytes as the coefficients of the 4th to 11th terms. 
That is:

  m[7] * x^11 + m[6] * x^10 ... + m[0] * x^4 + 0 * x^3 +... + 0
  
We then multiply the generator polynomial by m[7] * x^7 and subtract
it - xor in GF(2^8) - from the above to eliminate the x^7 term (the 
artihmetic on the coefficients is done in GF(2^8). We then multiply 
the generator polynomial by x^6 * coeff(x^10) and use this to remove
the x^10 term. We carry on in this way until the x^4 term is removed
so that we are left with:

  r[3] * x^3 + r[2] * x^2 + r[1] 8 x^1 + r[0]

which give the resulting 4 bytes of the remainder. This is equivalent 
to the matrix multiplication in the Twofish description but much faster 
to implement.

*/

#define G_MOD   0x0000014d

static u4byte mds_rem(u4byte p0, u4byte p1)
{   u4byte  i, t, u;

    for(i = 0; i < 8; ++i)
    {
        t = p1 >> 24;   // get most significant coefficient
        
        p1 = (p1 << 8) | (p0 >> 24); p0 <<= 8;  // shift others up
            
        // multiply t by a (the primitive element - i.e. left shift)

        u = (t << 1); 
        
        if(t & 0x80)            // subtract modular polynomial on overflow
        
            u ^= G_MOD; 

        p1 ^= t ^ (u << 16);    // remove t * (a * x^2 + 1)  

        u ^= (t >> 1);          // form u = a * t + t / a = t * (a + 1 / a); 
        
        if(t & 0x01)            // add the modular polynomial on underflow
        
            u ^= G_MOD >> 1;

        p1 ^= (u << 24) | (u << 8); // remove t * (a + 1/a) * (x^3 + x)
    }

    return p1;
};

/* initialise the key schedule from the user supplied key   */

u4byte *twofish_set_key(TwofishInstance *instance, const u4byte in_key[])
{   u4byte  i, a, b, me_key[4], mo_key[4];
	u4byte *l_key, *s_key;

	l_key = instance->l_key;
	s_key = instance->s_key;

#ifdef Q_TABLES
    if(!qt_gen)
    {
        gen_qtab(); qt_gen = 1;
    }
#endif

#ifdef M_TABLE
    if(!mt_gen)
    {
        gen_mtab(); mt_gen = 1;
    }
#endif

    instance->k_len = 4;

    for(i = 0; i < instance->k_len; ++i)
    {
        a = LE32(in_key[i + i]);     me_key[i] = a;
        b = LE32(in_key[i + i + 1]); mo_key[i] = b;
        s_key[instance->k_len - i - 1] = mds_rem(a, b);
    }

    for(i = 0; i < 40; i += 2)
    {
        a = 0x01010101 * i; b = a + 0x01010101;
        a = h_fun(instance, a, me_key);
        b = rotl(h_fun(instance, b, mo_key), 8);
        l_key[i] = a + b;
        l_key[i + 1] = rotl(a + 2 * b, 9);
    }

#ifdef MK_TABLE
    gen_mk_tab(instance, s_key);
#endif

    return l_key;
};

/* encrypt a block of text  */

#ifndef TC_MINIMIZE_CODE_SIZE

#define f_rnd(i)                                                    \
    t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);                       \
    blk[2] = rotr(blk[2] ^ (t0 + t1 + l_key[4 * (i) + 8]), 1);      \
    blk[3] = rotl(blk[3], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 9]);  \
    t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);                       \
    blk[0] = rotr(blk[0] ^ (t0 + t1 + l_key[4 * (i) + 10]), 1);     \
    blk[1] = rotl(blk[1], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 11])

void twofish_encrypt(TwofishInstance *instance, const u4byte in_blk[4], u4byte out_blk[])
{   u4byte  t0, t1, blk[4];

	u4byte *l_key = instance->l_key;
	u4byte *mk_tab = instance->mk_tab;

	blk[0] = LE32(in_blk[0]) ^ l_key[0];
    blk[1] = LE32(in_blk[1]) ^ l_key[1];
    blk[2] = LE32(in_blk[2]) ^ l_key[2];
    blk[3] = LE32(in_blk[3]) ^ l_key[3];

    f_rnd(0); f_rnd(1); f_rnd(2); f_rnd(3);
    f_rnd(4); f_rnd(5); f_rnd(6); f_rnd(7);

    out_blk[0] = LE32(blk[2] ^ l_key[4]);
    out_blk[1] = LE32(blk[3] ^ l_key[5]);
    out_blk[2] = LE32(blk[0] ^ l_key[6]);
    out_blk[3] = LE32(blk[1] ^ l_key[7]); 
};

#else // TC_MINIMIZE_CODE_SIZE

void twofish_encrypt(TwofishInstance *instance, const u4byte in_blk[4], u4byte out_blk[])
{   u4byte  t0, t1, blk[4];

	u4byte *l_key = instance->l_key;
#ifdef TC_WINDOWS_BOOT_TWOFISH
	u4byte *mk_tab = instance->mk_tab;
#endif
	int i;

	blk[0] = LE32(in_blk[0]) ^ l_key[0];
    blk[1] = LE32(in_blk[1]) ^ l_key[1];
    blk[2] = LE32(in_blk[2]) ^ l_key[2];
    blk[3] = LE32(in_blk[3]) ^ l_key[3];

	for (i = 0; i <= 7; ++i)
	{
		t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);
		blk[2] = rotr(blk[2] ^ (t0 + t1 + l_key[4 * (i) + 8]), 1);
		blk[3] = rotl(blk[3], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 9]);
		t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);
		blk[0] = rotr(blk[0] ^ (t0 + t1 + l_key[4 * (i) + 10]), 1);
		blk[1] = rotl(blk[1], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 11]);
	}

    out_blk[0] = LE32(blk[2] ^ l_key[4]);
    out_blk[1] = LE32(blk[3] ^ l_key[5]);
    out_blk[2] = LE32(blk[0] ^ l_key[6]);
    out_blk[3] = LE32(blk[1] ^ l_key[7]); 
};

#endif // TC_MINIMIZE_CODE_SIZE

/* decrypt a block of text  */

#ifndef TC_MINIMIZE_CODE_SIZE

#define i_rnd(i)                                                        \
        t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);                       \
        blk[2] = rotl(blk[2], 1) ^ (t0 + t1 + l_key[4 * (i) + 10]);     \
        blk[3] = rotr(blk[3] ^ (t0 + 2 * t1 + l_key[4 * (i) + 11]), 1); \
        t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);                       \
        blk[0] = rotl(blk[0], 1) ^ (t0 + t1 + l_key[4 * (i) +  8]);     \
        blk[1] = rotr(blk[1] ^ (t0 + 2 * t1 + l_key[4 * (i) +  9]), 1)

void twofish_decrypt(TwofishInstance *instance, const u4byte in_blk[4], u4byte out_blk[4])
{   u4byte  t0, t1, blk[4];

	u4byte *l_key = instance->l_key;
	u4byte *mk_tab = instance->mk_tab;

    blk[0] = LE32(in_blk[0]) ^ l_key[4];
    blk[1] = LE32(in_blk[1]) ^ l_key[5];
    blk[2] = LE32(in_blk[2]) ^ l_key[6];
    blk[3] = LE32(in_blk[3]) ^ l_key[7];

    i_rnd(7); i_rnd(6); i_rnd(5); i_rnd(4);
    i_rnd(3); i_rnd(2); i_rnd(1); i_rnd(0);

    out_blk[0] = LE32(blk[2] ^ l_key[0]);
    out_blk[1] = LE32(blk[3] ^ l_key[1]);
    out_blk[2] = LE32(blk[0] ^ l_key[2]);
    out_blk[3] = LE32(blk[1] ^ l_key[3]); 
};

#else // TC_MINIMIZE_CODE_SIZE

void twofish_decrypt(TwofishInstance *instance, const u4byte in_blk[4], u4byte out_blk[4])
{   u4byte  t0, t1, blk[4];

	u4byte *l_key = instance->l_key;
#ifdef TC_WINDOWS_BOOT_TWOFISH
	u4byte *mk_tab = instance->mk_tab;
#endif
	int i;

    blk[0] = LE32(in_blk[0]) ^ l_key[4];
    blk[1] = LE32(in_blk[1]) ^ l_key[5];
    blk[2] = LE32(in_blk[2]) ^ l_key[6];
    blk[3] = LE32(in_blk[3]) ^ l_key[7];

	for (i = 7; i >= 0; --i)
	{
		t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);
		blk[2] = rotl(blk[2], 1) ^ (t0 + t1 + l_key[4 * (i) + 10]);
		blk[3] = rotr(blk[3] ^ (t0 + 2 * t1 + l_key[4 * (i) + 11]), 1);
		t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);
		blk[0] = rotl(blk[0], 1) ^ (t0 + t1 + l_key[4 * (i) +  8]);
		blk[1] = rotr(blk[1] ^ (t0 + 2 * t1 + l_key[4 * (i) +  9]), 1);
	}

    out_blk[0] = LE32(blk[2] ^ l_key[0]);
    out_blk[1] = LE32(blk[3] ^ l_key[1]);
    out_blk[2] = LE32(blk[0] ^ l_key[2]);
    out_blk[3] = LE32(blk[1] ^ l_key[3]); 
};

#endif // TC_MINIMIZE_CODE_SIZE
