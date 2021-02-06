
/* Fragments of code removed, and small modifications made */

/*
**  BCRYPT - High speed un*x password encryption/compare routines
**  Originally written by VIz, modifications by Doctor Dissector
**
**  Filename   : bcrypt.c
**
**  Description: the actual bcrypt encryption engine and related functions
**
**  Updated    : 7/28/91
*/

/*=[ VIz's Original Disclaimer ]============================================*/

/*
**                             LARD
**                       "The power of LARD"
**                            by VIz
**
**  I am not responsible for any use of this program by anyone,
**  on any machine for any purpose, anywhere at anytime....
*/

/*=[ Testing ]==============================================================*/

/*
**  For testing purposes, bcrypt() can be called similarly to the original
**  crypt() function, as "char *bcrypt(char *plaintext, char *salt)".
**  This method is not an efficient method for cracking passwords, but
**  is a simple way to test bcrypt()'s results for validity.  In order
**  to enable this function, un-comment the definition "TESTING" in
**  the file bcrypt.h and re-compile.  Also, if you are testing under the
**  MS/PC-DOS environment with Turbo C, Turbo C++, Borland C++, or
**  Microsoft compilers, be sure to call the bcrypt_init() function before
**  the testing is done and bcrypt_done() when testing is complete.  For
**  full implementation details, see "Implementation" below.
*/

/*=[ Implementation ]=======================================================*/

/*
**  ----------------------------------------------
**  Example variables:
**
**      U32  SL[2];
**      BU64 pwcode, resultcode;
**      char pw[14];
**      int  match;
**  ----------------------------------------------
**  Before doing anything:
**
**      bcrypt_init();
**  ----------------------------------------------
**  For EACH account:
**
**      bcrypt_salt_to_E(pw[0], pw[1], SL);
**      pwcode=bcrypt_pw_to_BU64(pw+2);
**  ----------------------------------------------
**  For each new word:
**
**      bcrypt_set_word(word);
**  ----------------------------------------------
**  For each comparision:
**
**      resultcode=bcrypt_encode(SL[0], SL[1]);
**      if ((pwcode.L.U==resultcode.L.U) && (pwcode.R.U==resultcode.R.U))
**          match=1;
**      else
**          match=0;
**  ----------------------------------------------
**  After everything is done (MS/PC-DOS ONLY)
**
**      bcrypt_done();
**  ----------------------------------------------
*/

/*=[ Include Files ]========================================================*/

#ifdef _TURBO
#include <malloc.h>
#endif
#include "bcrypt.h"

/*=[ Static Variables ]=====================================================*/

static char KS[16][48];             /* Key Schedule */
static BU32 UKS[16][4];             /* Key Schedule In Alternate Form */

/* S-Boxes, S2, S3, S (S is master S-Box) */
static unsigned long S2[8][64];

#if defined(_MICROSOFT) || defined(_TURBO)
unsigned long *S3[4],               /* S-Box, far malloc'd form */
              *S[4];                /* Permuted S-Box S3, far-malloc'd form */
#else
unsigned long S3[4][4096],          /* S-Box */
              S[4][4096];           /* Permuted S-Box S3 */
#endif

/*==========================================================================*/

U32 CV0(INU)
    U32 INU;
{
    REG BU32 in, out;

    in.U=INU;
    out.U=0;
    out.N.b0=in.N.b4;
    out.N.b1=in.N.b10;
    out.N.b2=in.N.b0;
    out.N.b3=in.N.b6;
    out.N.b4=in.N.b1;
    out.N.b5=in.N.b7;
    out.N.b6=in.N.b2;
    out.N.b7=in.N.b8;
    out.N.b8=in.N.b9;
    out.N.b9=in.N.b3;
    out.N.b10=in.N.b11;
    out.N.b11=in.N.b5;

    return(out.U);
}

/*==========================================================================*/

U32 CV1(INU)
    U32 INU;
{
    REG BU32 in, out;

    in.U=INU;
    out.U=0;
    out.N.b0=in.N.b4;
    out.N.b1=in.N.b10;
    out.N.b2=in.N.b0;
    out.N.b3=in.N.b6;
    out.N.b4=in.N.b1;
    out.N.b5=in.N.b7;
    out.N.b6=in.N.b2;
    out.N.b7=in.N.b8;
    out.N.b8=in.N.b3;
    out.N.b9=in.N.b9;
    out.N.b10=in.N.b5;
    out.N.b11=in.N.b11;

    return(out.U);
}

/*==========================================================================*/

BU32 EN(in)
    BU32 in;
{
    REG BU32 out;

    out.N.b0=in.N.b14;
    out.N.b1=in.N.b30;
    out.N.b2=in.N.b31;
    out.N.b3=in.N.b15;
    out.N.b4=in.N.b0;
    out.N.b5=in.N.b16;
    out.N.b6=in.N.b1;
    out.N.b7=in.N.b17;
    out.N.b8=in.N.b2;
    out.N.b9=in.N.b18;
    out.N.b10=in.N.b3;
    out.N.b11=in.N.b19;
    out.N.b12=in.N.b4;
    out.N.b13=in.N.b20;
    out.N.b14=in.N.b5;
    out.N.b15=in.N.b21;
    out.N.b16=in.N.b6;
    out.N.b17=in.N.b22;
    out.N.b18=in.N.b7;
    out.N.b19=in.N.b23;
    out.N.b20=in.N.b8;
    out.N.b21=in.N.b24;
    out.N.b22=in.N.b9;
    out.N.b23=in.N.b25;
    out.N.b24=in.N.b10;
    out.N.b25=in.N.b26;
    out.N.b26=in.N.b11;
    out.N.b27=in.N.b27;
    out.N.b28=in.N.b12;
    out.N.b29=in.N.b28;
    out.N.b30=in.N.b13;
    out.N.b31=in.N.b29;

    return(out);
}

/*==========================================================================*/

BU32 DE(in)
    BU32 in;
{
    REG BU32 out;

    out.N.b0=in.N.b4;
    out.N.b1=in.N.b6;
    out.N.b2=in.N.b8;
    out.N.b3=in.N.b10;
    out.N.b4=in.N.b12;
    out.N.b5=in.N.b14;
    out.N.b6=in.N.b16;
    out.N.b7=in.N.b18;
    out.N.b8=in.N.b20;
    out.N.b9=in.N.b22;
    out.N.b10=in.N.b24;
    out.N.b11=in.N.b26;
    out.N.b12=in.N.b28;
    out.N.b13=in.N.b30;
    out.N.b14=in.N.b0;
    out.N.b15=in.N.b3;
    out.N.b16=in.N.b5;
    out.N.b17=in.N.b7;
    out.N.b18=in.N.b9;
    out.N.b19=in.N.b11;
    out.N.b20=in.N.b13;
    out.N.b21=in.N.b15;
    out.N.b22=in.N.b17;
    out.N.b23=in.N.b19;
    out.N.b24=in.N.b21;
    out.N.b25=in.N.b23;
    out.N.b26=in.N.b25;
    out.N.b27=in.N.b27;
    out.N.b28=in.N.b29;
    out.N.b29=in.N.b31;
    out.N.b30=in.N.b1;
    out.N.b31=in.N.b2;

    return(out);
}
/*==========================================================================*/

BU64 IP(B)
    BU64 B;
{
    REG BU64 Ret;

    Ret.L.N.b31=B.R.N.b6;
    Ret.L.N.b30=B.R.N.b14;
    Ret.L.N.b29=B.R.N.b22;
    Ret.L.N.b28=B.R.N.b30;
    Ret.L.N.b27=B.L.N.b6;
    Ret.L.N.b26=B.L.N.b14;
    Ret.L.N.b25=B.L.N.b22;
    Ret.L.N.b24=B.L.N.b30;
    Ret.L.N.b23=B.R.N.b4;
    Ret.L.N.b22=B.R.N.b12;
    Ret.L.N.b21=B.R.N.b20;
    Ret.L.N.b20=B.R.N.b28;
    Ret.L.N.b19=B.L.N.b4;
    Ret.L.N.b18=B.L.N.b12;
    Ret.L.N.b17=B.L.N.b20;
    Ret.L.N.b16=B.L.N.b28;
    Ret.L.N.b15=B.R.N.b2;
    Ret.L.N.b14=B.R.N.b10;
    Ret.L.N.b13=B.R.N.b18;
    Ret.L.N.b12=B.R.N.b26;
    Ret.L.N.b11=B.L.N.b2;
    Ret.L.N.b10=B.L.N.b10;
    Ret.L.N.b9=B.L.N.b18;
    Ret.L.N.b8=B.L.N.b26;
    Ret.L.N.b7=B.R.N.b0;
    Ret.L.N.b6=B.R.N.b8;
    Ret.L.N.b5=B.R.N.b16;
    Ret.L.N.b4=B.R.N.b24;
    Ret.L.N.b3=B.L.N.b0;
    Ret.L.N.b2=B.L.N.b8;
    Ret.L.N.b1=B.L.N.b16;
    Ret.L.N.b0=B.L.N.b24;

    Ret.R.N.b31=B.R.N.b7;
    Ret.R.N.b30=B.R.N.b15;
    Ret.R.N.b29=B.R.N.b23;
    Ret.R.N.b28=B.R.N.b31;
    Ret.R.N.b27=B.L.N.b7;
    Ret.R.N.b26=B.L.N.b15;
    Ret.R.N.b25=B.L.N.b23;
    Ret.R.N.b24=B.L.N.b31;
    Ret.R.N.b23=B.R.N.b5;
    Ret.R.N.b22=B.R.N.b13;
    Ret.R.N.b21=B.R.N.b21;
    Ret.R.N.b20=B.R.N.b29;
    Ret.R.N.b19=B.L.N.b5;
    Ret.R.N.b18=B.L.N.b13;
    Ret.R.N.b17=B.L.N.b21;
    Ret.R.N.b16=B.L.N.b29;
    Ret.R.N.b15=B.R.N.b3;
    Ret.R.N.b14=B.R.N.b11;
    Ret.R.N.b13=B.R.N.b19;
    Ret.R.N.b12=B.R.N.b27;
    Ret.R.N.b11=B.L.N.b3;
    Ret.R.N.b10=B.L.N.b11;
    Ret.R.N.b9=B.L.N.b19;
    Ret.R.N.b8=B.L.N.b27;
    Ret.R.N.b7=B.R.N.b1;
    Ret.R.N.b6=B.R.N.b9;
    Ret.R.N.b5=B.R.N.b17;
    Ret.R.N.b4=B.R.N.b25;
    Ret.R.N.b3=B.L.N.b1;
    Ret.R.N.b2=B.L.N.b9;
    Ret.R.N.b1=B.L.N.b17;
    Ret.R.N.b0=B.L.N.b25;

    return(Ret);
}

/*==========================================================================*/

BU64 FP(B)
    BU64 B;
{
    REG BU64 Ret;

    Ret.L.N.b31=B.R.N.b24;
    Ret.L.N.b30=B.L.N.b24;
    Ret.L.N.b29=B.R.N.b16;
    Ret.L.N.b28=B.L.N.b16;
    Ret.L.N.b27=B.R.N.b8;
    Ret.L.N.b26=B.L.N.b8;
    Ret.L.N.b25=B.R.N.b0;
    Ret.L.N.b24=B.L.N.b0;
    Ret.L.N.b23=B.R.N.b25;
    Ret.L.N.b22=B.L.N.b25;
    Ret.L.N.b21=B.R.N.b17;
    Ret.L.N.b20=B.L.N.b17;
    Ret.L.N.b19=B.R.N.b9;
    Ret.L.N.b18=B.L.N.b9;
    Ret.L.N.b17=B.R.N.b1;
    Ret.L.N.b16=B.L.N.b1;
    Ret.L.N.b15=B.R.N.b26;
    Ret.L.N.b14=B.L.N.b26;
    Ret.L.N.b13=B.R.N.b18;
    Ret.L.N.b12=B.L.N.b18;
    Ret.L.N.b11=B.R.N.b10;
    Ret.L.N.b10=B.L.N.b10;
    Ret.L.N.b9=B.R.N.b2;
    Ret.L.N.b8=B.L.N.b2;
    Ret.L.N.b7=B.R.N.b27;
    Ret.L.N.b6=B.L.N.b27;
    Ret.L.N.b5=B.R.N.b19;
    Ret.L.N.b4=B.L.N.b19;
    Ret.L.N.b3=B.R.N.b11;
    Ret.L.N.b2=B.L.N.b11;
    Ret.L.N.b1=B.R.N.b3;
    Ret.L.N.b0=B.L.N.b3;

    Ret.R.N.b31=B.R.N.b28;
    Ret.R.N.b30=B.L.N.b28;
    Ret.R.N.b29=B.R.N.b20;
    Ret.R.N.b28=B.L.N.b20;
    Ret.R.N.b27=B.R.N.b12;
    Ret.R.N.b26=B.L.N.b12;
    Ret.R.N.b25=B.R.N.b4;
    Ret.R.N.b24=B.L.N.b4;
    Ret.R.N.b23=B.R.N.b29;
    Ret.R.N.b22=B.L.N.b29;
    Ret.R.N.b21=B.R.N.b21;
    Ret.R.N.b20=B.L.N.b21;
    Ret.R.N.b19=B.R.N.b13;
    Ret.R.N.b18=B.L.N.b13;
    Ret.R.N.b17=B.R.N.b5;
    Ret.R.N.b16=B.L.N.b5;
    Ret.R.N.b15=B.R.N.b30;
    Ret.R.N.b14=B.L.N.b30;
    Ret.R.N.b13=B.R.N.b22;
    Ret.R.N.b12=B.L.N.b22;
    Ret.R.N.b11=B.R.N.b14;
    Ret.R.N.b10=B.L.N.b14;
    Ret.R.N.b9=B.R.N.b6;
    Ret.R.N.b8=B.L.N.b6;
    Ret.R.N.b7=B.R.N.b31;
    Ret.R.N.b6=B.L.N.b31;
    Ret.R.N.b5=B.R.N.b23;
    Ret.R.N.b4=B.L.N.b23;
    Ret.R.N.b3=B.R.N.b15;
    Ret.R.N.b2=B.L.N.b15;
    Ret.R.N.b1=B.R.N.b7;
    Ret.R.N.b0=B.L.N.b7;

    return(Ret);
}

/*==========================================================================*/

BU64 bcrypt_encode(SL0, SL1)
    U32 SL0, SL1;
{
    REG int  count, i;
    REG BU32 L, R, I, T, Y;
    REG BU64 ret;

    ret.R.U=0;
    ret.L.U=0;
    for(count=25; count>0; count--) {
        for(i=0; i<16; i++) {
            T=ret.R;
            ret.R=ret.L;
            ret.L=T;
            I.U  = ret.L.FE1.b31_26;
            I.F12.b11_6 = ret.L.FE1.b5_0;   /* 0 & 4 */
            T.U  = (I.U ^ (I.U >> 1)) & SL0;
            I.U ^= T.U | (T.U << 1);
            I.U ^= UKS[i][0].U;
            Y.U  = S[0][I.U];

            I.U  = ret.L.FE0.b29_18;         /* 1 & 5 */
            T.U  = (I.U ^ (I.U >> 1)) & SL1;
            I.U ^= T.U | (T.U << 1);
            I.U ^= UKS[i][1].U;
            Y.U |= S[1][I.U];

            I.U  = ret.L.FE1.b21_10;         /* 2 & 6 */
            I.U ^= UKS[i][2].U;
            Y.U |= S[2][I.U];

            I.U  = ret.L.FE0.b13_2;          /* 3 & 7 */
            I.U ^= UKS[i][3].U;
            Y.U |= S[3][I.U];

            ret.R.U ^= Y.U;
        }
        T=ret.R;
        ret.R=ret.L;
        ret.L=T;
    }
    return(ret);
}

/*==========================================================================*/

void bcrypt_salt_to_E(salt0, salt1, SL)
    char salt0, salt1;
    U32  SL[2];
{
    REG  int j;

    if(salt0>'Z')
        salt0-=6;
    if(salt0>'9')
        salt0-=7;
    salt0-='.';
    if (salt1>'Z')
        salt1-=6;
    if(salt1>'9')
        salt1-=7;
    salt1-='.';
    for(j=0, SL[0]=0; j<6; j++)
        SL[0] |= ((salt0 >> j) & 0x1) << ((5-j)*2);
    for(j=0, SL[1]=0; j<6; j++)
        SL[1] |= ((salt1 >> j) & 0x1) << ((5-j)*2);
}

/*==========================================================================*/

void bcrypt_set_word(word)
    REG    char *word;
{
    REG    int  i, j, k, t;
    REG    char c;
    static char block[66], C[28], D[28];

    for(i=0; (c=(*word)) && (i<64); word++, i++) {
        for(j=0; j<7; j++, i++)
            block[i] = (c >> (6-j)) & 0x1;
        block[i]=0;
    }
    for(;i<66;i++)
        block[i]=0;
    for (i=0; i<28; i++) {
        C[i]=block[PC1_C[i]-1];
        D[i]=block[PC1_D[i]-1];
    }
    for (i=0; i<16; i++) {
        for (k=0; k<shifts[i]; k++) {
            for (j=0, t=C[0]; j<28-1; j++)
                C[j]  = C[j+1];
                C[27] = t;
                t     = D[0];
                for (j=0; j<28-1; j++)
                    D[j]  = D[j+1];
                    D[27] = t;
        }
        for (j=0; j<24; j++) {
            KS[i][j]    = C[PC2_C[j]-1];
            KS[i][j+24] = D[PC2_D[j]-28-1];
        }
    }
    for(i=0; i<16; i++) {
        for(j=0, k=0; j<4; j++, k+=6) {
            UKS[i][j].U     = 0;
            UKS[i][j].N.b11 = KS[i][k+0];
            UKS[i][j].N.b9  = KS[i][k+1];
            UKS[i][j].N.b8  = KS[i][k+2];
            UKS[i][j].N.b7  = KS[i][k+3];
            UKS[i][j].N.b6  = KS[i][k+4];
            UKS[i][j].N.b10 = KS[i][k+5];

            UKS[i][j].N.b5 = KS[i][k+24+0];
            UKS[i][j].N.b3 = KS[i][k+24+1];
            UKS[i][j].N.b2 = KS[i][k+24+2];
            UKS[i][j].N.b1 = KS[i][k+24+3];
            UKS[i][j].N.b0 = KS[i][k+24+4];
            UKS[i][j].N.b4 = KS[i][k+24+5];
        }
        UKS[i][0].U = CV0(UKS[i][0].U);
        UKS[i][1].U = CV1(UKS[i][1].U);
        UKS[i][2].U = CV1(UKS[i][2].U);
        UKS[i][3].U = CV1(UKS[i][3].U);
    }
}

/*==========================================================================*/

BU64 bcrypt_pw_to_BU64(pw)
    char *pw;
{
    REG    int i;
    REG    BU64 b;
    static char temp[11];

    for(i=0; i<11; i++) {
        temp[i]=pw[i];
        if (temp[i]>='a')
            temp[i]-=6;
        if (temp[i]>='A')
            temp[i]-=7;
        temp[i]-='.';
    }
    b.L.B6.b0_5    = temp[0];
    b.L.B6.b6_11   = temp[1];
    b.L.B6.b12_17  = temp[2];
    b.L.B6.b18_23  = temp[3];
    b.L.B6.b24_29  = temp[4];
    b.L.B6.b30_31  = temp[5] >> 4;
    b.R.B6_.b0_3   = temp[5];
    b.R.B6_.b4_9   = temp[6];
    b.R.B6_.b10_15 = temp[7];
    b.R.B6_.b16_21 = temp[8];
    b.R.B6_.b22_27 = temp[9];
    b.R.B6_.b28_31 = temp[10] >> 2;

    b=IP(b);
    b.L=EN(b.L);
    b.R=EN(b.R);

    return(b);
}

/*==========================================================================*/

void bcrypt_done()
{
    int i;

#if defined(_TURBO)
    for(i=0; i<4; i++) {
        if (S3[i])
            farfree(S3[i]);
        if (S[i])
            farfree(S[i]);
    }
#elif defined(_MICROSOFT)
    for(i=0; i<4; i++) {
        if (S3[i])
            _ffree(S3[i]);
        if (S[i])
            _ffree(S[i]);
    }
#endif

}
/*==========================================================================*/

void bcrypt_init()
{
    BU32 T, F;
    int  i, j, k;

#if defined(_TURBO)
    for(i=0; i<4; i++) {
        S3[i]=(unsigned long *)farmalloc(sizeof(long)*4096);
        S[i]=(unsigned long *)farmalloc(sizeof(long)*4096);
        if ((!S3[i]) || (!S[i])) {
            bcrypt_done();
            exit(1);
        }
    }
#elif defined(_MICROSOFT)
    for(i=0; i<4; i++) {
        S3[i]=(unsigned long *)_fmalloc(sizeof(long)*4096);
        S[i]=(unsigned long *)_fmalloc(sizeof(long)*4096);
        if ((!S3[i]) || (!S[i])) {
            bcrypt_done();
            exit(1);
        }
    }
#endif
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(unsigned long) OS[0][i];
        T.N.b23=F.N.b3;
        T.N.b15=F.N.b2;
        T.N.b9=F.N.b1;
        T.N.b1=F.N.b0;
        S2[0][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(unsigned long) OS[1][i];
        T.N.b30=F.N.b1;
        T.N.b19=F.N.b3;
        T.N.b14=F.N.b0;
        T.N.b4=F.N.b2;
        S2[1][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(unsigned long) OS[2][i];
        T.N.b26=F.N.b0;
        T.N.b16=F.N.b2;
        T.N.b8=F.N.b3;
        T.N.b2=F.N.b1;
        S2[2][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(unsigned long) OS[3][i];
        T.N.b31=F.N.b0;
        T.N.b22=F.N.b1;
        T.N.b12=F.N.b2;
        T.N.b6=F.N.b3;
        S2[3][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(unsigned long) OS[4][i];
        T.N.b29=F.N.b0;
        T.N.b24=F.N.b3;
        T.N.b18=F.N.b2;
        T.N.b7=F.N.b1;
        S2[4][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(unsigned long) OS[5][i];
        T.N.b28=F.N.b3;
        T.N.b21=F.N.b1;
        T.N.b13=F.N.b0;
        T.N.b3=F.N.b2;
        S2[5][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(unsigned long) OS[6][i];
        T.N.b25=F.N.b0;
        T.N.b20=F.N.b2;
        T.N.b10=F.N.b1;
        T.N.b0=F.N.b3;
        S2[6][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(unsigned long) OS[7][i];
        T.N.b27=F.N.b3;
        T.N.b17=F.N.b1;
        T.N.b11=F.N.b0;
        T.N.b5=F.N.b2;
        S2[7][i]=T.U;
    }
    for(k=0; k<4; k++) {
        for(i=0; i<64; i++) {
            for(j=0; j<64; j++) {
                F.U=S2[k][i] | S2[k+4][j];
                F=EN(F);
                S3[k][(i*64)+j]=F.U;
            }
        }
    }
    for(j=0; j<4096; j++) {
        S[0][CV0((unsigned long) j)]=S3[0][j];
        S[1][CV1((unsigned long) j)]=S3[1][j];
        S[2][CV1((unsigned long) j)]=S3[2][j];
        S[3][CV1((unsigned long) j)]=S3[3][j];
    }
}
