
/* Bcrypt 2.0 + Doctor D's 1.0 mods
   removed MSDOS defines */

/*=[ Include Files ]========================================================*/

#include "bcrypt.h"

/*=[ Static Variables ]=====================================================*/

static char KS[16][48];             /* Key Schedule */
static BU32 UKS[16][4];             /* Key Schedule In Alternate Form */

/* S-Boxes, S2, S3, S (S is master S-Box) */
static unsigned long S2[8][64];

unsigned long S3[4][4096],          /* S-Box */
              S[4][4096];           /* Permuted S-Box S3 */

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

#ifdef SYSV
#define bzero(addr, cnt)     memset(addr, 0, cnt)
#define bcopy(from, to, len) memcpy(to, from, len)
#endif

void bcrypt_set_word(word)
   REG char *word;
{
   REG int i,j;
   REG char c;
   
   bzero( (char *)UKS, sizeof(UKS) );

   for(i=0;i<16;i++)
   {
    for(j=0;word[j] && j<8;j++)
    {
     c=word[j]&0x7F;
     UKS[i][0].U|=EKS[i][j][c][0];
     UKS[i][1].U|=EKS[i][j][c][1];
     UKS[i][2].U|=EKS[i][j][c][2];
     UKS[i][3].U|=EKS[i][j][c][3];
    }
   }
}

/*
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
*/
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

}
/*==========================================================================*/

static int PC2_C2[16][24]={
 { 14,17,11,24, 1, 5, 3, 0,15, 6,21,10,23,19,12, 4,26, 8,16, 7,27,20,13, 2, },
 { 15,18,12,25, 2, 6, 4, 1,16, 7,22,11,24,20,13, 5,27, 9,17, 8, 0,21,14, 3, },
 { 17,20,14,27, 4, 8, 6, 3,18, 9,24,13,26,22,15, 7, 1,11,19,10, 2,23,16, 5, },
 { 19,22,16, 1, 6,10, 8, 5,20,11,26,15, 0,24,17, 9, 3,13,21,12, 4,25,18, 7, },
 { 21,24,18, 3, 8,12,10, 7,22,13, 0,17, 2,26,19,11, 5,15,23,14, 6,27,20, 9, },
 { 23,26,20, 5,10,14,12, 9,24,15, 2,19, 4, 0,21,13, 7,17,25,16, 8, 1,22,11, },
 { 25, 0,22, 7,12,16,14,11,26,17, 4,21, 6, 2,23,15, 9,19,27,18,10, 3,24,13, },
 { 27, 2,24, 9,14,18,16,13, 0,19, 6,23, 8, 4,25,17,11,21, 1,20,12, 5,26,15, },
 {  0, 3,25,10,15,19,17,14, 1,20, 7,24, 9, 5,26,18,12,22, 2,21,13, 6,27,16, },
 {  2, 5,27,12,17,21,19,16, 3,22, 9,26,11, 7, 0,20,14,24, 4,23,15, 8, 1,18, },
 {  4, 7, 1,14,19,23,21,18, 5,24,11, 0,13, 9, 2,22,16,26, 6,25,17,10, 3,20, },
 {  6, 9, 3,16,21,25,23,20, 7,26,13, 2,15,11, 4,24,18, 0, 8,27,19,12, 5,22, },
 {  8,11, 5,18,23,27,25,22, 9, 0,15, 4,17,13, 6,26,20, 2,10, 1,21,14, 7,24, },
 { 10,13, 7,20,25, 1,27,24,11, 2,17, 6,19,15, 8, 0,22, 4,12, 3,23,16, 9,26, },
 { 12,15, 9,22,27, 3, 1,26,13, 4,19, 8,21,17,10, 2,24, 6,14, 5,25,18,11, 0, },
 { 13,16,10,23, 0, 4, 2,27,14, 5,20, 9,22,18,11, 3,25, 7,15, 6,26,19,12, 1, },
};

static int PC2_D2[16][24]={
 { 13,24, 3, 9,19,27, 2,12,23,17, 5,20,16,21,11, 0, 6,25,18,14,22, 8, 1, 4, },
 { 14,25, 4,10,20, 0, 3,13,24,18, 6,21,17,22,12, 1, 7,26,19,15,23, 9, 2, 5, },
 { 16,27, 6,12,22, 2, 5,15,26,20, 8,23,19,24,14, 3, 9, 0,21,17,25,11, 4, 7, },
 { 18, 1, 8,14,24, 4, 7,17, 0,22,10,25,21,26,16, 5,11, 2,23,19,27,13, 6, 9, },
 { 20, 3,10,16,26, 6, 9,19, 2,24,12,27,23, 0,18, 7,13, 4,25,21, 1,15, 8,11, },
 { 22, 5,12,18, 0, 8,11,21, 4,26,14, 1,25, 2,20, 9,15, 6,27,23, 3,17,10,13, },
 { 24, 7,14,20, 2,10,13,23, 6, 0,16, 3,27, 4,22,11,17, 8, 1,25, 5,19,12,15, },
 { 26, 9,16,22, 4,12,15,25, 8, 2,18, 5, 1, 6,24,13,19,10, 3,27, 7,21,14,17, },
 { 27,10,17,23, 5,13,16,26, 9, 3,19, 6, 2, 7,25,14,20,11, 4, 0, 8,22,15,18, },
 {  1,12,19,25, 7,15,18, 0,11, 5,21, 8, 4, 9,27,16,22,13, 6, 2,10,24,17,20, },
 {  3,14,21,27, 9,17,20, 2,13, 7,23,10, 6,11, 1,18,24,15, 8, 4,12,26,19,22, },
 {  5,16,23, 1,11,19,22, 4,15, 9,25,12, 8,13, 3,20,26,17,10, 6,14, 0,21,24, },
 {  7,18,25, 3,13,21,24, 6,17,11,27,14,10,15, 5,22, 0,19,12, 8,16, 2,23,26, },
 {  9,20,27, 5,15,23,26, 8,19,13, 1,16,12,17, 7,24, 2,21,14,10,18, 4,25, 0, },
 { 11,22, 1, 7,17,25, 0,10,21,15, 3,18,14,19, 9,26, 4,23,16,12,20, 6,27, 2, },
 { 12,23, 2, 8,18,26, 1,11,22,16, 4,19,15,20,10,27, 5,24,17,13,21, 7, 0, 3, },
 };
 
static BU32 UKS[16][4];

static unsigned short EKS[16][8][128][4];

void FUDGE(char *pw,int achar,int pos)
{
   static char block[64];
   register int i,j,k;
   char c;
   unsigned long  CL,DL;
   BU32 T; 

   for(i=0;i<64; pw++,i++)
   {
    c=*pw;
    for(j=0; j<7; j++, i++)
     block[i] = (c>>(6-j)) & 01;
    block[i]=0;
   }
   for(;i<64;i++)
    block[i]=0;

   CL=0;
   DL=0;
   for (i=27; i>=0; i--)
   {
    CL<<=1;
    DL<<=1;
    CL|=block[PC1_C[i]-1];
    DL|=block[PC1_D[i]-1];
   }
   for (i=0; i<16; i++)
   {    
    for(j=0,k=0;j<4;j++,k+=6)
    {
     T.U=0;
     T.N.b11=(CL>>PC2_C2[i][k+0]);
     T.N.b10=(DL>>PC2_D2[i][k+0]);
     T.N.b9 =(CL>>PC2_C2[i][k+1]);
     T.N.b8 =(DL>>PC2_D2[i][k+1]);
     T.N.b7 =(CL>>PC2_C2[i][k+2]);
     T.N.b6 =(DL>>PC2_D2[i][k+2]);
     T.N.b5 =(CL>>PC2_C2[i][k+3]);
     T.N.b4 =(DL>>PC2_D2[i][k+3]);
     T.N.b3 =(CL>>PC2_C2[i][k+4]);
     T.N.b2 =(DL>>PC2_D2[i][k+4]);
     T.N.b1 =(CL>>PC2_C2[i][k+5]);
     T.N.b0 =(DL>>PC2_D2[i][k+5]);
     UKS[i][j]=T;
    }
    T.U=UKS[i][0].N.b9;
    UKS[i][0].N.b9=UKS[i][0].N.b8;
    UKS[i][0].N.b8=T.U;
    T.U=UKS[i][0].N.b11;
    UKS[i][0].N.b11=UKS[i][0].N.b10;
    UKS[i][0].N.b10=T.U;
    
    EKS[i][pos][achar][0]=UKS[i][0].U;
    EKS[i][pos][achar][1]=UKS[i][1].U;
    EKS[i][pos][achar][2]=UKS[i][2].U;
    EKS[i][pos][achar][3]=UKS[i][3].U;
   }
}

void HELL()
{
  int pos,achar,i,j;
  char pw[9];
  
  for(pos=0;pos<8;pos++)
   for(achar=0;achar<128;achar++)
   {
    for(i=0;i<9;i++)
     pw[i]=0;
    pw[pos]=achar;
    FUDGE(pw,achar,pos);  
   }
}

void bcrypt_init()
{
    BU32 T, F;
    int  i, j, k;

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
  HELL();
}
