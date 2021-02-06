
#include "bcrypt.h"
#include <stdio.h>

static char KS[16][48];             /* Key Schedule */
static BU32 UKS[16][4];             /* Key Schedule In Alternate Form */

/* S-Boxes, S2, S3, S (S is master S-Box) */
static U32 S2[8][64];

static U32 S3[4][4096],             /* S-Box */
           S[4][4096];              /* Permuted S-Box S3 */

/*==========================================================================*/

U32 CV0(INU)
    REG U32 INU;
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
    REG U32 INU;
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

#define ENCODE_R(x) \
    I.U  = ret.R.FE1.b31_26;\
    I.F12.b11_6 = ret.R.FE1.b5_0;\
    T.U  = (I.U ^ (I.U >> 1)) & SL0;\
    I.U ^= (T.U | (T.U << 1)) ^ UKS[x][0].U;\
    Y.U  = S[0][I.U];\
    I.U  = ret.R.FE0.b29_18;\
    T.U  = (I.U ^ (I.U >> 1)) & SL1;\
    I.U ^= (T.U | (T.U << 1)) ^ UKS[x][1].U;\
    ret.L.U ^= (Y.U | S[1][I.U] | S[2][ret.R.FE1.b21_10 ^ UKS[x][2].U] | S[3][ret.R.FE0.b13_2 ^ UKS[x][3].U]);\

#define ENCODE_L(x) \
    I.U  = ret.L.FE1.b31_26;\
    I.F12.b11_6 = ret.L.FE1.b5_0;\
    T.U  = (I.U ^ (I.U >> 1)) & SL0;\
    I.U ^= (T.U | (T.U << 1)) ^ UKS[x][0].U;\
    Y.U  = S[0][I.U];\
    I.U  = ret.L.FE0.b29_18;\
    T.U  = (I.U ^ (I.U >> 1)) & SL1;\
    I.U ^= (T.U | (T.U << 1)) ^ UKS[x][1].U;\
    ret.R.U ^= (Y.U | S[1][I.U] | S[2][ret.L.FE1.b21_10 ^ UKS[x][2].U] | S[3][ret.L.FE0.b13_2 ^ UKS[x][3].U]);\

/*==========================================================================*/

BU64 bcrypt_encode(register U32 SL0, register U32 SL1)
{
    REG char count;
    REG BU32 I, T, Y;
    REG BU64 ret;

    ret.R.U=ret.L.U=0;
    for(count=25; count>0; count--) {
        ENCODE_R(0);
        ENCODE_L(1);
        ENCODE_R(2);
        ENCODE_L(3);
        ENCODE_R(4);
        ENCODE_L(5);
        ENCODE_R(6);
        ENCODE_L(7);
        ENCODE_R(8);
        ENCODE_L(9);
        ENCODE_R(10);
        ENCODE_L(11);
        ENCODE_R(12);
        ENCODE_L(13);
        ENCODE_R(14);
        ENCODE_L(15);
        T=ret.R;
        ret.R=ret.L;
        ret.L=T;
    }
    return(ret);
}

/*==========================================================================*/

void bcrypt_salt_to_E(salt0, salt1, SL)
    register char salt0, salt1;
    register U32 SL[2];
{
    REG  int  j;

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

#define ROTATE_ONE(a) \
    j=a[0];\
    memcpy(a,a+1,27); \
    a[27]=j;

/*
    a[ 0]=a[ 1], a[ 1]=a[ 2], a[ 2]=a[ 3], a[ 3]=a[ 4],\
    a[ 4]=a[ 5], a[ 5]=a[ 6], a[ 6]=a[ 7], a[ 7]=a[ 8],\
    a[ 8]=a[ 9], a[ 9]=a[10], a[10]=a[11], a[11]=a[12],\
    a[12]=a[13], a[13]=a[14], a[14]=a[15], a[15]=a[16],\
    a[16]=a[17], a[17]=a[18], a[18]=a[19], a[19]=a[20],\
    a[20]=a[21], a[21]=a[22], a[22]=a[23], a[23]=a[24],\
    a[24]=a[25], a[25]=a[26], a[26]=a[27], a[27]=j
*/

#define ROTATE_TWO(a) \
    j=a[0];\
    k=a[1];\
    memcpy(a,a+2,26); \
    a[26]=j; \
    a[27]=k;
/*
    a[ 0]=a[ 2], a[ 1]=a[ 3], a[ 2]=a[ 4], a[ 3]=a[ 5],\
    a[ 4]=a[ 6], a[ 5]=a[ 7], a[ 6]=a[ 8], a[ 7]=a[ 9],\
    a[ 8]=a[10], a[ 9]=a[11], a[10]=a[12], a[11]=a[13],\
    a[12]=a[14], a[13]=a[15], a[14]=a[16], a[15]=a[17],\
    a[16]=a[18], a[17]=a[19], a[18]=a[20], a[19]=a[21],\
    a[20]=a[22], a[21]=a[23], a[22]=a[24], a[23]=a[25],\
    a[24]=a[26], a[25]=a[27], a[26]=j,     a[27]=k
*/
/*==========================================================================*/

void bcrypt_set_word(register char *word)
{
    REG    int  i, j, k;
    static union char_union t;
    static char block[66], C[28], D[28];

    for(i=0; ((t.c=(*word++))!=NULL) && (i<64); ) {
        block[i++]=t.bits.b6;
        block[i++]=t.bits.b5;
        block[i++]=t.bits.b4;
        block[i++]=t.bits.b3;
        block[i++]=t.bits.b2;
        block[i++]=t.bits.b1;
        block[i++]=t.bits.b0;
        block[i++]=0;
    }
    for(; i<66; i++)
        block[i]=0;

    /* Permuted choice 1 (C) */
    C[ 0]=block[56], C[ 1]=block[48], C[ 2]=block[40], C[ 3]=block[32],
    C[ 4]=block[24], C[ 5]=block[16], C[ 6]=block[ 8], C[ 7]=block[ 0],
    C[ 8]=block[57], C[ 9]=block[49], C[10]=block[41], C[11]=block[33],
    C[12]=block[25], C[13]=block[17], C[14]=block[ 9], C[15]=block[ 1],
    C[16]=block[58], C[17]=block[50], C[18]=block[42], C[19]=block[34],
    C[20]=block[26], C[21]=block[18], C[22]=block[10], C[23]=block[ 2],
    C[24]=block[59], C[25]=block[51], C[26]=block[43], C[27]=block[35];

    /* Permuted choice 1 (D) */
    D[ 0]=block[62], D[ 1]=block[54], D[ 2]=block[46], D[ 3]=block[38],
    D[ 4]=block[30], D[ 5]=block[22], D[ 6]=block[14], D[ 7]=block[ 6],
    D[ 8]=block[61], D[ 9]=block[53], D[10]=block[45], D[11]=block[37],
    D[12]=block[29], D[13]=block[21], D[14]=block[13], D[15]=block[ 5],
    D[16]=block[60], D[17]=block[52], D[18]=block[44], D[19]=block[36],
    D[20]=block[28], D[21]=block[20], D[22]=block[12], D[23]=block[ 4],
    D[24]=block[27], D[25]=block[19], D[26]=block[11], D[27]=block[ 3];

    for (i=0; i<16; i++) {
        if (SHIFTS_M1[i]) {
            ROTATE_TWO(C);
            ROTATE_TWO(D);
        }
        else {
            ROTATE_ONE(C);
            ROTATE_ONE(D);
        }

        /* Permuted choice 2 (C) */
        KS[i][ 0]=C[13], KS[i][ 1]=C[16], KS[i][ 2]=C[10], KS[i][ 3]=C[23],
        KS[i][ 4]=C[ 0], KS[i][ 5]=C[ 4], KS[i][ 6]=C[ 2], KS[i][ 7]=C[27],
        KS[i][ 8]=C[14], KS[i][ 9]=C[ 5], KS[i][10]=C[20], KS[i][11]=C[ 9],
        KS[i][12]=C[22], KS[i][13]=C[18], KS[i][14]=C[11], KS[i][15]=C[ 3],
        KS[i][16]=C[25], KS[i][17]=C[ 7], KS[i][18]=C[15], KS[i][19]=C[ 6],
        KS[i][20]=C[26], KS[i][21]=C[19], KS[i][22]=C[12], KS[i][23]=C[ 1];

        /* Permuted choice 2 (D) */
        KS[i][24]=D[12], KS[i][25]=D[23], KS[i][26]=D[ 2], KS[i][27]=D[ 8],
        KS[i][28]=D[18], KS[i][29]=D[26], KS[i][30]=D[ 1], KS[i][31]=D[11],
        KS[i][32]=D[22], KS[i][33]=D[16], KS[i][34]=D[ 4], KS[i][35]=D[19],
        KS[i][36]=D[15], KS[i][37]=D[20], KS[i][38]=D[10], KS[i][39]=D[27],
        KS[i][40]=D[ 5], KS[i][41]=D[24], KS[i][42]=D[17], KS[i][43]=D[13],
        KS[i][44]=D[21], KS[i][45]=D[ 7], KS[i][46]=D[ 0], KS[i][47]=D[ 3];
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

            UKS[i][j].N.b5 = KS[i][k+24];
            UKS[i][j].N.b3 = KS[i][k+25];
            UKS[i][j].N.b2 = KS[i][k+26];
            UKS[i][j].N.b1 = KS[i][k+27];
            UKS[i][j].N.b0 = KS[i][k+28];
            UKS[i][j].N.b4 = KS[i][k+29];
        }
        UKS[i][0].U = CV0(UKS[i][0].U);
        UKS[i][1].U = CV1(UKS[i][1].U);
        UKS[i][2].U = CV1(UKS[i][2].U);
        UKS[i][3].U = CV1(UKS[i][3].U);
    }
}

/*==========================================================================*/

BU64 bcrypt_pw_to_BU64(char *pw)
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

void bcrypt_init()
{
    BU32 T, F;
    int  i, j, k;

    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(U32) OS[0][i];
        T.N.b23=F.N.b3;
        T.N.b15=F.N.b2;
        T.N.b9=F.N.b1;
        T.N.b1=F.N.b0;
        S2[0][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(U32) OS[1][i];
        T.N.b30=F.N.b1;
        T.N.b19=F.N.b3;
        T.N.b14=F.N.b0;
        T.N.b4=F.N.b2;
        S2[1][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(U32) OS[2][i];
        T.N.b26=F.N.b0;
        T.N.b16=F.N.b2;
        T.N.b8=F.N.b3;
        T.N.b2=F.N.b1;
        S2[2][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(U32) OS[3][i];
        T.N.b31=F.N.b0;
        T.N.b22=F.N.b1;
        T.N.b12=F.N.b2;
        T.N.b6=F.N.b3;
        S2[3][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(U32) OS[4][i];
        T.N.b29=F.N.b0;
        T.N.b24=F.N.b3;
        T.N.b18=F.N.b2;
        T.N.b7=F.N.b1;
        S2[4][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(U32) OS[5][i];
        T.N.b28=F.N.b3;
        T.N.b21=F.N.b1;
        T.N.b13=F.N.b0;
        T.N.b3=F.N.b2;
        S2[5][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(U32) OS[6][i];
        T.N.b25=F.N.b0;
        T.N.b20=F.N.b2;
        T.N.b10=F.N.b1;
        T.N.b0=F.N.b3;
        S2[6][i]=T.U;
    }
    for(i=0; i<64; i++) {
        T.U=0;
        F.U=(U32) OS[7][i];
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
    for(j=0; j<4096; j++)
        S[0][CV0((U32) j)]=S3[0][j];
    for(j=0; j<4096; j++)
        S[1][CV1((U32) j)]=S3[1][j];
    for(j=0; j<4096; j++)
        S[2][CV1((U32) j)]=S3[2][j];
    for(j=0; j<4096; j++)
        S[3][CV1((U32) j)]=S3[3][j];
}
