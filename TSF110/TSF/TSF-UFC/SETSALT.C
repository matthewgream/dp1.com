
static unsigned long shortmask[6] =
  {
    0x00000020, 0x00000010,
    0x00000008, 0x00000004,
    0x00000002, 0x00000001
  };

void shuffle_sb(k, saltbits)
  unsigned long *k, saltbits;
  { int j, x;
    for(j=4096; j--;) {
      x = (k[0] ^ k[1]) & saltbits;
      *k++ ^= x;
      *k++ ^= x;
    }
  }

static unsigned char current_salt[3]="&&"; /* invalid value */
static unsigned long oldsaltbits = 0;

void setup_salt(s)
  char *s;
  {
    register unsigned long mask1,word_value,comes_from_word;
        static unsigned long saltbits;
        register long c;

    if(s[0]==current_salt[0] && s[1]==current_salt[1]) return;
    current_salt[0]=s[0]; current_salt[1]=s[1];

    saltbits=0;
    bcopy((char*)eref,(char*)disturbed_e,sizeof eref);

        c=s[0];
    if(c<0 || c>63) c=0;

        if(c & 0x1)   {
            disturbed_e[ 0]=16;
            disturbed_e[24]=32;
            saltbits |= bm[0];   }

        if( (c >> 1) & 0x1)   {
            disturbed_e[ 1]=17;
            disturbed_e[25]=1;
            saltbits |= bm[1];   }

        if( (c >> 2) & 0x1)   {
            disturbed_e[ 2]=18;
            disturbed_e[26]=2;
            saltbits |= bm[2];   }

        if( (c >> 3) & 0x1)   {
            disturbed_e[ 3]=19;
            disturbed_e[27]=3;
            saltbits |= bm[3];   }

        if( (c >> 4) & 0x1)   {
            disturbed_e[ 4]=20;
            disturbed_e[28]=4;
            saltbits |= bm[4];   }

        if( (c >> 5) & 0x1)   {
            disturbed_e[ 5]=21;
            disturbed_e[29]=5;
            saltbits |= bm[5];   }


    c=s[1];
    if(c<0 || c>63) c=0;

        if(c & 0x1)   {
            disturbed_e[ 6]=20;
            disturbed_e[30]=4;
            saltbits |= bm[6];   }

        if( (c >> 1) & 0x1)   {
            disturbed_e[ 7]=21;
            disturbed_e[31]=5;
            saltbits |= bm[7];   }

        if( (c >> 2) & 0x1)   {
            disturbed_e[ 8]=22;
            disturbed_e[32]=6;
            saltbits |= bm[8];   }

        if( (c >> 3) & 0x1)   {
            disturbed_e[ 9]=23;
            disturbed_e[33]=7;
            saltbits |= bm[9];   }

        if( (c >> 4) & 0x1)   {
            disturbed_e[10]=24;
            disturbed_e[34]=8;
            saltbits |= bm[10];   }

        if( (c >> 5) & 0x1)   {
            disturbed_e[11]=25;
            disturbed_e[35]=9;
            saltbits |= bm[11];   }

    shuffle_sb(sb0, oldsaltbits ^ saltbits); 
    shuffle_sb(sb1, oldsaltbits ^ saltbits);
    shuffle_sb(sb2, oldsaltbits ^ saltbits);
    shuffle_sb(sb3, oldsaltbits ^ saltbits);

    oldsaltbits = saltbits;

    e_inverse[disturbed_e[47]-1]  = 47;
    e_inverse[disturbed_e[47]+31] = 95;
    e_inverse[disturbed_e[46]-1]  = 46;
    e_inverse[disturbed_e[46]+31] = 94;
    e_inverse[disturbed_e[45]-1]  = 45;
    e_inverse[disturbed_e[45]+31] = 93;
    e_inverse[disturbed_e[44]-1]  = 44;
    e_inverse[disturbed_e[44]+31] = 92;
    e_inverse[disturbed_e[43]-1]  = 43;
    e_inverse[disturbed_e[43]+31] = 91;
    e_inverse[disturbed_e[42]-1]  = 42;
    e_inverse[disturbed_e[42]+31] = 90;
    e_inverse[disturbed_e[41]-1]  = 41;
    e_inverse[disturbed_e[41]+31] = 89;
    e_inverse[disturbed_e[40]-1]  = 40;
    e_inverse[disturbed_e[40]+31] = 88;
    e_inverse[disturbed_e[39]-1]  = 39;
    e_inverse[disturbed_e[39]+31] = 87;
    e_inverse[disturbed_e[38]-1]  = 38;
    e_inverse[disturbed_e[38]+31] = 86;
    e_inverse[disturbed_e[37]-1]  = 37;
    e_inverse[disturbed_e[37]+31] = 85;
    e_inverse[disturbed_e[36]-1]  = 36;
    e_inverse[disturbed_e[36]+31] = 84;
    e_inverse[disturbed_e[35]-1]  = 35;
    e_inverse[disturbed_e[35]+31] = 83;
    e_inverse[disturbed_e[34]-1]  = 34;
    e_inverse[disturbed_e[34]+31] = 82;
    e_inverse[disturbed_e[33]-1]  = 33;
    e_inverse[disturbed_e[33]+31] = 81;
    e_inverse[disturbed_e[32]-1]  = 32;
    e_inverse[disturbed_e[32]+31] = 80;
    e_inverse[disturbed_e[31]-1]  = 31;
    e_inverse[disturbed_e[31]+31] = 79;
    e_inverse[disturbed_e[30]-1]  = 30;
    e_inverse[disturbed_e[30]+31] = 78;
    e_inverse[disturbed_e[29]-1]  = 29;
    e_inverse[disturbed_e[29]+31] = 77;
    e_inverse[disturbed_e[28]-1]  = 28;
    e_inverse[disturbed_e[28]+31] = 76;
    e_inverse[disturbed_e[27]-1]  = 27;
    e_inverse[disturbed_e[27]+31] = 75;
    e_inverse[disturbed_e[26]-1]  = 26;
    e_inverse[disturbed_e[26]+31] = 74;
    e_inverse[disturbed_e[25]-1]  = 25;
    e_inverse[disturbed_e[25]+31] = 73;
    e_inverse[disturbed_e[24]-1]  = 24;
    e_inverse[disturbed_e[24]+31] = 72;
    e_inverse[disturbed_e[23]-1]  = 23;
    e_inverse[disturbed_e[23]+31] = 71;
    e_inverse[disturbed_e[22]-1]  = 22;
    e_inverse[disturbed_e[22]+31] = 70;
    e_inverse[disturbed_e[21]-1]  = 21;
    e_inverse[disturbed_e[21]+31] = 69;
    e_inverse[disturbed_e[20]-1]  = 20;
    e_inverse[disturbed_e[20]+31] = 68;
    e_inverse[disturbed_e[19]-1]  = 19;
    e_inverse[disturbed_e[19]+31] = 67;
    e_inverse[disturbed_e[18]-1]  = 18;
    e_inverse[disturbed_e[18]+31] = 66;
    e_inverse[disturbed_e[17]-1]  = 17;
    e_inverse[disturbed_e[17]+31] = 65;
    e_inverse[disturbed_e[16]-1]  = 16;
    e_inverse[disturbed_e[16]+31] = 64;
    e_inverse[disturbed_e[15]-1]  = 15;
    e_inverse[disturbed_e[15]+31] = 63;
    e_inverse[disturbed_e[14]-1]  = 14;
    e_inverse[disturbed_e[14]+31] = 62;
    e_inverse[disturbed_e[13]-1]  = 13;
    e_inverse[disturbed_e[13]+31] = 61;
    e_inverse[disturbed_e[12]-1]  = 12;
    e_inverse[disturbed_e[12]+31] = 60;
    e_inverse[disturbed_e[11]-1]  = 11;
    e_inverse[disturbed_e[11]+31] = 59;
    e_inverse[disturbed_e[10]-1]  = 10;
    e_inverse[disturbed_e[10]+31] = 58;
    e_inverse[disturbed_e[9]-1]  = 9;
    e_inverse[disturbed_e[9]+31] = 57;
    e_inverse[disturbed_e[8]-1]  = 8;
    e_inverse[disturbed_e[8]+31] = 56;
    e_inverse[disturbed_e[7]-1]  = 7;
    e_inverse[disturbed_e[7]+31] = 55;
    e_inverse[disturbed_e[6]-1]  = 6;
    e_inverse[disturbed_e[6]+31] = 54;
    e_inverse[disturbed_e[5]-1]  = 5;
    e_inverse[disturbed_e[5]+31] = 53;
    e_inverse[disturbed_e[4]-1]  = 4;
    e_inverse[disturbed_e[4]+31] = 52;
    e_inverse[disturbed_e[3]-1]  = 3;
    e_inverse[disturbed_e[3]+31] = 51;
    e_inverse[disturbed_e[2]-1]  = 2;
    e_inverse[disturbed_e[2]+31] = 50;
    e_inverse[disturbed_e[1]-1]  = 1;
    e_inverse[disturbed_e[1]+31] = 49;
    e_inverse[disturbed_e[0]-1]  = 0;
    e_inverse[disturbed_e[0]+31] = 48;

    bzero((char*)efp,sizeof efp);

    comes_from_word = e_inverse[39] / 6;
    mask1 = shortmask[(e_inverse[39] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x80000000;

    comes_from_word = e_inverse[7] / 6;
    mask1 = shortmask[(e_inverse[7] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x40000000;

    comes_from_word = e_inverse[47] / 6;
    mask1 = shortmask[(e_inverse[47] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x20000000;

    comes_from_word = e_inverse[15] / 6;
    mask1 = shortmask[(e_inverse[15] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x10000000;

    comes_from_word = e_inverse[55] / 6;
    mask1 = shortmask[(e_inverse[55] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x08000000;

    comes_from_word = e_inverse[23] / 6;
    mask1 = shortmask[(e_inverse[23] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x04000000;

    comes_from_word = e_inverse[63] / 6;
    mask1 = shortmask[(e_inverse[63] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x02000000;

    comes_from_word = e_inverse[31] / 6;
    mask1 = shortmask[(e_inverse[31] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x01000000;

    comes_from_word = e_inverse[38] / 6;
    mask1 = shortmask[(e_inverse[38] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00800000;

    comes_from_word = e_inverse[6] / 6;
    mask1 = shortmask[(e_inverse[6] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00400000;

    comes_from_word = e_inverse[46] / 6;
    mask1 = shortmask[(e_inverse[46] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00200000;

    comes_from_word = e_inverse[14] / 6;
    mask1 = shortmask[(e_inverse[14] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00100000;

    comes_from_word = e_inverse[54] / 6;
    mask1 = shortmask[(e_inverse[54] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00080000;

    comes_from_word = e_inverse[22] / 6;
    mask1 = shortmask[(e_inverse[22] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00040000;

    comes_from_word = e_inverse[62] / 6;
    mask1 = shortmask[(e_inverse[62] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00020000;

    comes_from_word = e_inverse[30] / 6;
    mask1 = shortmask[(e_inverse[30] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00010000;

    comes_from_word = e_inverse[37] / 6;
    mask1 = shortmask[(e_inverse[37] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00008000;

    comes_from_word = e_inverse[5] / 6;
    mask1 = shortmask[(e_inverse[5] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00004000;

    comes_from_word = e_inverse[45] / 6;
    mask1 = shortmask[(e_inverse[45] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00002000;

    comes_from_word = e_inverse[13] / 6;
    mask1 = shortmask[(e_inverse[13] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00001000;

    comes_from_word = e_inverse[53] / 6;
    mask1 = shortmask[(e_inverse[53] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000800;

    comes_from_word = e_inverse[21] / 6;
    mask1 = shortmask[(e_inverse[21] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000400;

    comes_from_word = e_inverse[61] / 6;
    mask1 = shortmask[(e_inverse[61] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000200;

    comes_from_word = e_inverse[29] / 6;
    mask1 = shortmask[(e_inverse[29] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000100;

    comes_from_word = e_inverse[36] / 6;
    mask1 = shortmask[(e_inverse[36] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000080;

    comes_from_word = e_inverse[4] / 6;
    mask1 = shortmask[(e_inverse[4] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000040;

    comes_from_word = e_inverse[44] / 6;
    mask1 = shortmask[(e_inverse[44] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000020;

    comes_from_word = e_inverse[12] / 6;
    mask1 = shortmask[(e_inverse[12] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000010;

    comes_from_word = e_inverse[52] / 6;
    mask1 = shortmask[(e_inverse[52] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000008;

    comes_from_word = e_inverse[20] / 6;
    mask1 = shortmask[(e_inverse[20] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000004;

    comes_from_word = e_inverse[60] / 6;
    mask1 = shortmask[(e_inverse[60] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000002;

    comes_from_word = e_inverse[28] / 6;
    mask1 = shortmask[(e_inverse[28] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][0] |= 0x00000001;

    comes_from_word = e_inverse[35] / 6;
    mask1 = shortmask[(e_inverse[35] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x80000000;

    comes_from_word = e_inverse[3] / 6;
    mask1 = shortmask[(e_inverse[3] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x40000000;

    comes_from_word = e_inverse[43] / 6;
    mask1 = shortmask[(e_inverse[43] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x20000000;

    comes_from_word = e_inverse[11] / 6;
    mask1 = shortmask[(e_inverse[11] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x10000000;

    comes_from_word = e_inverse[51] / 6;
    mask1 = shortmask[(e_inverse[51] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x08000000;

    comes_from_word = e_inverse[19] / 6;
    mask1 = shortmask[(e_inverse[19] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x04000000;

    comes_from_word = e_inverse[59] / 6;
    mask1 = shortmask[(e_inverse[59] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x02000000;

    comes_from_word = e_inverse[27] / 6;
    mask1 = shortmask[(e_inverse[27] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x01000000;

    comes_from_word = e_inverse[34] / 6;
    mask1 = shortmask[(e_inverse[34] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00800000;

    comes_from_word = e_inverse[2] / 6;
    mask1 = shortmask[(e_inverse[2] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00400000;

    comes_from_word = e_inverse[42] / 6;
    mask1 = shortmask[(e_inverse[42] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00200000;

    comes_from_word = e_inverse[10] / 6;
    mask1 = shortmask[(e_inverse[10] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00100000;

    comes_from_word = e_inverse[50] / 6;
    mask1 = shortmask[(e_inverse[50] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00080000;

    comes_from_word = e_inverse[18] / 6;
    mask1 = shortmask[(e_inverse[18] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00040000;

    comes_from_word = e_inverse[58] / 6;
    mask1 = shortmask[(e_inverse[58] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00020000;

    comes_from_word = e_inverse[26] / 6;
    mask1 = shortmask[(e_inverse[26] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00010000;

    comes_from_word = e_inverse[33] / 6;
    mask1 = shortmask[(e_inverse[33] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00008000;

    comes_from_word = e_inverse[1] / 6;
    mask1 = shortmask[(e_inverse[1] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00004000;

    comes_from_word = e_inverse[41] / 6;
    mask1 = shortmask[(e_inverse[41] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00002000;

    comes_from_word = e_inverse[9] / 6;
    mask1 = shortmask[(e_inverse[9] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00001000;

    comes_from_word = e_inverse[49] / 6;
    mask1 = shortmask[(e_inverse[49] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000800;

    comes_from_word = e_inverse[17] / 6;
    mask1 = shortmask[(e_inverse[17] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000400;

    comes_from_word = e_inverse[57] / 6;
    mask1 = shortmask[(e_inverse[57] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000200;

    comes_from_word = e_inverse[25] / 6;
    mask1 = shortmask[(e_inverse[25] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000100;

    comes_from_word = e_inverse[32] / 6;
    mask1 = shortmask[(e_inverse[32] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000080;

    comes_from_word = e_inverse[0] / 6;
    mask1 = shortmask[(e_inverse[0] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000040;

    comes_from_word = e_inverse[40] / 6;
    mask1 = shortmask[(e_inverse[40] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000020;

    comes_from_word = e_inverse[8] / 6;
    mask1 = shortmask[(e_inverse[8] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000010;

    comes_from_word = e_inverse[48] / 6;
    mask1 = shortmask[(e_inverse[48] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000008;

    comes_from_word = e_inverse[16] / 6;
    mask1 = shortmask[(e_inverse[16] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000004;

    comes_from_word = e_inverse[56] / 6;
    mask1 = shortmask[(e_inverse[56] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000002;

    comes_from_word = e_inverse[24] / 6;
    mask1 = shortmask[(e_inverse[24] % 6)];

     for(word_value=64; word_value--;)
        if(word_value & mask1)
            efp[comes_from_word][word_value][1] |= 0x00000001;

  }

