
#ifdef SYSV
#define bzero(addr, cnt)     memset(addr, 0, cnt)
#define bcopy(from, to, len) memcpy(to, from, len)
#endif

static unsigned long pc1[56] =
  { 57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
  };

static unsigned long totrot[16] =
  { 1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28 };

static unsigned long pc2[48] =
  { 14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
  };

static unsigned long eref[48] =
  { 32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
  };
static unsigned long disturbed_e[48];
static unsigned long e_inverse[64];

static unsigned long perm32[32] = 
  { 16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
  };

static unsigned long sbox[8][4][16]=
      { { { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
          {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
          {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
          { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
        },

        { { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
          {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
          {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
          { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
        },

        { { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
          { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
          { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
          {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
        },

        { {  7,  13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
          { 13,  8,  11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
          { 10,  6,   9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
          {  3, 15,   0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
        },

        { {  2, 12,   4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
          { 14, 11,   2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
          {  4,  2,   1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
          { 11,  8,  12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
        },

        { { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
          { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
          {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
          {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
        },

        { {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
          { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
          {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
          {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
        },

        { { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
          {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
          {  7, 11, 4,   1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
          {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
        }
      };

static unsigned char final_perm[64] =
  { 40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
  };

unsigned long keytab[16][2];
#define ascii_to_bin(c) ((c)>='a'?(c-59):(c)>='A'?((c)-53):(c)-'.')
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')
#define BITMASK(i) ( (1<<(11-(i)%12+3)) << ((i)<12?16:0) )
static unsigned long bm[12];
unsigned long sb0[8192],sb1[8192],sb2[8192],sb3[8192];
static unsigned long *sb[4] = {sb0,sb1,sb2,sb3}; 
static unsigned long eperm32tab[4][256][2];
static unsigned long mk_keytab_table[8][16][2][128];
static unsigned long efp[16][64][2];

static unsigned char bytemask[8]  =
  { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

static unsigned long longmask[32] = 
  { 0x80000000, 0x40000000, 0x20000000, 0x10000000,
    0x08000000, 0x04000000, 0x02000000, 0x01000000,
    0x00800000, 0x00400000, 0x00200000, 0x00100000,
    0x00080000, 0x00040000, 0x00020000, 0x00010000,
    0x00008000, 0x00004000, 0x00002000, 0x00001000,
    0x00000800, 0x00000400, 0x00000200, 0x00000100,
    0x00000080, 0x00000040, 0x00000020, 0x00000010,
    0x00000008, 0x00000004, 0x00000002, 0x00000001
  };

static unsigned long initialized = 0;
#define s_lookup(i,s) sbox[(i)][(((s)>>4) & 0x2)|((s) & 0x1)][((s)>>1) & 0xf];

void init_des()
  { unsigned long tbl_long,bit_within_long,comes_from_bit;
    unsigned long bit,sg,j;
    unsigned long bit_within_byte,key_byte,byte_value;
    unsigned long round,mask;

    bzero((char*)mk_keytab_table,sizeof mk_keytab_table);
    
        for(j=0;j<12;j++) bm[j]=BITMASK(j);
    for(round=0; round<16; round++)
      for(bit=0; bit<48; bit++)
        { tbl_long        = bit / 24;
          bit_within_long = bit % 24;

          comes_from_bit = pc2[bit] - 1;

          if(comes_from_bit>=28)
            comes_from_bit =  28 + (comes_from_bit + totrot[round]) % 28;
          else
            comes_from_bit =       (comes_from_bit + totrot[round]) % 28;

          comes_from_bit = pc1[comes_from_bit] - 1;
          key_byte        =  comes_from_bit  / 8;
          bit_within_byte = (comes_from_bit % 8)+1;

          mask = bytemask[bit_within_byte];

          for(byte_value=0; byte_value<128; byte_value++)
            if(byte_value & mask)
              mk_keytab_table[key_byte][round][tbl_long][byte_value] |= 
                BITMASK(bit_within_long);
        }

    bzero((char*)eperm32tab,sizeof eperm32tab);
    for(bit=0; bit<48; bit++)
      { unsigned long mask1,comes_from;
        
        comes_from = perm32[eref[bit]-1]-1;
        mask1      = bytemask[comes_from % 8];
        
        for(j=256; j--;)
          if(j & mask1)
            eperm32tab[comes_from/8][j][bit/24] |= BITMASK(bit % 24);
      }
    
    for(sg=0; sg<4; sg++)
      { unsigned long j1,j2;
        unsigned long s1,s2;
    
        for(j1=0; j1<64; j1++)
          { s1 = s_lookup(2*sg,j1);
            for(j2=0; j2<64; j2++)
              { unsigned long to_permute,inx;

                s2         = s_lookup(2*sg+1,j2);
                to_permute = ((s1<<4)  | s2) << (24-8*sg);
                inx        = ((j1<<6)  | j2) << 1;

                sb[sg][inx  ]  = eperm32tab[0][(to_permute >> 24) & 0xff][0];
                sb[sg][inx+1]  = eperm32tab[0][(to_permute >> 24) & 0xff][1];
  
                sb[sg][inx  ] |= eperm32tab[1][(to_permute >> 16) & 0xff][0];
                sb[sg][inx+1] |= eperm32tab[1][(to_permute >> 16) & 0xff][1];
  
                sb[sg][inx  ] |= eperm32tab[2][(to_permute >>  8) & 0xff][0];
                sb[sg][inx+1] |= eperm32tab[2][(to_permute >>  8) & 0xff][1];
                
                sb[sg][inx  ] |= eperm32tab[3][(to_permute)       & 0xff][0];
                sb[sg][inx+1] |= eperm32tab[3][(to_permute)       & 0xff][1];
              }
          }
      }  
    initialized++;
  }

#include "setsalt.c"
#include "keytab.c"
#include "return.c"
#include "ufcpre.c"

