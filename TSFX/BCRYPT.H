
/**/
#define NON_NETORDER    1
/**/

/**/
#define INT_32BIT       1
/**/

/*=[ General Definitions ]==================================================*/

#define REG     register

#ifdef INT_32BIT
#define U32     unsigned int
#else
#define U32     unsigned long
#endif

/*=[ Union: char_union ]====================================================*/

#ifdef NON_NETORDER
union char_union {
    struct {
        unsigned    b0:1;
        unsigned    b1:1;
        unsigned    b2:1;
        unsigned    b3:1;
        unsigned    b4:1;
        unsigned    b5:1;
        unsigned    b6:1;
        unsigned    b7:1;
    } bits;
    char c;
};
#else
union char_union {
    struct {
        unsigned    b7:1;
        unsigned    b6:1;
        unsigned    b5:1;
        unsigned    b4:1;
        unsigned    b3:1;
        unsigned    b2:1;
        unsigned    b1:1;
        unsigned    b0:1;
    } bits;
    char c;
};
#endif

/*=[ Union: BU32 ]==========================================================*/

#ifdef NON_NETORDER
typedef union {
    /* individiual bits */
    struct {
        unsigned  b0:1;
        unsigned  b1:1;
        unsigned  b2:1;
        unsigned  b3:1;
        unsigned  b4:1;
        unsigned  b5:1;
        unsigned  b6:1;
        unsigned  b7:1;
        unsigned  b8:1;
        unsigned  b9:1;
        unsigned  b10:1;
        unsigned  b11:1;
        unsigned  b12:1;
        unsigned  b13:1;
        unsigned  b14:1;
        unsigned  b15:1;
        unsigned  b16:1;
        unsigned  b17:1;
        unsigned  b18:1;
        unsigned  b19:1;
        unsigned  b20:1;
        unsigned  b21:1;
        unsigned  b22:1;
        unsigned  b23:1;
        unsigned  b24:1;
        unsigned  b25:1;
        unsigned  b26:1;
        unsigned  b27:1;
        unsigned  b28:1;
        unsigned  b29:1;
        unsigned  b30:1;
        unsigned  b31:1;
    } N;
    /* Feldmeier expansion part 0 */
    struct {
        unsigned z2:2;
        unsigned b13_2:12;
        unsigned z1:4;
        unsigned b29_18:12;
        unsigned z0:2;
    } FE0;
    /* Feldmeier expanion part 1 */
    struct {
        unsigned b5_0:6;
        unsigned z1:4;
        unsigned b21_10:12;
        unsigned z0:4;
        unsigned b31_26:6;
    } FE1;
    struct {
        unsigned b5_0:6;
        unsigned b11_6:6;
        unsigned z1:10;
        unsigned z0:10;
    } F12;
    struct {
        unsigned b30_31:2;
        unsigned b24_29:6;
        unsigned b18_23:6;
        unsigned b12_17:6;
        unsigned b6_11:6;
        unsigned b0_5:6;
    } B6;
    struct {
        unsigned b28_31:4;
        unsigned b22_27:6;
        unsigned b16_21:6;
        unsigned b10_15:6;
        unsigned b4_9:6;
        unsigned b0_3:4;
    } B6_;
    U32 U;
} BU32;
#else
typedef union {
    /* individual bits */
    struct {
        unsigned  b31:1;
        unsigned  b30:1;
        unsigned  b29:1;
        unsigned  b28:1;
        unsigned  b27:1;
        unsigned  b26:1;
        unsigned  b25:1;
        unsigned  b24:1;
        unsigned  b23:1;
        unsigned  b22:1;
        unsigned  b21:1;
        unsigned  b20:1;
        unsigned  b19:1;
        unsigned  b18:1;
        unsigned  b17:1;
        unsigned  b16:1;
        unsigned  b15:1;
        unsigned  b14:1;
        unsigned  b13:1;
        unsigned  b12:1;
        unsigned  b11:1;
        unsigned  b10:1;
        unsigned  b9:1;
        unsigned  b8:1;
        unsigned  b7:1;
        unsigned  b6:1;
        unsigned  b5:1;
        unsigned  b4:1;
        unsigned  b3:1;
        unsigned  b2:1;
        unsigned  b1:1;
        unsigned  b0:1;
    } N;
    /* Feldmeier expansion part 0 */
    struct {
        unsigned z0:2;
        unsigned b29_18:12;
        unsigned z1:4;
        unsigned b13_2:12;
        unsigned z2:2;
    } FE0;
    /* Feldmeier expanion part 1 */
    struct {
        unsigned b31_26:6;
        unsigned z0:4;
        unsigned b21_10:12;
        unsigned z1:4;
        unsigned b5_0:6;
    } FE1;
    struct {
        unsigned z0:10;
        unsigned z1:10;
        unsigned b11_6:6;
        unsigned b5_0:6;
    } F12;
    struct {
        unsigned  b0_5:6;
        unsigned  b6_11:6;
        unsigned  b12_17:6;
        unsigned  b18_23:6;
        unsigned  b24_29:6;
        unsigned  b30_31:2;
    } B6;
    struct {
        unsigned  b0_3:4;
        unsigned  b4_9:6;
        unsigned  b10_15:6;
        unsigned  b16_21:6;
        unsigned  b22_27:6;
        unsigned  b28_31:4;
    } B6_;
    U32 U;
} BU32;
#endif

/*=[ Structure: BU64 ]======================================================*/

typedef struct {
    BU32 L, R;
} BU64;

/*=[ Static Tables ]========================================================*/

/* Shifts (shifts[]), Minus 1 */
static char SHIFTS_M1[] =
 {
  0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0,
 };

/*
** The 8 original selection functions.  For some reason, they give
** a 0-origin index, unlike everything else.
*/
static char OS[8][64] =
 {
  14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
   0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
   4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
  15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13,

  15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
   3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
   0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
  13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9,

  10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
  13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
  13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
   1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12,

   7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
  13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
  10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
   3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14,

   2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
  14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
   4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
  11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3,

  12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
  10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
   9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
   4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13,

   4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
  13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
   1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
   6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12,

  13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
   1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
   7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
   2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11,
 };


BU64 bcrypt_encode();
void bcrypt_salt_to_E();
void bcrypt_set_word();
BU64 bcrypt_pw_to_BU64();
void bcrypt_done();
void bcrypt_init();

