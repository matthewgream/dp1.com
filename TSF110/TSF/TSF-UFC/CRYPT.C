
extern int output_conversion();
extern unsigned long sb0[], sb1[], sb2[], sb3[];
extern unsigned long keytab[16][2];

#define SBA(sb, v) (*(unsigned long*)((char*)(sb)+(v)))

#define F(I, O1, O2, SBX, SBY)                                        \
    s = *k++ ^ I;                                                     \
    O1 ^= SBA(SBX, (s & 0xffff)); O2 ^= SBA(SBX, ((s & 0xffff) + 4)); \
    O1 ^= SBA(SBY, (s >>= 16));   O2 ^= SBA(SBY, ((s)          + 4));

#define G(I1, I2, O1, O2)                                             \
        F(I1, O1, O2, sb1, sb0) F(I2, O1, O2, sb3, sb2)

#define H G(r1, r2, l1, l2) ; G(l1, l2, r1, r2)

int ufc(key, salt)
  char *key;
  char *salt;
  {
    unsigned long l1, l2, r1, r2, i, j;
    register unsigned long s,*k;

    l1=l2=r1=r2=0;

    for(j=0; j<25; j++) {
      k = &keytab[0][0];
      for(i=8; i--; ) {
            H;
      }
      s=l1; l1=r1; r1=s; s=l2; l2=r2; r2=s;
    }

    return output_conversion(l1, l2, r1, r2, salt);
  }

