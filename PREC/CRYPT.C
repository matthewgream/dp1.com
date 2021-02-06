
#include "ufc-crypt.h"

extern ufc_long *_ufc_dofinalperm();

/*
 * 32 bit version
 */

extern long32 _ufc_keytab[16][2];
extern long32 _ufc_sb0[], _ufc_sb1[], _ufc_sb2[], _ufc_sb3[];

#define SBA(sb, v) (*(long32*)((char*)(sb)+(v)))

ufc_long *_ufc_doit(l1, l2, r1, r2, itr)
  ufc_long l1, l2, r1, r2, itr;
  { int i;
    long32 s, *k;

    while(itr--) {
      k = &_ufc_keytab[0][0];
      for(i=8; i--; ) {
	s = *k++ ^ r1;
	l1 ^= SBA(_ufc_sb1, s & 0xffff); l2 ^= SBA(_ufc_sb1, (s & 0xffff)+4);  
        l1 ^= SBA(_ufc_sb0, s >>= 16);   l2 ^= SBA(_ufc_sb0, (s)         +4); 
        s = *k++ ^ r2; 
        l1 ^= SBA(_ufc_sb3, s & 0xffff); l2 ^= SBA(_ufc_sb3, (s & 0xffff)+4);
        l1 ^= SBA(_ufc_sb2, s >>= 16);   l2 ^= SBA(_ufc_sb2, (s)         +4);

        s = *k++ ^ l1; 
        r1 ^= SBA(_ufc_sb1, s & 0xffff); r2 ^= SBA(_ufc_sb1, (s & 0xffff)+4);  
        r1 ^= SBA(_ufc_sb0, s >>= 16);   r2 ^= SBA(_ufc_sb0, (s)         +4); 
        s = *k++ ^ l2; 
        r1 ^= SBA(_ufc_sb3, s & 0xffff); r2 ^= SBA(_ufc_sb3, (s & 0xffff)+4);  
        r1 ^= SBA(_ufc_sb2, s >>= 16);   r2 ^= SBA(_ufc_sb2, (s)         +4);
      } 
      s=l1; l1=r1; r1=s; s=l2; l2=r2; r2=s;
    }
    return _ufc_dofinalperm(l1, l2, r1, r2);
  }

