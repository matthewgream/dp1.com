
void mk_keytab(key)
  char *key;
  {
    static int i;
    register unsigned long *mkt,*k;
    register char t;

        bzero((char*)keytab, sizeof keytab);
        mkt = &mk_keytab_table[0][0][0][0];

        for(i=0; (t=(*key++) & 0x7f) && i<8; i++) {
           k = &keytab[0][0];
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
           *k++ |= mkt[t]; mkt += 128;
    }

        for(; i<8; i++) {
           k = &keytab[0][0];
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
           *k++ |= mkt[0]; mkt += 128;
    }
}

