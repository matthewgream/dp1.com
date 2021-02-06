
void ufc_preprocess(ret,pw)
char *ret;
char *pw;
{
    register int i;
    for(i=0;i<13;i++) {
        ret[i]=ascii_to_bin(pw[i]);
    }
}
