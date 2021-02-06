
/*
    Name        : runp.c
                  (c) 1992 rokstar @ dp1.com
    Revision    : Version 1.60 March 1992.
    Description : Experimental pre-encryption, generation engine.
    Licence     : you may NOT distribute this product, doing so will
                  forfeit any further releases.
*/

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <malloc.h>
#include <time.h>

static char *src = "prepare.c - v1.60 - (c) rokstar 1992";

/* for msdos/gcc ..
 */
#ifndef S_IREAD
#define S_IREAD 0
#endif

#ifndef S_IWRITE
#define S_IWRITE 0
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define BYTE unsigned char
#define psmall(s) printf(s),fflush(stdout)

struct w_rec {
  struct w_rec *next,
               *last;
         char  *word;
};

struct w_rec *wst,
             *wcur,
             *wtmp;

unsigned long w_total;

/* unused YET
    char *fnames[64];
*/

/* external for UFC */
char *fcrypt();

char *ppul(unsigned long numba)
{
   static char retul[32];
   char *pend;
   int ps,sn;

    sprintf(retul,"%lu",numba);
    retul[31]=ps=0;
    sn=strlen(retul);
    pend= &retul[30];
    while(++ps<=sn) {
        *(pend--) = retul[sn-ps];
        if(!(ps%3)) *(pend--) = ',';
    }
    if(*++pend==',') pend++;
    return(pend);
}

int yesno(msg)
char *msg;
/* simple yes/no input routine */
{
    char buf[10];

    printf("%s (Y/n) -> ",msg);
    fflush(stdout);
    do
     gets(buf);
    while(!strchr("YN",toupper(buf[0])));
    return(toupper(buf[0])=='Y');
}

void read_words(fname)
char *fname;
/* reads words into internal list */
{
    FILE *fp;
    char buf[255];

    if(!(fp=fopen(fname,"r"))) {
        puts("Fatal: Unable to open word file");
        exit(1);
    }

    printf("Wordfile   -> %s ",fname);
    wst=wcur=NULL;
    w_total=0;
    while(!feof(fp)) {
      buf[0]=0;
      fgets(buf,255,fp);
      buf[8]=buf[strlen(buf)-1]=0;
#ifdef LONGWORDS
      if(strlen(buf)>=6) {
#else
      if(buf[0]) {
#endif
       wtmp=(struct w_rec *)malloc(sizeof(struct w_rec));
       wtmp->word=strdup(buf);
        wtmp->next=NULL;
       if(!wcur)
         wst=wtmp;
       else
         wcur->next=wtmp;
       wtmp->last=wcur;
       wcur=wtmp;
       w_total++;
      }
    }
    fclose(fp);
    printf("[%lu words].\n",w_total);
}

void process_words()
/* sorts & uniq's words */
{
    struct w_rec *wsst,*wscur;
	unsigned long nt;
    char *wlast;

    wscur=wsst=NULL;
    wlast=NULL;
    nt=0;
    psmall("Preprocess -> Sorting/Uniqing, ");
    /* well fuck, i dont care, bubble sorts are my life, plus im no
       comsci.. all i study is ASM and PLD design! */
    while(wst) {
        wcur=wtmp=wst;
        while(wcur=wcur->next)
            if(strcmp(wcur->word,wtmp->word)<0) wtmp=wcur;

        if( (wlast) && (strcmp(wlast,wtmp->word)==0) ) {
          /* duplicated word */
#ifdef DEBUG
      printf("dup(%s)\n",wtmp->word);
#endif
         if(wtmp->last)
            wtmp->last->next=wtmp->next;
         else
            wst=wtmp->next;
         if(wtmp->next)
            wtmp->next->last=wtmp->last;
         free(wtmp->word);
         free(wtmp);
         w_total--;

        } else {
           if(wtmp->last)
               wtmp->last->next=wtmp->next;
           else
               wst=wtmp->next;
           if(wtmp->next)
              wtmp->next->last=wtmp->last;

          if(!wscur)
             wsst=wtmp;
          else
             wscur->next=wtmp;
          wtmp->last=wscur;
          wtmp->next=NULL;
          wscur=wtmp;
          wlast=wscur->word;
        }
    }
   wst=wsst;
   printf("[%lu words left].\n",w_total);
}

int write_words_index(wbase)
char *wbase;
/* writes the wordfile index */
{
    int wdat,widx,wofs;
    long *woffsetl,woffset;
    char indexname[81],dataname[81];

    woffsetl=(long *)malloc(sizeof(long) * (w_total+2));
    wofs=0;
    woffset=0;

    sprintf(dataname,"%s.DAT",wbase);
    if((wdat=open(dataname,O_RDWR|O_CREAT|O_BINARY,S_IREAD|S_IWRITE))<0) {
        free(woffsetl);
        return(0);
    }
    printf("\nWord DATA  -> %s.\n",dataname);
    wcur=wst;
    while(wcur) {
        write(wdat,(void *)wcur->word,(strlen(wcur->word)+1));
        woffsetl[wofs++]=woffset;
        woffset+=(long)(strlen(wcur->word)+1);
        wcur=wcur->next;
    }
    close(wdat);

    sprintf(indexname,"%s.IDX",wbase);
    if((widx=open(indexname,O_BINARY|O_RDWR|O_TRUNC|O_CREAT,S_IREAD|S_IWRITE))<0) {
            free(woffsetl);
            return(0);
    }
    printf("Word INDEX -> %s.\n\n",indexname);
    write(widx,(void *)woffsetl,(wofs*sizeof(long))); /* write the index */
    write(widx,(void *)&woffset,(sizeof(long)) ); /* write the size of data file */
    woffset=(wofs*sizeof(long));
    write(widx,(void *)&woffset,(sizeof(long)) ); /* write size of index file */
    close(widx);
    free(woffsetl);
    return(1);
}

void crypt_check()
/* checks UFC and displays time estimations */
{
    char passwd[14],
         word[8];
    int ok,i;
    unsigned long tst,ted;
    double retval;

#define NUMREPS 5000

    strcpy(word,"contact");
    strcpy(passwd,"XPYXtEl2UfrPQ");

    printf("\nUFC's cps (%4d iterations) -> ",NUMREPS);
    fflush(stdout);

    time(&tst);
    for(i=0;i<NUMREPS;i++)
        ok=strcmp(fcrypt(word,passwd),passwd);
    time(&ted);

    if(ok!=0) {
        puts("UFC IS NOT FUNCTIONING CORRECTLY!");
        exit(1);
    }

    retval=(double)(((double)NUMREPS)/((double)(ted-tst)));
    printf("%.2f crypts/sec.\n",retval);
    printf("Number of crypts needed     -> %s.\n",ppul((unsigned long)(w_total * 4096)));
    printf("Approx mins required        -> %.2f mins.\n",(double)(((w_total * 4096)/retval)/60));
    printf("Disk space required (est.)  -> %s bytes.\n\n", ppul((unsigned long)(w_total * 4096)));

    fflush(stdout);
}

#define ascii_to_bin(c) ((c)>='a'?(c-59):(c)>='A'?((c)-53):(c)-'.')
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')

int filexists(nm)
char *nm;
/* self explanatory */
{
    int f,ok;

    ok=f=open(nm,O_RDONLY);
    close(f);
    return(ok>=0);
}

void pre_crypt(cbase)
char *cbase;
/* the actual precrypt bit */
{
    BYTE salt0,salt1;
    int outf;
    unsigned bpos;
    char cryptfile[81];
    BYTE *buf;
    char *pwd;
    char salts[3];
    unsigned long tstart,tend;

    buf=(BYTE *)malloc( (sizeof(BYTE) * w_total) + 32);
    salts[2]=0;
    printf("Generating 64 MASTER x 64 SLAVE salts (00-3f) [4096 total].\n");
    printf(" -SL- ----------------------------------------------------------------");
    time(&tstart);
    for(salt0=0;salt0<64;salt0++) {
        salts[0]=bin_to_ascii(salt0);
        printf("\n  %02x  ",salt0);
        fflush(stdout);

        sprintf(cryptfile,"%s.%02x",cbase,salt0);
        if(filexists(cryptfile)) {
                printf("!!File Exists, Skipping Generation.");
        } else
        if((outf=open(cryptfile,O_BINARY|O_RDWR|O_CREAT,S_IREAD|S_IWRITE))>=0) {
         for(salt1=0;salt1<64;salt1++) {
            putchar('.');
            fflush(stdout);
            salts[1]=bin_to_ascii(salt1);
            bpos=0;
            wcur=wst;
        while(wcur!=NULL) {
                pwd=fcrypt(wcur->word,salts);
                /* this gives 256 possibilites */
                buf[bpos++]=(BYTE)( (BYTE)(pwd[3] << 6) |
                                    (BYTE)(pwd[2] & 0x3f) );
                /* push up 2 from [3] and overlay the 6 from [2] */
                wcur=wcur->next;
            }
            write(outf,(void *)buf,(sizeof(BYTE) * bpos));
         }
        close(outf);
        }
    }
    time(&tend);
    free(buf);
    printf("\n\nFinished pre-encryption -> %.2f minutes.\n",
                    ((double)(tend-tstart)?((tend-tstart)/60):0.0));
}

void main(argc,argv)
int argc;
char *argv[];
{
    char s[81];
    char wname[81];
    int nop,i,sorted;

    wname[0]=nop=sorted=0;

    puts("\n// PREC - pre-encryption fast generation utility.");
    puts("// Version 1.60 - (c) rokstar 1992.\n");

    for(i=1;i<argc;i++) {
        if(argv[i][0]=='-') {
            if(!strcmp(argv[i]+1,"nop")) nop=1;
              else
            if(!strcmp(argv[i]+1,"sorted")) sorted=1;
        } else {
            sprintf(wname,"%s%s",getenv("PREDIR"),argv[i]);
        }
    }

    if((argc<2) || (!wname[0])) {
        puts("Usage: PREC [-nop] [-sorted] <wordfile>");
        puts("       wordfile  = wordfile to process.");
        puts("       -nop      = dont ask for y/n prompt (for nohuping).");
        puts("       -sorted   = the wordfile is already sorted and uniqed.\n");
        exit(1);
    }
    read_words(wname);

if(!sorted)
    process_words();

    crypt_check();

    if(nop || yesno("Do you wish to continue this installation")) {

        if(!write_words_index(wname))
            puts("Fatal: Unable to create .IDX/.DAT file");

        pre_crypt(wname);

        puts("\nInstallation complete.\n");
        while(wtmp=wst) {
            wst=wst->next;
            free(wtmp->word);
            free(wtmp);
        }
    }
}

