
/*
    Name        : runp.c
                  (c) 1992 rokstar @ dp1.com
    Revision    : Version 2.00 March 1992.
    Description : Experimental pre-encryption, runtime executable.
    Licence     : you may NOT distribute this product, doing so will
                  forfeit any further releases.
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <ctype.h>
#include <malloc.h>
#include <string.h>
#include <time.h>

static char *src = "runp.c - Version 2.00 - (c) rokstar 1992";

/* maximum allowable size for internal disk cache, anything above 64 is
 * a waste of time , unless you have memory problems, or your wordfile
 * is very large, leave this at 64
 */
#define CACHESIZE 64

/* this option if played around with will give a slight amount of
 * optimization on machines with a not real great disk io. When optimizing
 * there will be periods of skipspace, ie salt chunks that dont get used
 * but are read into memory anyway, this figure determins the amount
 * of allowed sequential redundant chunks to read, if you want NONE, set it
 * to one
 */
#define CACHESKIP 8

/* for gcc and messydos
 */
#ifndef O_BINARY
#define O_BINARY 0
#endif

#define BYTE unsigned char

/* structs
 */
struct pw_rec {
    struct pw_rec   *last,
                    *next;
             char   *login,
                    *passwd,
                    *rest;
             BYTE   pre;
             BYTE   opt;
};


/* globals and externals
 */

char *fcrypt();

long *woffsetl,
     tot_words,
     indexsize,
     datasize;

char *wbuf;

unsigned long pw_total=0,
              tot_compares=0;

struct pw_rec *pwst,
              *pwcur,
              *pwtmp;


/* rokstar '#define macros are my life' heh
 */

#define ascii_to_bin(c) ((c)>='a'?(c-59):(c)>='A'?((c)-53):(c)-'.')
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')
#define psmall(s) printf(s),fflush(stdout)

#define pw_free(pw_tofree) { \
    if (pw_tofree) { \
            if(pw_tofree->login) free(pw_tofree->login); \
            if(pw_tofree->passwd) free(pw_tofree->passwd); \
            if(pw_tofree->rest) free(pw_tofree->rest); \
            free(pw_tofree); \
        } \
}

struct pw_rec *pw_delink(pwdel)
struct pw_rec *pwdel;
{
    static struct pw_rec *pwret;

    pwtmp=pwdel;
    pwret=pwdel->next;

    if(pwdel->last)
         pwdel->last->next=pwdel->next;
    else
         pwst=pwdel->next;

    if(pwdel->next)
         pwdel->next->last=pwdel->last;

    pw_free(pwtmp);
    pw_total--;
    return(pwret);
}

#ifdef EIGHTYCUT
char obuf[255];
#define pw_cracked(pwdel,dpwd) { \
        sprintf(obuf,"%-8s - %s:%s:%s", \
                               dpwd, \
                               pwdel->login,\
                               pwdel->passwd, \
                               pwdel->rest); \
        obuf[79]=0; \
        puts(obuf); \
    }

#else
#define pw_cracked(pwdel,dpwd) printf("%-8s - %s:%s:%s\n", dpwd, \
                               pwdel->login,\
                                 pwdel->passwd, pwdel->rest);

#endif

struct pw_rec *pw_alloc(p1,p2,p3)
char *p1, *p2, *p3;
{
  struct pw_rec *pwret;

  if ( ((pwret=(struct pw_rec *)malloc(sizeof(struct pw_rec)))==NULL) ||
       ((pwret->login=(char *)malloc(strlen(p1)+1))==NULL) ||
       (( pwret->passwd=(char *)malloc(strlen(p2)+1) )==NULL) ||
       (( pwret->rest=(char *)malloc(strlen(p3)+1) )==NULL) ) {
        fprintf(stderr,"Malloc died");
        exit(1);
       }

    strcpy(pwret->login,p1);
    strcpy(pwret->passwd,p2);
    strcpy(pwret->rest,p3);
    pwret->pre=(BYTE)( (BYTE)(pwret->passwd[3] << 6) |
                       (BYTE)(pwret->passwd[2] &  0x3f) );
    pwret->next=NULL;
    pwret->last=NULL;

    return(pwret);
}

char *pw_strip(ptr)
char *ptr;
{
    while(*ptr && *ptr!=':')
            ptr++;
    if(*ptr==':')
        *ptr++=0;
    return(ptr);
}

void pw_readfile(pwdfile)
char *pwdfile;
{
    char *ptr1, *ptr2, *ptr3,
         buf[255];
    FILE *fp;

    pwst=pwcur=NULL;
    if (!(fp=fopen(pwdfile,"r"))) {
            fprintf(stderr,"Fatal: Unable to open passwd file '%s'\n",pwdfile);
            exit(1);
    }

     printf("Loading passwds  -> %s ",pwdfile);

    while(!feof(fp)) {

            buf[0]=0;
            fgets(buf,255,fp);
            if(buf[0]) buf[strlen(buf)-1]=0;
        
            if( buf[0] && strchr(buf,':') )
            {
                ptr1=buf;
                ptr2=pw_strip(ptr1);
                ptr3=pw_strip(ptr2);
                if (strlen(ptr1)<=8) {
                    pwtmp=pw_alloc(ptr1,ptr2,ptr3);

                    if (!pwcur)
                        pwst=pwtmp;
                      else
                        pwcur->next=pwtmp;

                    pwtmp->last=pwcur;
                    pwtmp->next=NULL;
                    pwcur=pwtmp;
                    pw_total++;
                }
            }
    }

    fclose(fp);
    printf("[%lu accounts].\n",pw_total);
}

void pw_preprocess()
{
    struct pw_rec *pwst_s=NULL,*pwcur_s=NULL;
    unsigned long ctmp;

     psmall("Preprocessing    -> Sorting, ");

    while(pwst) {

        pwtmp=pwst;

        for(pwcur=pwst;(pwcur);pwcur=pwcur->next)
           if (strcmp(pwcur->passwd,pwtmp->passwd)<0)
                    pwtmp=pwcur;

        if (pwtmp->last)
             pwtmp->last->next=pwtmp->next;
          else
             pwst=pwtmp->next;

        if (pwtmp->next)
             pwtmp->next->last=pwtmp->last;

        if (pwcur_s)
             pwcur_s->next=pwtmp;
          else
             pwst_s=pwtmp;

        pwtmp->next=NULL;
        pwtmp->last=pwcur_s;
        pwcur_s=pwtmp;
       }

       pwst=pwst_s;

      ctmp=pw_total;
      psmall("Rejecting, ");

      for(pwcur=pwst;(pwcur);) {
            if (!pwcur->passwd[0])
                        pwcur=pw_delink(pwcur);
            else {
                    if ( (strlen(pwcur->passwd)<13) ||
                       strchr(pwcur->passwd,'*') ||
                       strchr(pwcur->passwd,'#') ||
                       strchr(pwcur->passwd,'%') ||
                       strchr(pwcur->passwd,' ') ||
                       strchr(pwcur->passwd,'!') )
                         pwcur=pw_delink(pwcur);
                    else
                         pwcur=pwcur->next;
            }
    }
    printf("[%lu acnts left].\n",pw_total);
}

void pw_optimize()
{
    BYTE s0tmp,s1tmp,opd;
    unsigned long oldreads,newreads;

    oldreads=newreads=0;
    psmall("Cache optimizing -> ");
    pwcur=pwst;
    while(pwcur) {
        if(!((s0tmp==pwcur->passwd[0]) && (s1tmp==pwcur->passwd[1])))
        {
          s0tmp=pwcur->passwd[0];
          s1tmp=pwcur->passwd[1];
          oldreads++;
        }
        pwcur=pwcur->next;
    }
    printf("oldreads=%lu, ",oldreads);
    pwcur=pwst;
    while(pwcur) {
        pwtmp=pwcur;
        s1tmp=s0tmp=(BYTE)ascii_to_bin(pwcur->passwd[1]);
        while( ( pwtmp ) &&
               ( pwtmp->passwd[0] == pwcur->passwd[0]) &&
               ( ( (ascii_to_bin(pwtmp->passwd[1])) - s1tmp) < CACHESKIP ) &&
               ( ( (ascii_to_bin(pwtmp->passwd[1])) - s0tmp) < CACHESIZE )
             ) {
            s1tmp=(BYTE)ascii_to_bin(pwtmp->passwd[1]);
            opd=pwtmp->opt=(BYTE)( s1tmp - s0tmp);
            pwtmp=pwtmp->next;
        }
        newreads++;
        pwcur->opt=(BYTE)( (opd+1) | 0x80);
        pwcur=pwtmp;
    }
    printf("newreads=%lu (%.2f%% reduction)\n",
        newreads,
        (double)((((double)oldreads-(double)newreads)/(double)oldreads) * (double)100.00 ) );

}

int read_words(wname)
char *wname;
{
    char wfn[81];
    int wf;

    sprintf(wfn,"%s.IDX",wname);
    if((wf=open(wfn,O_RDONLY|O_BINARY))<0) return(0);
     lseek(wf, -(2 * (sizeof(long))), L_XTND );
     read(wf,(void *)&datasize,sizeof(long));
     read(wf,(void *)&indexsize,sizeof(long));
     tot_words=(indexsize/sizeof(long));

     printf("Loading indexes  -> %s [%lu words].\n", wname,tot_words);
     printf("Dataset sizes    -> %ld,IDX - %ld,SLT.\n", indexsize,datasize);

     woffsetl=(long *)malloc(indexsize+4);
     lseek(wf,0L,L_SET);
     read(wf,(void *)woffsetl,(indexsize));
     close(wf);

     sprintf(wfn,"%s.DAT",wname);
    if((wf=open(wfn,O_RDONLY|O_BINARY))<0) return(0);
     wbuf=(char *)malloc(datasize+4);
     read(wf,(void *)wbuf,(datasize));
     close(wf);

    return(1);
}

void pw_crack(fpref)
register char *fpref;
{
    register BYTE lsalt0=0xff,lsalt1=0xff,salt0,salt1;
    BYTE *pbuf;
    register unsigned int j;
    int fw;
    char fname[81];
    unsigned long tstart,tend;
    char *wptr;
    long blocksize;
    unsigned long rval;
    BYTE *boffs;

    unsigned long ncompares,ncrypts,ncracked,nacnts,plogin;

    printf("\n");
    plogin=nacnts=ncompares=ncrypts=ncracked=0;
    blocksize=(tot_words * sizeof(BYTE));
    pbuf=(BYTE *)malloc((CACHESIZE * blocksize)+16);
    if(!pbuf) {
       fprintf(stderr,"\nmalloc could not allocate CACHESIZE (%d)\n",CACHESIZE);
       exit(1);
    }

    time(&tstart);
    pwcur=pwst;
    while(pwcur) {
      nacnts++;
#ifdef DEBUG
    printf("Checking -> %s / %s\n",pwcur->login,pwcur->passwd);
#endif

#ifdef DEBUG
      printf("opt: %d\n",pwcur->opt);
#endif
      if(pwcur->opt & (BYTE)0x80) {

            salt0=ascii_to_bin(pwcur->passwd[0]);
            salt1=ascii_to_bin(pwcur->passwd[1]);

            sprintf(fname,"%s.%02x",fpref,salt0);
            if((fw=open(fname,O_RDONLY|O_BINARY))<0)
                fprintf(stderr,"Fatal: Couldnt open '%s'\n",fname);
            else {
                lseek(fw,(long)(salt1 * blocksize),L_SET);
                rval=read(fw,(void *)pbuf,(blocksize * (pwcur->opt & 0x7f)) );
#ifdef DEBUG
                printf("debug-> rval(%lu) - bsize(%lu)\n",
                          rval,
                          (blocksize * (pwcur->opt & 0x7f)) );
#endif
                close(fw);
            }
            boffs=pbuf;
      } else {
            boffs=(pbuf+(blocksize * pwcur->opt));
      }

#ifdef CHECKLOGIN
      ncrypts++;
      if(!strcmp(pwcur->passwd,fcrypt(pwcur->login,pwcur->passwd))) {
                ++plogin;
                ++ncracked;
                pw_cracked(pwcur,pwcur->login);
      } else
#endif

      { register BYTE p_pre = pwcur->pre;

          for(j=0;j<blocksize;j++) {
          ++ncompares;
          if(p_pre==(BYTE)(*boffs++)) {
            wptr=(wbuf+woffsetl[j]);
            ++ncrypts;
            if(!strcmp(pwcur->passwd,fcrypt(wptr,pwcur->passwd))) {
                j=blocksize;
                ++ncracked;
                pw_cracked(pwcur,wptr);
            }
          }
        }

      }
      pwcur=pwcur->next;
    }
    time(&tend);
    free(pbuf);

     printf("\nExecution time   -> %lu seconds [%lu accounts].\n",
                                    (tend-tstart),
                                    nacnts);
     printf("Compares/crypts  -> %lu compares, %lu crypts.\n",ncompares,ncrypts);
#ifdef CHECKLOGIN
     printf("Accounts cracked -> %lu [%lu %s login=passwd].\n",
                ncracked,plogin,(plogin==1)?"was":"were");
#else
     printf("Accounts cracked -> %lu.\n",ncracked);
#endif
     printf("Account averages -> %.2f REAL crypts/acnt, %.2f seconds/acnt.\n",
                            (double)((double)ncrypts / (double)nacnts),
                            (double)((double)(tend-tstart) / (double)nacnts) );
     printf("EFFECTIVE cps    -> %.2f crypts/second.\n",
                            (double)(tend-tstart)?((double)(ncompares+ncrypts)/(double)(tend-tstart)):0.0 );

}

void main(argc,argv)
int argc;
char *argv[];
{
    char wordfname[81];
    unsigned long ttime;

    woffsetl=NULL;
    wbuf=NULL;

    puts("\n// RUNP - pre-encryption fast runtime executable.");
      puts("// Version 2.00 - Rokstar March 1992.\n");

    if(argc!=3) {
        puts("Usage: RUNP <wordfile> <pwdfile>");
        puts("       wordfile = worfile being used to crack with.");
        puts("       pwdfile  = passwd file to process.\n");
        exit(1);
    }

    time(&ttime);
     printf("Local start time -> %s\n",ctime(&ttime));

    pw_readfile(argv[2]);
    pw_preprocess();
    pw_optimize();

    strcpy(wordfname,getenv("PREDIR"));
    strcat(wordfname,argv[1]);
    if(!read_words(wordfname)) {
        fprintf(stderr,"\nFatal: Couldnt read word files '%s.IDX/.DAT'\n",argv[1]);
        if(woffsetl) free(woffsetl);
        exit(1);
    }

   pw_crack(wordfname);

   time(&ttime);
   printf("\nLocal exit time  -> %s\n",ctime(&ttime));
   if(woffsetl)
        free(woffsetl);
   if(wbuf)
        free(wbuf);
}

