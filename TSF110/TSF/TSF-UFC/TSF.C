/*
       -=UFc Version=-
       the modified UFC by rokk.
*/

/********************* The following contains defines you can modify */

#ifndef NETWORK
#define PWDFILE "passwd"
#define LOGFILE "hits.out"
#endif
#define WORDFILE "words"

#define PREFIX "0123456789!"
#define SUFFIX "0123456789!"

#define SHOW_INVALID 1

#define DUMP_UNCRACKED 1

#define IMMEDIATE 1

/*
#define OUT_STDIO 1
*/
#define OUT_LOG 1

/*
#define SHOWSOMETHING 1
*/

#define OUT_ALWAYSOPEN 1

/********************* You should leave these defines as they are */

#define VERSION "V1.00UX-ufc[PR]"

#ifdef SHOWSOMETHING
#define show_try() printf("Trying: %-10s\r",pwcur->login)
#else
#define show_try() ;
#endif

/* debug iz for ME!
#define DEBUG 1
*/

/********************* Include Files Used */

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>

/* externals for ufc */
#ifdef TSF_UFC
int ufc();
void ufc_preprocess();
#else
char *crypt();
#endif
void init_des();
void setup_salt();
/********************* Structures and global variables */

#ifndef IMMEDIATE
struct cq_rec {
    struct cq_rec   *next;
             char   *logrec;
        };

struct cq_rec *cqst=NULL,
              *cqcur=NULL,
              *cqtmp;
#endif

struct pw_rec {
    struct pw_rec   *last,
                    *next;
             char   *login,
                    *passwd,
                    *rest;
};

struct pw_rec *pwst=NULL,
              *pwcur=NULL,
              *pwres=NULL,
              *pwtmp;

struct w_rec {
        struct w_rec  *next;
                char  *word;
 };

struct w_rec *wst=NULL,
             *wcur=NULL,
             *wtmp;

unsigned long w_total=0,
              pw_total=0,
              pass_total=0,
              pass_compares=0,
              tot_total=0,
              tot_compares=0;

unsigned long ctmp=0;

FILE          *w_file,
              *pw_file;

#ifdef OUT_LOG
FILE          *log_file;
#endif

char    buf[255],
        buf1[255],
        suf[80],
        pref[80],
        pw_res[20],
        pass_res='\0',
        bool=0,
        inpass=0;

time_t  pass_start=0,
        pass_time=0,
        timetemp=0,
        tot_time=0;

/********************* Start of Routines and Main Code */

void tsf_blog(s)
char *s;
{
#ifdef OUT_LOG
        if (log_file==NULL)
                    log_file=fopen(LOGFILE,"a");
        fprintf(log_file,"%s\n",s);
#endif
#ifdef OUT_STDIO
        printf("%s\n",s);
#endif
}

#ifdef OUT_ALWAYSOPEN
#define tsf_log(s) tsf_blog(s)
#else
#define tsf_log(s) tsf_blog(s), fclose(log_file), log_file=NULL
#endif

#define upcase(ch) ((ch > '`') && (ch < '{'))?(ch-32):ch;

#define pw_free(pw_tofree) { \
    if (pw_tofree) { \
            if(pw_tofree->login) free(pw_tofree->login); \
            if(pw_tofree->passwd) free(pw_tofree->passwd); \
            if(pw_tofree->rest) free(pw_tofree->rest); \
            free(pw_tofree); \
        } \
}

#define w_free(w_tofree) { \
    if (w_tofree) { \
            if(w_tofree->word) free(w_tofree->word); \
            free(w_tofree); \
        } \
}

#ifndef IMMEDIATE
void tsf_dumpcq()
{
    while(cqst) {
        tsf_blog(cqst->logrec);
        cqtmp=cqst;
        cqst=cqst->next;
        if (cqtmp) {
            if (cqtmp->logrec) free(cqtmp->logrec);
            free(cqtmp);
        }
    }
}
#else
#define tsf_dumpcq() ;
#endif


void pw_dump(pw_sdump, type)
struct pw_rec *pw_sdump;
char *type;
{
        while(pw_sdump)
         {
            sprintf(buf1,"%s%s:%s:%s",
                                type,
                                pw_sdump->login,
                                pw_sdump->passwd,
                                pw_sdump->rest);
            tsf_blog(buf1);
            pw_sdump=pw_sdump->next;
        }
 }

void pass_end()
{
     pass_time=time(&timetemp)-pass_start;
     tot_time+=pass_time;
     tot_compares+=pass_compares;
     tot_total+=pass_total;
     inpass=0;
     pwres=NULL;
     tsf_dumpcq();
     sprintf(buf,"S; \nS; --[Ended: crack. AC:%lu. C:%lu T:%lu = %.2f C/S]----------\nS; ",pass_total,pass_compares,pass_time,(pass_time)?((double)pass_compares/pass_time):0);
     tsf_log(buf);
}

void tsf_die(errmsg,exitcode)
char *errmsg;
int exitcode;
{

#ifndef IMMEDIATE
    if (cqst) {
            tsf_blog("S; Termination Occured with Stack not Empty!:");
            tsf_dumpcq();
        }
#endif

#ifdef DUMP_UNCRACKED
if ( (pwst) && tot_compares) {   /* no use dumping if there was no cracking! */
    tsf_blog("S; dumping uncracked accounts:\nS; ");
    pw_dump(pwst,"U; ");
    tsf_blog("S; ");
}
#endif

    while(pwst) {
            pwtmp=pwst->next;
            pw_free(pwst);
            pwst=pwtmp;
        }

    while(wst)  {
            wtmp=wst->next;
            w_free(wst);
            wst=wtmp;
        }

    sprintf(buf1,"S; tsf_die!(X %d): %s",exitcode,errmsg);
    tsf_blog(buf1);

    if (tot_compares) {
        sprintf(buf1,"S; total compares: %lu. total time: %lu secs. total cracked: %lu.\nS; computed overall efficiency was %.2f crypts/sec.",
                tot_compares,
                tot_time,
                tot_total,
                ( (double)tot_compares/tot_time ));
        tsf_blog(buf1);
    }

    tsf_log("-=-=-=-");
    if(w_file)
        fclose(w_file);
    if(pw_file)
        fclose(pw_file);

#ifdef NETWORK
    FILE *fp;
    if( (fp=fopen(NETFILE,"r")) ) {
        fprintf(fp,"H: %-20s A: %4lu T: %8lu C: %8lu E: %.2f\n",
            HOST,
            tot_total,
            tot_time,
            tot_compares,
            ( (double)tot_compares/tot_time ) );
        fclose(fp);
    }
#endif

    exit(exitcode);
}


int sig()
{

    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT,SIG_IGN);

    if(inpass) {
            pass_end();
            sprintf(buf,"got SIGNAL. user='%s'. pwd='%s'",
            (pwcur)?pwcur->login:"None.",
            (pwcur)?pwcur->passwd:"None.");
    } else strcpy(buf,"got SIGNAL. Not in crack phase");
    tsf_die(buf,1);
    return(0);
}

void crypt_check()
{
    char passwd[14],
         binpasswd[14],
         word[8];

    strcpy(word,"contact");
    strcpy(passwd,"XPYXtEl2UfrPQ");

#ifdef TSF_UFC
    ufc_preprocess(binpasswd,passwd);
    setup_salt(binpasswd);
#else
    setup_salt(passwd);
#endif
    mk_keytab(word);

#ifdef TSF_UFC
        if ( ufc(word,binpasswd) )
#else
        if ( strcmp(crypt(word,passwd),passwd)==0)
#endif
            {
                tsf_log("S; UFC engine self-test succeeded.");
            }
        else {
                tsf_die("Fatal: UFC is NOT working",-1);
            }
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
    return(pwret);
}

struct pw_rec *tsf_cracked(pwdel, type, dpwd)
struct pw_rec *pwdel;
char *type;
char *dpwd;
{
        pass_total++;
        sprintf(buf,"%s%-8s - %s:%s:%s",type,dpwd,pwdel->login,
                                                pwdel->passwd,
                                                pwdel->rest);
#ifdef IMMEDIATE
        tsf_log(buf);
#else
        cqtmp=NULL;
        if (  ((cqtmp=(struct cq_rec *)malloc(sizeof(struct cq_rec)))==NULL) ||
              ((cqtmp->logrec=(char *)malloc(strlen(buf)+1))==NULL)
           ) {
                    tsf_log(buf); /* if we dont have mem, just log the fucker */
                    if (cqtmp) {
                            if (cqtmp->logrec) free(cqtmp->logrec);
                            free(cqtmp);
                        }
                }
        else {
                    strcpy(cqtmp->logrec,buf);
                    cqtmp->next=NULL;
                    if(!cqcur)
                       cqst=cqtmp;
                     else
                       cqcur->next=cqtmp;
                    cqcur=cqtmp;
            }
#endif

#ifdef SHOWSOMETHING
  buf[79]='\0';
  printf("%s\n",buf);
#endif

 return(pw_delink(pwdel));
}


struct pw_rec *pw_alloc(p1,p2,p3)
char    *p1,
        *p2,
        *p3;
{
    struct pw_rec *pwret;

  if ( ((pwret=(struct pw_rec *)malloc(sizeof( struct pw_rec)))==NULL) ||
       ((pwret->login=(char *)malloc(strlen(p1)+1))==NULL) ||
       (( pwret->passwd=(char *)malloc(strlen(p2)+1) )==NULL) ||
       (( pwret->rest=(char *)malloc(strlen(p3)+1) )==NULL) )
                    tsf_die("Fatal: malloc died on pw_rec",-1);

    strcpy(pwret->login,p1);
    strcpy(pwret->passwd,p2);
    strcpy(pwret->rest,p3);
    pwret->next=NULL;
    pwret->last=NULL;

    return(pwret);
}

char *pw_strip(ptr)
char    *ptr;
{
    while ( *ptr && *ptr!=':')
            ptr++;
    if (*ptr==':')
                 *ptr++='\0';
    return(ptr);
}

void pw_readfile()
{
    char          *ptr1,
                  *ptr2,
                  *ptr3;

    if (!(pw_file=fopen(PWDFILE,"r")))
            tsf_die("Fatal: unable to open PWDFILE.",-1);

    while(!feof(pw_file))
        {
            buf[0]='\0';  /* stupid turboc */
            fgets(buf,255,pw_file);
            buf[strlen(buf)-1]='\0';
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
                    pwcur=pwtmp;
                    pw_total++;
                }
            }
        }

    fclose(pw_file);
    pw_file=NULL;
    sprintf(buf,"S; read_passwds('%s'): got %lu accounts.",
                                        PWDFILE,
                                        pw_total);
    tsf_blog(buf);
}

void w_addword(word)
char *word;
{

    if ( (wtmp=(struct w_rec *)malloc(sizeof(struct w_rec)))==NULL ||
          (wtmp->word=(char *)malloc(strlen(word)+1))==NULL )
                     tsf_die("Fatal: malloc died on w_rec",-1);

        strcpy(wtmp->word,word);
        wtmp->next=NULL;

        if (!wcur)
             wst=wtmp;
        else
             wcur->next=wtmp;
        wcur=wtmp;
        w_total++;
}


void w_readfile()
{
    if (!(w_file=fopen(WORDFILE,"r")))
            tsf_die("Fatal: unable to open WORDFILE",-1);

    while(!feof(w_file)) {

            buf[0]='\0'; /* stupid turboc */
            fgets(buf,255,w_file);
            buf[ (strlen(buf)>8)?8:(strlen(buf)-1)]='\0';
            if(buf[0])
                w_addword(buf);
     }

     fclose(w_file);

     sprintf(buf,"S; read_words('%s'): got %lu words.",
                                        WORDFILE,
                                        w_total);
     tsf_blog(buf);

}

void pw_preprocess(res)
char *res;
{
    struct pw_rec *pwst_s=NULL,*pwcur_s=NULL;

    ctmp=0;
    while(pwst) {

        ctmp++;
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
       sprintf(buf,"S; sorted %lu password records by salts.",ctmp);
       tsf_blog(buf);

       if(res[0]) {
          sprintf(buf,"S; restoring at acnt->passwd='%s'",res);
          tsf_blog(buf);
          for(pwcur=pwst;(pwcur)&&(!pwres);pwcur=pwcur->next)
                if (! strncmp(pwcur->passwd,res,strlen(res)) )
                        pwres=pwcur;
          if(!pwres)
            tsf_die("could not restore at specified account",-1);
       }

       ctmp=0;
       tsf_blog("S; \nS; --[Started pass: preprocess.]----------\nS; ");
       pass_total=0;
      for(pwcur=pwst;(pwcur);) {
            if (!pwcur->passwd[0])
                        pwcur=tsf_cracked(pwcur,"C; ","*blank");
            else {
                    if ( (strlen(pwcur->passwd)<13) ||
                       strchr(pwcur->passwd,'*') ||
                       strchr(pwcur->passwd,'#') ||
                       strchr(pwcur->passwd,'%') ||
                       strchr(pwcur->passwd,' ') ||
                       strchr(pwcur->passwd,'!') )
                         pwcur=tsf_cracked(pwcur,"I; ","*invalid"),ctmp++,pass_total--;
                    else pwcur=pwcur->next;
        }
    }
    tsf_dumpcq();
    sprintf(buf,"S; \nS; --[Ended: preprocess. got %lu blank, %lu invalid acnts]----------\nS; ",pass_total,ctmp);
    tsf_log(buf);

}

void tsf_crack()
{
    static char binpasswd[14];
    static char *ptr,*pos;
    static char wtemp[16];

    inpass=1;
    tsf_log("S; --[Started: crack]----------\nS; ");
    pass_compares=0;
    pass_total=0;
    pwcur=(pwres)?pwres:pwst;
    pass_start=time(&timetemp);

    while(pwcur) {
        show_try();
#ifdef TSF_UFC
        ufc_preprocess(binpasswd,pwcur->passwd);
        setup_salt(binpasswd);
#endif
        bool=0;
        wcur=wst;
        while(wcur) {
            pass_compares++;
#ifdef TSF_UFC
            mk_keytab(wcur->word);
            if( ufc(wcur->word,binpasswd) ) {
#else
            if(strcmp( crypt(wcur->word,pwcur->passwd),pwcur->passwd)==0) {
#endif
                    pwcur=tsf_cracked(pwcur,"C; ",wcur->word);
                    wcur=NULL;
                    bool=1;
               } else {
                            /** do prefixes **/
                        strcpy(wtemp+1,wcur->word);
                        wtemp[9]=0;
                        for(ptr=pref;(*ptr)&&(wcur);ptr++) {
                                wtemp[0]=*ptr;
                                pass_compares++;
#ifdef TSF_UFC
                                mk_keytab(wtemp);
                                if( ufc(wtemp,binpasswd) ) {
#else
                                if(strcmp( crypt(wtemp,pwcur->passwd),pwcur->passwd)==0) {
#endif
                                        pwcur=tsf_cracked(pwcur,"C; ",wtemp);
                                        wcur=NULL;
                                        bool=1;
                                }
                        }
                            /** now do suffixs**/
                        if( (wcur) && strlen(wcur->word)<8) {
                            strcpy(wtemp,wcur->word);
                            pos=wtemp+strlen(wtemp);
                            for(ptr=suf;(*ptr)&&(wcur);ptr++) {
                                *pos=*ptr;
                                pass_compares++;
#ifdef TSF_UFC
                                mk_keytab(wtemp);
                                if( ufc(wtemp,binpasswd) ) {
#else
                                if(strcmp( crypt(wtemp,pwcur->passwd),pwcur->passwd)==0) {
#endif
                                        pwcur=tsf_cracked(pwcur,"C; ",wtemp);
                                        wcur=NULL;
                                        bool=1;
                                }
                              }
                            }
                         /** end of prefix's **/
            if(wcur) wcur=wcur->next;
                }
          }
        if(!bool) pwcur=pwcur->next; /* skip it for next pass */
      }
     pass_end();
}

void main(argc,argv)
int argc;
char *argv[];
{
    static int i;

    pw_res[0]='\0';
    tsf_blog("-=-=-=-");
    sprintf(buf,"S; TSFd(tm) %s (c) rokK 1992",VERSION);
    tsf_blog(buf);

    signal(SIGINT, sig);
    signal(SIGQUIT,sig);

    init_des();
    crypt_check();
    pw_readfile();

    if (argc>1) {
        strcpy(pw_res,argv[1]);
    }

       ctmp=0;

       for(pwcur=pwst;(pwcur);pwcur=pwcur->next) {
            bool=0;

            for(wcur=wst;(wcur) && (!bool);wcur=wcur->next) {
                if (!strcmp(pwcur->login,wcur->word))
                        bool=1;
                        wtmp=wcur;
                    }

            if (!bool)
                wcur=wtmp,w_addword(pwcur->login),ctmp++;
       }
       for(wcur=wst;(wcur);wcur=wcur->next)
        ;           /* make sure its pointing to end.. */

       sprintf(buf,"S; added %lu unique login names to wordlist.",ctmp);
       tsf_blog(buf);

    w_readfile();
    pw_preprocess(pw_res);

    strcpy(suf,SUFFIX);
    strcpy(pref,PREFIX);

    fflush(log_file);
    tsf_crack();

    tsf_die("Normal End of run termination.",0);
}
