/*
       -=Bcrypt Version=-
         This version is built for bcrypt().
*/

/********************* The following contains defines you can modify */

#define PWDFILE "passwd"
#define LOGFILE "hits.out"
#define WORDFILE "words"

#define PREFIX "01"
/* #define SUFFIX "!" */

#define SHOW_INVALID 1

#define DUMP_UNCRACKED 1

#define LOG_TO_FILE 1

/*
#define IMMEDIATE 1
*/
#define SHOWSOMETHING 1

#define OUT_ALWAYSOPEN 1

/* not implemented yet
#define LOG_TO_SOCKET 1

#ifdef LOG_TO_SOCKET
#define SOCKET_NUM 9999
#define HOST_NAME "255.255.255.255"
#endif

#define LOG_TO_MAIL 1

#ifdef LOG_TO_MAIL
#define MAIL_PROGRAM "/bin/mail"
#define MAIL_DEST "root@nic.ddn.mil"
#endif
*/

/********************* You should leave these defines as they are */

#ifdef LOG_TO_FILE

#define tsf_blog(s) if(!log_file) log_file=fopen(LOGFILE,"a"); \
                    fprintf(log_file,"%s\n",s)

#ifdef OUT_ALWAYSOPEN
#define tsf_log(s) tsf_blog(s);
#else
#define tsf_log(s) tsf_blog(s); \
                   fclose(log_file); \
                   log_file=NULL;
#endif
#endif /* LOG_TO_FILE */

#define VERSION "V1.11DOS-bcrypt[PR]"

#ifdef SHOWSOMETHING
#define show_try() fprintf(stdout,"Trying: %-10s\r",currentword); \
                   fflush(stdout);
#else
#define show_try() ;
#endif

/********************* Include Files Used */

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>

#include "bcrypt.h"

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
             U32    SL[2];
             BU64   pw;
};

struct pw_rec *pwst=NULL,
              *pwcur=NULL,
              *pwtmp;

struct w_rec {
        struct w_rec  *next;
                char  *word;
 };

struct w_rec *wst=NULL,
             *wcur=NULL,
             *wr=NULL,
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

#ifdef LOG_TO_FILE
FILE          *log_file;
#endif

char    buf[255],
        buf1[255],
        suf[80],
        pref[80],
        currentword[14],
        pass_name[80],
        pass_res='\0',
        *w_cur,
        bool=0,
        inpass=0;

time_t  pass_start=0,
        pass_time=0,
        timetemp=0,
        tot_time=0;

/********************* Start of Routines and Main Code */


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
    tsf_log("S; ");
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
    /* bcrypt_done(); */
    if(w_file)
        fclose(w_file);
    if(pw_file)
        fclose(pw_file);
    exit(exitcode);
}

#define w_rewind() wcur=wst

#define tsf_crack_all(word) { \
    bcrypt_set_word(word); \
     pwcur=pwst; \
     while(pwcur) { \
       rcode=bcrypt_encode(pwcur->SL[0],pwcur->SL[1]); \
       pwcur=((pwcur->pw.L.U==rcode.L.U) && (pwcur->pw.R.U==rcode.R.U))?tsf_cracked(pwcur,"C; ",word):pwcur->next; \
       pass_compares++; \
      } \
    }

void pass_st()
{
    inpass=1;
    sprintf(buf,"S; --[Start: %s.]----------\nS; ",pass_name);
    tsf_log(buf);
    pass_compares=0;
    pass_total=0;
    pass_start=time(&timetemp);
}

void pass_end()
{
     pass_time=time(&timetemp)-pass_start;
     tot_time+=pass_time;
     tot_compares+=pass_compares;
     tot_total+=pass_total;
     inpass=0;
     tsf_dumpcq();
     w_rewind();
     sprintf(buf,"S; \nS; --[End: %s. AC:%lu, C:%lu T:%lu = %.2f C/S]----------\nS; ",pass_name,pass_total,pass_compares,pass_time,(pass_time)?((double)pass_compares/pass_time):0);
     tsf_log(buf);
}
int sig()
{

    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT,SIG_IGN);

    if(inpass) {
            pass_end();
          }

    sprintf(buf,"got SIGNAL. pass='%s'. word='%s'.",
            (pass_name[0])?pass_name:"None.",
            (w_cur[0])?w_cur:"None.");

    tsf_die(buf,1);
    return(0);
}

void crypt_check()
{
        char passwd[15];
        U32  SL[2];
        BU64 pw,
             code;

        strcpy(passwd,"XPYXtEl2UfrPQ");
        bcrypt_salt_to_E(passwd[0],passwd[1],SL);
        pw=bcrypt_pw_to_BU64(passwd+2);
        bcrypt_set_word("contact");
        code=bcrypt_encode(SL[0],SL[1]);

        if ((pw.L.U==code.L.U) && (pw.R.U==code.R.U)) {
                tsf_log("S; Bcrypt engine self-test succeeded.");
            }
        else {
                tsf_die("Fatal: Bcrypt is NOT working",-1);
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


void w_readfile(restoreword)
char *restoreword;
{
    if (!(w_file=fopen(WORDFILE,"r")))
            tsf_die("Fatal: unable to open WORDFILE",-1);

    if (restoreword[0]) {
        sprintf(buf,"S; attempting restore at word '%s'",restoreword);
        tsf_blog(buf);
    }

    while  (!feof(w_file)) {
            buf[0]='\0'; /* stupid turboc */
            fgets(buf,255,w_file);
            buf[ (strlen(buf)>8)?8:(strlen(buf)-1)]='\0';

                if(buf[0])
                    w_addword(buf);
     }

     fclose(w_file);

     if (restoreword[0]) {
        wr=wst;
        while((wr) && (restoreword[0])) {
            if (strcmp(wr->word,restoreword))
                    wr=wr->next;
                else
                    restoreword[0]='\0';
                }
     }

     if(restoreword[0]) {
        sprintf(buf,"Fatal: didnt find restoreword '%s'.",restoreword);
        tsf_die(buf,-1);
      }

     sprintf(buf,"S; read_words('%s'): got %lu words.",
                                        WORDFILE,
                                        w_total);
     tsf_blog(buf);

}

void pw_preprocess()
{
    struct pw_rec *pwst_s=NULL,*pwcur_s=NULL;

    /* ok so its a Lamero bubble sort, SUE ME THEN! */

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


       ctmp=0;
       strcpy(pass_name,"preprocess");
       tsf_blog("S; \nS; --[Started pass: preprocess.]----------\nS; ");
       pass_total=0;
       for(pwcur=pwst;(pwcur);) {
            if (!pwcur->passwd[0])
                        pwcur=tsf_cracked(pwcur,"C; ","*blank");
            else if ( (strlen(pwcur->passwd)<13) ||
                       strchr(pwcur->passwd,'*') ||
                       strchr(pwcur->passwd,'#') ||
                       strchr(pwcur->passwd,' ') ||
                       strchr(pwcur->passwd,'%') ||
                       strchr(pwcur->passwd,'!') )
                         pwcur=tsf_cracked(pwcur,"I; ","*invalid"),ctmp++,pass_total--;
            else {
                    bcrypt_salt_to_E(pwcur->passwd[0],pwcur->passwd[1],pwcur->SL);
                    pwcur->pw=bcrypt_pw_to_BU64(pwcur->passwd+2);
                    pwcur=pwcur->next;
                }
       }

    tsf_dumpcq();

    sprintf(buf,"S; \nS; --[Ended: preprocess. got %lu blank, %lu invalid acnts]----------\nS; ",pass_total,ctmp);
    tsf_log(buf);

}

void tsf_crack() /*** Crack Routine for Cracking by WORDS.
                      Crypters Like UFC require cracking by USERS.
                 ***/
{
    register BU64 rcode;
    register char *ptr;
    register int i;

if (!pass_res) {

    strcpy(pass_name,"word");
    pass_st();

    for(;(wcur);wcur=wcur->next) {
        w_cur=wcur->word;
        strcpy(currentword,w_cur);
        show_try();
        tsf_crack_all(currentword);
       }

    pass_end();
}

#ifdef SUFFIX
if (pass_res!='P') {

    sprintf(pass_name,"suf,word[%s]",SUFFIX);
    pass_st();

    for(;(wcur);wcur=wcur->next) {
        w_cur=wcur->word;
        strcpy(currentword,w_cur);
        currentword[(i=strlen(currentword))+1]='\0';
        if(i<8)
           for(ptr=suf;(*ptr);ptr++) {
                currentword[i]=*ptr;
                show_try();
                tsf_crack_all(currentword);
           }
       }

    pass_end();
}
#endif

#ifdef PREFIX
    sprintf(pass_name,"pre,[%s]word",PREFIX);
    pass_st();

    for(;(wcur);wcur=wcur->next) {
        w_cur=wcur->word;
        strcpy(currentword+1,w_cur);
        currentword[8]='\0';
        for(ptr=pref;(*ptr);ptr++) {
                currentword[0]=*ptr;
                show_try();
                tsf_crack_all(currentword);
            }
       }

    pass_end();
#endif

}


void main(argc,argv)
int argc;
char *argv[];
{
    static int i;

    currentword[0]='\0';
    w_cur=currentword;
    tsf_blog("-=-=-=-");
    sprintf(buf,"S; TSFd(tm) %s (c) rokK 1992",VERSION);
    tsf_blog(buf);

    signal(SIGINT,  sig);
    signal(SIGQUIT, sig);

    bcrypt_init();
    crypt_check();
    pw_readfile();

    if (argc>1) {
        strcpy(currentword,argv[1]);
        i=2;
        while( (i<argc) && (argv[i][0]!='-')) { /* for words with spaces */
            strcat(currentword," ");
            strcat(currentword,argv[i++]);
        }
        if ( (i<argc) && argv[i][0]=='-') {
                pass_res=upcase(argv[i][1]);    /* should be either P or S */
            }
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

    w_readfile(currentword);
    pw_preprocess();

#ifdef SUFFIX
    strcpy(suf,SUFFIX);
#endif
#ifdef PREFIX
    strcpy(pref,PREFIX);
#endif

    wcur=(wr)?wr:wst;
    tsf_crack();

    tsf_die("Normal End of run termination.",0);
}

