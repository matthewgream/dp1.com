/********************* Include Files Used */

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys\types.h>
#include <malloc.h>
#include <alloc.h>

#include "bcrypt.h"

/********************* The following contains defines you can modify */

#define PREFIX "0123456789!"
#define SUFFIX "0123456789!"

/********************* Structures and global variables */

FILE *pwdfile,
     *outfile;
char suf[20],
     pref[20];

/********************* Start of Routines and Main Code */

void die()
{
        fclose(pwdfile);
        fclose(outfile);
        bcrypt_done();
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

        if ((pw.L.U==code.L.U) && (pw.R.U==code.R.U))
                printf("Bcrypt is working 100%\n");
        else {
                printf("Bcrypt is not working\n");
                die();
            }
}

#define CHECK(word) if(!ok) { \
                        bcrypt_set_word(word); \
                        rcode=bcrypt_encode(SL[0],SL[1]); \
                        if((pw.L.U==rcode.L.U) && (pw.R.U==rcode.R.U)) \
                          {   \
                             ok=1; \
                             sprintf(s,"%-10s -> %s:%s:%s",word,ptr1,ptr2,ptr3); \
                             fprintf(outfile,"%s\n",s); \
                             s[79]=0; \
                             printf("%s\n",s); \
                             fflush(stdout); \
                          } \
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

void crack()
{
    int           ok;
    char          *ptr1,
                  *ptr2,
                  *ptr3;
    char          buf[255],
                  s[255],
                  w[14];
    register U32  SL[2];
    register BU64 pw,
                  rcode;
    int           i,j;

    while(!feof(pwdfile))
        {
            buf[0]='\0';  /* stupid turboc */
            fgets(buf,255,pwdfile);
            buf[strlen(buf)-1]='\0';
            if( buf[0] && strchr(buf,':') )
            {
                ptr1=buf;
                ptr2=pw_strip(ptr1);
                ptr3=pw_strip(ptr2);
                if (strlen(ptr1)<=8) {

                    printf("Trying: %-10s\r",ptr1);
                    strcpy(w+1,ptr1);
                    bcrypt_salt_to_E(ptr2[0],ptr2[1],SL);
                    pw=bcrypt_pw_to_BU64(ptr2+2);

                    ok=0;
                    j=strlen(w+1);
                    CHECK(w+1);

                    for(i=0;(!ok)&&(pref[i]);i++) {
                        w[0]=pref[i];
                        CHECK(w);
                    }

                    if((!ok)&&(j<8)) {
                            w[j+2]='\0';
                            for(i=0;(!ok)&&(suf[i]);i++) {
                               w[j+1]=suf[i];
                               CHECK(w+1);
                            }
                   }

                   for(i=0;(ptr1[i]);i++)
                        w[j-i]=ptr1[i];
                   w[j+1]='\0';
                   CHECK(w);
                }
            }
        }
}



void main(argc,argv)
int argc;
char *argv[];
{
    if(argc!=3) {
         printf("Usage: %s <passwdfile> <logfile>\nWill try each user back/forth and with\nprefixes 0-9+! and suffixes 0-9+!\n",argv[0]);
         exit(-1);
    }
    if(!(pwdfile=fopen(argv[1],"r"))) {
         printf("Cant open '%s' for reading\n",argv[1]);
         exit(-1);
    }
    if(!(outfile=fopen(argv[2],"a"))) {
         printf("Cant open '%s' for writing\n",argv[2]);
         fclose(pwdfile);
         exit(-1);
    }

    bcrypt_init();
    crypt_check();
    strcpy(suf,SUFFIX);
    strcpy(pref,PREFIX);
    crack();
    die();
}

