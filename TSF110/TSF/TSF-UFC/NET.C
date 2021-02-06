
/*
        TSFNet.c - roKK Jan.1992.

        Network Cracking for TSFd.

        Operation: To run this program you will need to have an account
        on a machine that has its filesystem mirrored on the rest, in
        other words ALL YOUR RHOSTS must have the same filesystem. All
        you need to do is make a directory that contains the passwd
        file (second arguement) and a file that lists rhosts (This can
        be a .rhosts, a /etc/hosts format or anything similar, BUT MAKE
        SURE THERE ARE NOT DUPES!). You will also need to make a
        subdirectory called net/ (mkdir net\r). This program will divide
        up the passwd file into equal segments for each machine, it will
        create seperate passwd files for each machine then rsh to each
        machine in succession and startup a script. This script will
        compile a tsf and execute it. Seperate compiling IS NEEDED for
        the case that your rhosts are differenct architectures.
        After all rhosts have been 'fired up', the program will wait
        for each machine to finish and process the results, building
        up a master list of results (tsfnet.out).

        The only downside at the moment is the dependence on the same
        filesystem, I may modify to get around this (rcp files across
        and such forth), but this will require some other way to gather
        output results (maybe rcp them BACK to the original system?)

*/

#include <stdio.h>
#include <sys/types.h>
#include <string.h>

struct w_list {
        struct h_list *next;
        char *w;
    };
                      /* some compilers dont init them to NULL ! */

struct w_list *h_start=NULL,
              *h_cur=NULL,
              *h_temp=NULL,

              *p_start=NULL,
              *p_cur=NULL,
              *p_temp=NULL;

FILE *rfile,
    *ofile;
int h_number=0,
    p_number=0;

void die(err)
int err;
{
    while(h_start) {
        h_temp=h_start;
        h_start=h_temp->next;
        free(h_temp->w);
        free(h_temp);
    }

    while(p_start) {
        p_temp=p_start;
        p_start=p_temp->next;
        free(p_temp->w);
        free(p_temp);
    }
    exit(err);
}

void add_list(w_st,w_cu,wo)
struct w_list *w_st,*w_cu;
char *wo;
{
    struct w_list *w_t;

    w_t=(struct w_list *)malloc( sizeof(struct w_list) );
    w_t->w=(char *)malloc(strlen(wo)+1);
    strcpy(w_t->w,wo);
    w_t->next=NULL;
    if(w_cu==NULL) {
        w_st=w_t;
    } else {
        w_cu->next=w_t;
    }
    w_c=w_t;
}

void read_hosts(filen)
char *filen;
{
    char s[255];
    int i,j;

    if (!(rfile=fopen(filen,"r"))) {
            fprintf(stderr,"Fatal: cannot open hosts file.\n");
            die(1);
        }
    while(!feof(rfile)) {
        s[0]=s[255]=0; /* i dont remmeber why i put 255 here? */
        fgets(s,255,rfile);
        s[strlen(s)-1]=0;
        if( s[0] && (s[0]!='#') ) {
            for(i=0; (s[i]) && (isspace(s[i]));i++)
                ;
            for(j=i; (s[j]) && (!isspace(s[j]));j++)
                ;
            s[j]=0;
            add_list(h_start,h_cur,s+i);
            h_number++;
        }
    }
  fclose(rfile);
}

void read_passwd(filen)
char *filen;
{
    char s[255];

    if (!(rfile=fopen(filen,"r"))) {
            fprintf(stderr,"Fatal: cannot open passwd file.\n");
            die(1);
        }
    while(!feof(rfile)) {
        s[0]=s[255]=0; /* why did i put 255 */
        fgets(s,255,rfile);
        s[strlen(s)-1]=0;
        if( s[0]) {
            add_list(p_start,p_cur,s);
            p_number++;
        }
    }
  fclose(rfile);
}

void gen_files()
{
    char s[255];
    int i,j,num_per_cr;

    num_per_cr=(int)( p_number / h_number);

    for(h_cur=h_start;(h_cur);h_cur=h_cur->next) {

       printf("Writing/Execing: %s\n",h_cur->w);

       /* first we write the passwd file required for this machine,
         note that all filenames have the machine name suffixed onto
         them for uniqueness */

       sprintf(s,"net/pwd.%s",h_cur->w);
       rfile=fopen(s,"w");
       for(i=0;( (p_start) && (i<num_per_cr) );i++) {
            fprintf(rfile,"%s\n",p_start->w);
            p_temp=p_start;
            p_start=p_start->next;
            free(p_temp->w);
            free(p_temp);
       }
       fclose(rfile);

       /* next we have to rsh a script to that machine to start
          compilation and execution, the script file generated
          above will do this */

       sprintf(s,"rsh %s \"nohup tsfnet.scr %s &\"",
                    h_cur->w,
                    h_cur->w );
       system(s);
    }

}

void gen_script()
{
    char s[255];

    if (!(rfile=fopen("tsfnet.scr","w"))) {
         fprintf(stderr,"Fatal: cannot write script file.\n");
         die(1);
    }
    /* make sure we run sh */

    fprintf(rfile,"#!/bin/sh\n");

    /* the compilation command, reason for doing this rather than
       just generating ONE executable and running it is that over
       different architectures the other method fails. you may
       have to change the -O3 and -DTSF_UFC option */

    fprintf(rfile,"cc -O3 -DNETWORK -DPWDFILE="net/pwd.$1" -DHOST="$1" -DNETFILE="net/res.$1" -DOUTFILE="net/out.$1" -DTSF_UFC crypt.c crypt_ut.c tsf.c -o net/tsf.$1\n");

    /* the execution command line */

    fprintf(rfile,"net/tsf.$1\n");

    /* remove the executable after we have finished */

    fprintf(rfile,"rm net/tsf.$1\n");
    fprintf(rfile,"rm tsf.$1.o\n");

    /* remove the passwd file after we have finished */

    fprintf(rfile,"rm net/pwd.$1\n");
    fprintf(rfile,"logout\n");
    fclose(rfile);
/* a few notes here, you could nohup net when you run it, then sleep
   for say 1 minute and then remove the pwd file and excutable ,
   since by 1 minute it should have opened the pwdf for reading,
   doing this way means you dont hae a lot of rsh's all open
   hogging up your cpu time *?
}

void dump_it(w_st,wo)
struct w_list *w_st;
char *wo;
{
    struct w_list *wmp;

    fprintf(ofile,"S; \nS; %s\nS; \n",wo);
    while(w_st) {
        fprintf(ofile,"%s\n",w_st->w);
        wmp=w_st;
        w_st=w_st->next;
        free(wmp->w);
        free(wmp);
    }
}

void c_wait()
{
    char s[255];
    char s1[255];
    char buf[255];
    struct w_list *cra_start=NULL,*cra_cur=NULL;
    struct w_list *inv_start=NULL,*inv_cur=NULL;
    struct w_list *unc_start=NULL,*unc_cur=NULL;

    ofile=fopen("tsfnet.out","a");
    fprintf(ofile,"-=-=-=-\n");
    fprintf(ofile,"S; TSFd Network Master - (c) roKK 1992\n");
    fprintf(ofile,"S; Networking on %d Machines.\n",h_number);
    fprintf(ofile,"S; Total %d passwords being cracked.\n",p_number);

    while(h_start) {
        sprintf(s,"net/res.%s",h_start->w);
        while(!exist(s))
            sleep(5); /* check every 5 seconds */

        /* start by extracting accounts etc */

        sprintf(s1,"net/out.%s",h_start->w);
        if ((rfile=fopen(s1,"r"))!=NULL)
           while(!feof(rfile)) {
                buf[0]=0;
                fgets(buf,255,rfile);
                buf[strlen(buf)-1]=0;
                switch (buf[0]) {
                     case 'C': add_list(cra_start,cra_cur,buf); break;
                     case 'I': add_list(inv_start,inv_cur,buf); break;
                     case 'U': add_list(unc_start,unc_cur,buf); break;
                      default: break;
                }
          }
        fclose(rfile);
        unlink(s1); /* fuck it off */

         /* now extract the session info */
        rfile=fopen(s,"r");
        fgets(buf,255,rfile);
        fclose(rfile);
        unlink(s);

        fprintf(ofile,"S; %s",buf);
        h_temp=h_start;
        h_start=h_start->next;
        free(h_temp->w);
        free(h_temp);
        /* now loopback and wait for next machine to finish */
    }

    dump_it(inv_start,"--[Invalid Accounts]--");
    dump_it(cra_start,"--[Cracked Accounts]--");
    dump_it(unc_start,"--[Uncracked Accounts]--");
    fprintf(ofile,"S; \nS; End of data dump.\n-=-=-=-\n");
    fclose(ofile);
}


void main(argc,argv)
int argc;
char *argv[];
{
    if(argc!=3) {
        fprintf(stderr,"Usage: tsfnet <hosts-file> <passwd-file>\n");
        exit(1);
    }
    printf("Reading HOSTS File: ");
    read_hosts(argv[1]);
    printf("Total of %d hosts read.\n",h_number);

    printf("Reading PASSWD File: ");
    read_passwd(argv[2]);
    printf("Total of %d passwds read.\n",p_number);

    printf("Creating tsfnet.scr sh file.\n");
    gen_script();
    printf("Generating/Execing files (%d passwds per machine).\n",
            (int) (p_number / h_number));
    gen_files();

    printf("Waiting for machines to finish.\n");
    c_wait();
    die(0);
}
