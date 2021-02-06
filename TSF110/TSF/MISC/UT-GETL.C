/* getl.c
   support prog for tsfd.
   - allows you to extract specific information from tsfd output
     files, ie after a crack you can 'getl -u hits.out >passwd' to
     make sure you dont try to recrack accounts on restoring.
     EG: -> for messydos u can make a batch file like:
                     / getl -c hits.out >>pwd\sparc1.out
                     / getl -u hits.out >pwd\sparc1.pwd
                     / grep KILLED hits.out >pwd\sparc1.res
                     / del hits.out
*/

#include <stdio.h>
#include <string.h>

FILE *fp;
char buf[255],
     ch;

void main(argc,argv)
int argc;
char *argv[];
{
    if ( (argc!=3) ||
         (argv[1][0]!='-') ||
         (!strchr("CUIS",(ch=toupper(argv[1][1])))) ) {
            fprintf(stderr,"Usage: %s -[c|u|i|s] [file of hits]\n",argv[0]);
            exit(-1);
        }

        if ((fp=fopen(argv[2],"r"))!=NULL) {
            while (!feof(fp)) {
                buf[0]=0;
                fgets(buf,255,fp);
                buf[strlen(buf)-1]=0;
                if ((buf[0]==ch) && (buf[1]==';'))
                        puts(buf+3);
            }
            fclose(fp);
        }
 }
