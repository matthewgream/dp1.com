/*  dict.c.
    support prog for tsfd
    - shitty program just truncates words at 8chars, lowercases them
      and throws it to stdout, run it like
      'dict words | sort | uniq >newwords'
*/

#include <stdio.h>

FILE *fp;
char buf[255];

void main(argc,argv)
int argc;
char *argv[];
{
    register char *ptr;

    if (argc!=2) {
             fprintf(stderr,"Usage: %s wordfile\n",argv[0]);
             exit(-1);
            }

    if((fp=fopen(argv[1],"r"))) {
       while(!feof(fp)) {
          buf[0]=0; /* some compilers u need to do this */
          fgets(buf,255,fp);
          if(buf[2]) {
               buf[(strlen(buf)>8)?8:(strlen(buf)-1)]='\0';
               ptr=buf;
               do {
                 *ptr=tolower(*ptr);
               } while(*(++ptr));
          }
       }
       fclose(fp);
   }

}
