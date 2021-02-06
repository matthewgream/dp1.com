/* gpwd.c
   support program for tsfd.
   - uses getpwent to snarf pwds on yp(nis), and some shadowed
     systems (NeXT's are a good xample)
*/

#include <stdio.h>
#include <pwd.h>

struct passwd *pw, *getpwent();

void main()
{
    setpwent();

    while((pw=getpwent()))
        printf("%s:%s:%d:%d:%s:%s:%s\n",
            pw->pw_name,
            pw->pw_passwd,
            pw->pw_uid,
            pw->pw_gid,
            pw->pw_gecos,
            pw->pw_dir,
            pw->pw_shell);

    endpwent();
}
