
# Makefile for Borland C++ 2.0 (messydos)
# comment O286 if you are compiling on an 8086/88
# and change bccx to bcc if your not using a 386

CC      = bccx
O286    = -1
CFLAGS  = -ml -Z -O -G -K -N- -d -r $(O286)
DFLAGS  = -D_TURBO

.c.obj:
  $(CC) $(CFLAGS) $(DFLAGS) -c $*.c

tsf-ibm.exe: bcrypt.obj tsf-ibm.obj
           $(CC) $(CFLAGS) tsf-ibm.obj bcrypt.obj
tsf-ibm.obj: tsf-ibm.c
bcrypt.obj: bcrypt.h bcrypt.c

