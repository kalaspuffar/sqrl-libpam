AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I build

pamdir = $(libdir)/security

bin_PROGRAMS      = sqrl-login-associate
pam_LTLIBRARIES   = pam_sqrl_login.la

MODULES_LDFLAGS = -avoid-version -module -shared -export-dynamic

sqrl_login_associate_SOURCES = \
        src/google_qrcode.c \
	src/base64.c \
	src/sqrl_login_associate.c

pam_sqrl_login_la_SOURCES = \
        src/google_qrcode.c \
	src/base64.c \
	src/pam_sqrl_login.c
pam_sqrl_login_la_LIBADD  = -lpam
pam_sqrl_login_la_CFLAGS  = $(AM_CFLAGS)
pam_sqrl_login_la_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS) -export-symbols-regex "pam_sm_(setcred|open_session|authenticate)"

super-clean: maintainer-clean
	rm -fr aclocal autom4te.cache/ m4 missing libtool config.guess
	rm -fr config.lt config.status config.sub configure depcomp
	rm -fr libtool install-sh  *~ Makefile aclocal.m4 config.h.in ltmain.sh
	rm -fr Makefile.in test-driver compile
