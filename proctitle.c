#ifndef HAVE_SETPROCTITLE
  #include <stdarg.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <string.h>
  #include <stdio.h>
  
  #define SPT_PADCHAR	'\0'
  #define SPT_SIZE		512 /*(964 on linux)*/
#endif

static char *argv_start = NULL;
int argv_origlen = 0;

void proctitle_init (int argc, char *argv[])
{
	argv_start = argv[1];
	argv_origlen = strlen (argv[1]);
}

#ifndef HAVE_SETPROCTITLE

void setproctitle (const char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	size_t len;
	extern char *__progname;

	va_start(ap, fmt);
	vsnprintf (buf, 1024, fmt, ap);
	va_end(ap);

	buf[1023] = 0;

	memcpy (argv_start, buf, strlen(buf)+1);
	len = strlen (buf);
	for(; len < argv_origlen; len++)
		argv_start[len] = SPT_PADCHAR;
}

#endif
