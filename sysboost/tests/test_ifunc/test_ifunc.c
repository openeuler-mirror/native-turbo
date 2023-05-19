#include <ctype.h>
#include <curses.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fnmatch.h>
#include <grp.h>
#include <iconv.h>
#include <inttypes.h>
#include <langinfo.h>
#include <libintl.h>
#include <locale.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <term.h>
#include <termcap.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

#ifdef __aarch64__
#define NO_COMPILE_OPTIMIZE(func_str) asm volatile("BL " func_str)
#else
#define NO_COMPILE_OPTIMIZE(func_str) asm volatile("jmp " func_str)
#endif

int main(void)
{
	char src[10] = {0};
	char dest[10] = {0};

	(void)strcpy(dest, src);
	(void)memmove(dest, src, 10);
	void *p = memchr(src, 0, 10);
	printf("%p", p);
	memset(src, 0, 10);
	if (strcmp(dest, src) == 0) {
		printf("%p", p);
	}
	if (bcmp(dest, src, 10) == 0) {
		printf("%p", p);
	}
	char *c = rindex(src, 0);
	printf("%p", c);

#ifdef __x86_64__
	NO_COMPILE_OPTIMIZE("__libc_strstr");
#endif

	/*
	__strnlen();
	__rawmemchr();
	__wcschr();
	strrchr();
	strcat();
	memchr();
	__wcscmp();
	strstr();
	strncmp();
	strncpy();
	memcmp();
	__strcasecmp_l();
	__wmemchr();
	memset();
	strcmp();
	__wmemset();
	strcspn();
	__wcscpy();
	__strncasecmp_l();
	__strcasecmp();
	strspn();
	strlen();
	strchr();
	__stpncpy();
	strpbrk();
	stpcpy();
	bcmp();
	wcslen();
	memcpy();
	__strncasecmp();
	wcsncmp();
	mempcpy();
	__wcslen();
	strncasecmp();
	strnlen();
	rawmemchr();
	wcscpy();
	strcasecmp_l();
	rindex();
	wmemchr();
	__stpcpy();
	__strchrnul();
	__wmemcmp();
	wmemset();
	strcasecmp();
	__libc_strstr();
	wcsnlen();
	strncat();
	wcschr();
	index();
	__wcsnlen();
	__memchr();
	__mempcpy();
	strncasecmp_l();
	__new_memcpy();
	wmemcmp();
	stpncpy();
	wcscmp();
	__libc_memmove();
	__strncat();
	strchrnul();*/

	return 0;
}
