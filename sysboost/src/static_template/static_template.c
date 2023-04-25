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

#define ADDR1 ((void *)0XDEAD01)
#define ADDR2 ((void *)0XDEAD02)

#ifdef __aarch64__
#define NO_COMPILE_OPTIMIZE(func_str) asm volatile("BL " func_str)
#else
#define NO_COMPILE_OPTIMIZE(func_str) asm volatile("jmp " func_str)
#endif

int main(void)
{
	(void)gettimeofday(NULL, 0);

	// gcc compile optimization will delete some code, we need use random len
	char buf[128] = {0};
	(void)getrandom(buf, sizeof(buf), 0);
	int len = buf[0] * buf[1];
	(void)memmove(ADDR1, ADDR2, 1);
	(void)__builtin___memmove_chk(ADDR1, ADDR2, len, 10);
	(void)memcpy(ADDR1, ADDR2, 1);
	(void)__builtin___memcpy_chk(ADDR1, ADDR2, len, 10);
	(void)memset(buf, 0, 1);
	(void)memcmp(ADDR1, ADDR2, 1);
	(void)strnlen(buf, 1);

	// _ITM_registerTMCloneTable is in libitm, OS do not use Transactional Memory, keep it NULL
	// __environ is in bss
	// __gmon_start__, exit(), abort(), __ctype_b_loc(), __ctype_toupper_loc(), __ctype_tolower_loc(), fprintf(), stpcpy(), wcschr(), malloc(), malloc(), strncmp(), strpbrk(),
	// wcslen(), strcasecmp(), realloc(), strcat(), strcmp(), free(), strncasecmp(), strcpy(), memchr(),
	// iswupper(), iswalnum(), strchrnul(), strstr(), towlower(), iswlower() is already in the template ELF

	// wctob, wcsncmp, mbrlen, mbsinit, strchr, strrchr, strcasestr, printf have been  optimized, so they're decorated with asm.
	NO_COMPILE_OPTIMIZE("wctob");
	NO_COMPILE_OPTIMIZE("wcsncmp");
	NO_COMPILE_OPTIMIZE("mbrlen");
	NO_COMPILE_OPTIMIZE("mbsinit");
	NO_COMPILE_OPTIMIZE("strchr");
	NO_COMPILE_OPTIMIZE("strrchr");
	NO_COMPILE_OPTIMIZE("strcasestr");
	NO_COMPILE_OPTIMIZE("printf");
	NO_COMPILE_OPTIMIZE("imaxdiv");
	NO_COMPILE_OPTIMIZE("__sprintf_chk");
	NO_COMPILE_OPTIMIZE("__errno_location");
	NO_COMPILE_OPTIMIZE("__snprintf_chk");
	NO_COMPILE_OPTIMIZE("__vsnprintf_chk");
	NO_COMPILE_OPTIMIZE("__fdelt_chk");
	NO_COMPILE_OPTIMIZE("__strncpy_chk");
	NO_COMPILE_OPTIMIZE("__strcpy_chk");
	NO_COMPILE_OPTIMIZE("__printf_chk");
	NO_COMPILE_OPTIMIZE("fdopen");
	NO_COMPILE_OPTIMIZE("__vfprintf_chk");
	NO_COMPILE_OPTIMIZE("__asprintf_chk");
	NO_COMPILE_OPTIMIZE("__fprintf_chk");
	NO_COMPILE_OPTIMIZE("iconv");
	NO_COMPILE_OPTIMIZE("__longjmp_chk");
	NO_COMPILE_OPTIMIZE("dcngettext");
	NO_COMPILE_OPTIMIZE("strcoll");
	NO_COMPILE_OPTIMIZE("putchar");
	NO_COMPILE_OPTIMIZE("fgets");
	NO_COMPILE_OPTIMIZE("tcflush");
	NO_COMPILE_OPTIMIZE("cfgetospeed");
	NO_COMPILE_OPTIMIZE("fread");
	NO_COMPILE_OPTIMIZE("strncat");
	NO_COMPILE_OPTIMIZE("__poll_chk");
	NO_COMPILE_OPTIMIZE("sigfillset");
	NO_COMPILE_OPTIMIZE("siglongjmp");
	NO_COMPILE_OPTIMIZE("vfprintf");

#ifdef __aarch64__
	// The __stack_chk_guard and __stack_chk_fail symbols are normally supplied by a GCC library called libssp
	NO_COMPILE_OPTIMIZE("__stack_chk_guard");
	NO_COMPILE_OPTIMIZE("__stack_chk_fail");
#endif

	setlocale(LC_ALL, "en_US.utf8");

	(void)fflush(stdin);
	(void)fflush(stdout);
	(void)fflush(stderr);

	(void)getgrent();
	(void)setgrent();
	(void)endgrent();
	(void)getpwent();
	(void)getpwnam(NULL);
	(void)getpwuid(0);
	(void)setpwent();
	(void)endpwent();
	(void)getaddrinfo(NULL, NULL, NULL, NULL);
	(void)mktemp(NULL);
	(void)getservent();
	(void)setservent(0);
	(void)endservent();

	(void)dlopen(NULL, 0);

	(void)__ctype_get_mb_cur_max();
	(void)__libc_current_sigrtmin();
	(void)__libc_current_sigrtmax();
	(void)mbrtowc(NULL, NULL, 0, NULL);
	(void)gai_strerror(0);
	(void)getcwd(0, 0);
	(void)freeaddrinfo(NULL);
	(void)dlerror();
	(void)strlen(NULL);
	(void)getpeername(0, NULL, NULL);
	(void)fputs(NULL, NULL);
	(void)mbstowcs(NULL, NULL, 0);
	(void)dup(0);
	(void)tcsetpgrp(0, 0);
	(void)strtoimax(NULL, NULL, 0);
	(void)mbtowc(NULL, NULL, 0);
	(void)getegid();
	(void)wctype("ascii");
	(void)sigprocmask(0, NULL, NULL);
	(void)geteuid();
	(void)iconv_close(0);
	// sigsetjmp same as __sigsetjmp
	(void)sigsetjmp(NULL, 0);
	(void)__sigsetjmp(NULL, 0);
	(void)ttyname(0);
	(void)readlink(NULL, NULL, 0);
	(void)getuid();
	(void)pipe(NULL);
	(void)putc(0, NULL);
	(void)opendir(NULL);
	(void)strftime(NULL, 0, " ", NULL);
	(void)fputc(0, NULL);
	(void)setrlimit(0, NULL);
	(void)qsort(NULL, 0, 0, NULL);
	(void)kill((int)getpid(), 0);
	(void)setvbuf(NULL, NULL, 0, 0);
	(void)pathconf(NULL, 0);
	(void)fork();
	(void)lseek(0, 0L, 0);
	(void)eaccess(NULL, 0);
	(void)localeconv();
	(void)tcgetattr(0, NULL);
	(void)fileno(NULL);
	(void)localtime(NULL);
	(void)fclose(NULL);
	(void)getpid();
	(void)nl_langinfo(0);
	(void)fopen("", "r");
	(void)time(NULL);
	(void)iswctype(0, 0);
	(void)wcwidth(0);
	(void)open(NULL, 0);
	(void)tzset();
	(void)wcswidth(NULL, 0);
	(void)getppid();
	(void)sigemptyset(NULL);
	(void)bindtextdomain(NULL, NULL);
	(void)__fpurge(NULL);
	(void)getgroups(0, NULL);
	(void)sleep(2);
	(void)fchmod(0, 0);
	(void)pselect(0, 0, 0, 0, NULL, NULL);
	(void)lstat(".", (struct stat *)0);
	(void)readdir(NULL);
	(void)clearerr(stdin);
	(void)strdup(NULL);
	(void)closedir(NULL);
	(void)strerror(0);
	(void)close(0);
	(void)sigaction(0, NULL, NULL);
	(void)tcgetpgrp(0);
	(void)stat(NULL, NULL);
	(void)write(0, "", 1);
	(void)strtoumax(NULL, NULL, 0);
	(void)mkdtemp(NULL);
	(void)access(NULL, 0);
	(void)wcsrtombs(NULL, NULL, 0, NULL);
	(void)puts(NULL);
	(void)getrusage(0, NULL);
	(void)textdomain(NULL);
	(void)sigismember(NULL, 0);
	(void)strtol(NULL, NULL, 0);
	(void)wctomb(NULL, 0);
	(void)setpgid(0, 0);
	(void)strtod(NULL, NULL);
	(void)chdir(NULL);
	(void)getgid();
	(void)getpgrp();
	(void)connect(0, NULL, 0);
	(void)mbsnrtowcs(NULL, NULL, 0, 0, NULL);
	(void)killpg(0, 0);
	(void)setitimer(0, NULL, NULL);
	(void)execve(NULL, NULL, NULL);
	(void)wmemchr(NULL, 0, 0);
	(void)rename(NULL, NULL);
	(void)fwrite(NULL, 0, 0, NULL);
	(void)fnmatch(NULL, 0, 0);
	(void)wcsdup(0);
	(void)fcntl(0, 0, 0);
	(void)socket(0, 0, 0);
	(void)getrlimit(0, NULL);
	(void)iconv_open("utf8", "eucJP");
	(void)confstr(0, NULL, 0);
	(void)mbsrtowcs(NULL, NULL, 0, NULL);
	(void)read(0, NULL, 0);
	(void)mkstemp(NULL);
	(void)tcsetattr(0, 0, NULL);
	(void)isatty(0);
	(void)sysconf(0);
	(void)gethostname(NULL, 0);
	(void)select(0, NULL, NULL, NULL, NULL);
	(void)dlsym(NULL, NULL);
	(void)setresuid(0, 0, 0);
	(void)dcgettext(NULL, NULL, 0);
	(void)wcscmp(NULL, NULL);
	(void)regexec(NULL, NULL, 0, NULL, 0);
	(void)sigdelset(NULL, 0);
	(void)regfree(NULL);
	(void)dup2(0, 0);
	(void)regcomp(NULL, NULL, 0);
	(void)strncpy(NULL, NULL, 0);
	(void)strsignal(0);
	(void)sigaddset(NULL, 0);
	(void)towupper(0);
	(void)iswprint(0);
	(void)wcscoll(NULL, NULL);
	(void)umask(0);
	(void)faccessat(0, NULL, 0, 0);
	(void)setresgid(0, 0, 0);
	(void)alarm(0);
	(void)chown(NULL, 0, 0);
	(void)mblen(NULL, 0);
	(void)dlclose(NULL);
	(void)fstat(0, NULL);
	(void)waitpid(0, NULL, 0);
	(void)unlink(NULL);
	(void)getdtablesize();
	(void)fgetc(NULL);
	(void)tcflow(0, 0);
	(void)ioctl(0, 0);
	(void)ferror(NULL);
	(void)wcrtomb(NULL, 0, NULL);

	return 0;
}
