#if __GNUC__ >= 3
#define __unused   /*@unused@*/ __attribute__((unused))
#else
#define __unused /*@unused@*/
#endif
