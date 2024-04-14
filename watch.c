#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "watch_skel.h"

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main()
{
    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    struct exec *skel = watch_bpf__open();
    watch_bpf__load(skel);
    watch_bpf__attach(skel);

    for (;;)
    {
    }
    return 0;
}