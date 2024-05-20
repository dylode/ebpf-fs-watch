#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "watch_skel.h"
#include "event.h"

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

static int handle_evt(void *ctx, void *data, size_t sz)
{
    const struct ringbuf_event *evt = data;

    for (int i = evt->path_elements_length - 1; i >= 0; i--)
    {
        fprintf(stdout, "%s ", evt->path_elements[i]);
    }

    fprintf(stdout, "\n");

    // fprintf(stdout, "path elements: %d 0: %s 1: %s 2: %s 3: %s 4: %s 5: %s\n", evt->path_elements_length, evt->path_elements[0], evt->path_elements[1], evt->path_elements[1], evt->path_elements[2], evt->path_elements[3], evt->path_elements[4], evt->path_elements[5]);

    return 0;
}

int main()
{
    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    struct watch_bpf *skel = watch_bpf__open();
    watch_bpf__load(skel);
    watch_bpf__attach(skel);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_evt, NULL, NULL);

    for (;;)
    {
        ring_buffer__poll(rb, 1000);
    }
}