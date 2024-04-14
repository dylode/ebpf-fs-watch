#include <stdio.h>
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main()
{
    libbpf_set_print(libbpf_print_fn);
    libbpf_prog_load();
    printf("hello world");
}