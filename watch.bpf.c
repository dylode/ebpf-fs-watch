#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct exec_params_t
{
    u64 __unused;
    u64 __unused2;
    unsigned int fd;
};

SEC("tp/syscalls/sys_enter_write")
int handle_sys_enter_write(struct exec_params_t *ctx)
{
    // bpf_printk("hi");

    bpf_printk("write %d", ctx->fd);
    return 0;
}

// struct exec_params_t
//{
//     u64 __unused;
//     u64 __unused2;
//
//     char *file;
// };
//
// SEC("tp/syscalls/sys_enter_execve")
// int handle_execve(struct exec_params_t *params)
//{
//     bpf_printk("Exec Called %s\n", params->file);
//     return 0;
// }

char LICENSE[] SEC("license") = "GPL";