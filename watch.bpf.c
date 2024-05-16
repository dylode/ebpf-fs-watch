#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct exec_params_t
{
    u64 __unused;
    u64 __unused2;
    unsigned int fd;
};

SEC("tp/syscalls/sys_enter_write")
int handle_sys_enter_write(struct exec_params_t *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // unsigned int max_fds = BPF_CORE_READ(task, files, fdt, max_fds);
    // bpf_printk("%d", max_fds);

    struct file **fd = BPF_CORE_READ(task, files, fdt, fd);

    struct file *f;
    bpf_probe_read(&f, sizeof(f), &fd[ctx->fd]);

    const char *name = BPF_CORE_READ(f, f_path.dentry, d_name.name);
    bpf_printk("%d => %s", ctx->fd, name);

    //  bpf_probe_read(&d, sizeof(d), f.f_path.dentry);

    // const unsigned char *name = d.d_name.name;
    // if (name != "")
    //{
    //     bpf_printk("%d => %s", ctx->fd, name);
    // }

    return 0;
}

static append_parent_name(struct parent_name *ctx)
{
}

char LICENSE[] SEC("license") = "GPL";