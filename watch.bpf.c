#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct exec_params_t
{
    u64 __unused;
    u64 __unused2;
    unsigned int fd;
};

static bool local_strcmp(const char *cs, const char *ct, int size)
{
    int len = 0;
    unsigned char c1, c2;

#pragma unroll
    for (len = 0; len < size; len++)
    {
        c1 = *cs++;
        c2 = *ct++;

        if (c1 != c2)
            return false;
    }

    return true;
}

SEC("tp/syscalls/sys_enter_write")
int handle_sys_enter_write(struct exec_params_t *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // unsigned int max_fds = BPF_CORE_READ(task, files, fdt, max_fds);
    // bpf_printk("%d", max_fds);

    struct file **fd = BPF_CORE_READ(task, files, fdt, fd);

    struct file *f;
    bpf_probe_read(&f, sizeof(f), &fd[ctx->fd]);

    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);

    struct dentry *d_parent;
    unsigned char *name;

    const char *path[16];

    char buf[64];

    name = BPF_CORE_READ(d, d_name.name);
    bpf_probe_read_str(buf, sizeof(buf), name);

    d = BPF_CORE_READ(d, d_parent);
    if (!local_strcmp(buf, "test", 3))
    {
        return 0;
    }

    bpf_printk("%s", name);

    name = BPF_CORE_READ(d, d_name.name);
    d = BPF_CORE_READ(d, d_parent);

    bpf_printk("%s", name);

    name = BPF_CORE_READ(d, d_name.name);
    d = BPF_CORE_READ(d, d_parent);

    bpf_printk("%s", name);

    name = BPF_CORE_READ(d, d_name.name);
    d = BPF_CORE_READ(d, d_parent);

    bpf_printk("%s", name);

    // bpf_repeat(16)
    //{
    //     name = BPF_CORE_READ(d, d_name.name);
    //     bpf_printk("%d => %s", ctx->fd, name);
    //     d_parent = BPF_CORE_READ(d, d_parent);

    //    if (d_parent == d)
    //    {
    //        break;
    //    }

    //    d = d_parent;
    //}

    //  bpf_probe_read(&d, sizeof(d), f.f_path.dentry);

    // const unsigned char *name = d.d_name.name;
    // if (name != "")
    //{
    //     bpf_printk("%d => %s", ctx->fd, name);
    // }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";