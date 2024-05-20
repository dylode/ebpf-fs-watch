#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

SEC(".maps")
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf;
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

    struct file **fd = BPF_CORE_READ(task, files, fdt, fd);

    struct file *f;
    bpf_probe_read_kernel(&f, sizeof(f), &fd[ctx->fd]);

    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
    struct dentry *d_parent;
    struct ringbuf_event *e;

    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("ringbuffer not reserved\n");
        return 0;
    }

    int i;

    const char *p;

#pragma unroll
    for (i = 0; i < 64; i++)
    {
        p = BPF_CORE_READ(d, d_name.name);
        bpf_probe_read_kernel_str(e->path_elements[i], sizeof(e->path_elements[i]), p);

        d_parent = BPF_CORE_READ(d, d_parent);
        if (d == d_parent)
        {
            break;
        }

        d = d_parent;
        i++;
    }

    e->path_elements_length = i;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";