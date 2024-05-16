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

    struct file f;
    bpf_probe_read(&f, sizeof(f), &fd[ctx->fd]);

    struct dentry d;
    bpf_probe_read(&d, sizeof(d), f.f_path.dentry);

    const unsigned char *name = d.d_name.name;
    if (name != "")
    {
        bpf_printk("%d => %s", ctx->fd, name);
    }
    // if (fd == 0)
    //{
    //     return 0;
    // }

    // struct file *f = fd[ctx->fd];
    // bpf_printk("%d", f);
    //  bpf_probe_read(f, sizeof(struct *file), fd[ctx->fd]);
    //  if (f == 0)
    //{
    //      return 0;
    //  }

    // struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
    // if (d == 0)
    //{
    //     return 0;
    // }

    // bpf_printk("%s", d->d_name.name);

    // const unsigned char *name = ();

    // unsigned char d_iname[40];
    // bpf_core_read_str(&d_iname, sizeof(d_iname), f->f_path.dentry->d_iname);
    // bpf_printk("write %s", d_iname);

    // bpf_core_read(&files, sizeof(void *), &task->files);

    // struct file *fd_array[64];
    // bpf_core_read(&fd_array, sizeof(fd_array), files->fd_array);

    // struct file *f;
    // bpf_core_read(&f, sizeof(struct file), files->fd_array);

    // bpf_printk("write %s", f->f_path.dentry->d_iname);

    // struct file *file;

    // bpf_core_read(&file, sizeof(void *), files->fd_array);
    //   unsigned char d_iname[40];
    // bpf_printk("write %s", fd_array[0].f_path.dentry->d_iname);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";