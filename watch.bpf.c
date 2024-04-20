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
    // bpf_printk("hi");
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files;

    bpf_core_read(&files, sizeof(void *), &task->files);

    // struct file *fd_array[64];
    // bpf_core_read(&fd_array, sizeof(fd_array), files->fd_array);

    struct file *file;

    bpf_core_read(&file, sizeof(struct file), files->fd_array[ctx->fd]);
    //  unsigned char d_iname[40];
    //  bpf_printk("write %s", file->f_path.dentry->d_iname);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";