#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "path_elements.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct path_elements));
    __uint(max_entries, 1);
} cpu_buffer SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct path_elements));
    __uint(max_entries, 255);
} relevant_paths SEC(".maps");

struct filter_ctx
{
    bool is_relevant;
    struct path_elements *path_elements_buffer;
    // unsigned char (*path_elements_buffer)[PATH_SEGMENTS];
};

struct exec_params_t
{
    u64 __unused;
    u64 __unused2;
    unsigned int fd;
};

static bool local_strcmp(const char *cs, const char *ct)
{
    unsigned char c1, c2;

    bpf_repeat(PATH_SEGMENT_LEN)
    {
        c1 = *cs++;
        c2 = *ct++;

        if (c1 != c2)
        {
            return false;
        }
    }

    return true;
}

static int filter(struct bpf_map *map, const void *key, struct path_elements *value, struct filter_ctx *ctx)
{
    if (value->path_elements_length == 0)
    {
        return 0; // continue to next entry in map
    }

    // unsigned char(*path_elements_buffer)[PATH_SEGMENTS] = ctx->path_elements_buffer;

    struct path_elements *path_elements_buffer = ctx->path_elements_buffer;
    if (path_elements_buffer->path_elements_length == 0)
    {
        return 1; // stop the foreach if there are no path elements in the buffer
    }

    if (value->path_elements_length > path_elements_buffer->path_elements_length)
    {
        return 0;
    }

    int i = 0;
    int j = value->path_elements_length - 1;

    bpf_repeat(PATH_SEGMENTS)
    {
        if (i > value->path_elements_length - 1)
        {
            break;
        }

        if (i >= 0 && i < PATH_SEGMENTS)
        {
            if (j >= 0 && j < PATH_SEGMENTS)
            {
                if (local_strcmp(value->path_elements[i], path_elements_buffer->path_elements[j]))
                {
                    ctx->is_relevant = true;
                    return 1;
                }
            }
        }

        i++;
        j--;
    }

    // #pragma unroll
    //     for (int i = 0; i < 64; i++)
    //     {
    //         if (i > value->path_elements_length - 1)
    //         {
    //             break;
    //         }
    //
    //         if (local_strcmp(value->path_elements[0], path_elements_buffer->path_elements[0], PATH_SEGMENT_LEN))
    //         {
    //             ctx->is_relevant = true;
    //             return 1;
    //         }
    //
    //         j--;
    //     }

    //__builtin_memcmp();

    // bpf_printk("%d %d", value->path_elements_length, path_elements_buffer->path_elements_length);

    // bpf_printk("%s %s", &value->path_elements[0], &path_elements_buffer->path_elements[0]);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int handle_sys_enter_write(struct exec_params_t *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct file **fd = BPF_CORE_READ(task, files, fdt, fd);

    struct file *f;
    bpf_probe_read_kernel(&f, sizeof(f), &fd[ctx->fd]);

    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
    struct dentry *d_parent;

    u32 index = 0;
    struct path_elements *path_elements_buffer;
    // unsigned char(*path_elements_buffer)[PATH_SEGMENTS];
    path_elements_buffer = bpf_map_lookup_elem(&cpu_buffer, &index);
    if (!path_elements_buffer)
    {
        return 0;
    }

    int i;

    const char *p;

#pragma unroll
    for (i = 0; i < 64; i++)
    {
        p = BPF_CORE_READ(d, d_name.name);
        bpf_probe_read_kernel_str(path_elements_buffer->path_elements[i], PATH_SEGMENT_LEN, p);

        d_parent = BPF_CORE_READ(d, d_parent);
        if (d == d_parent)
        {
            break;
        }

        d = d_parent;
        i++;
    }

    path_elements_buffer->path_elements_length = i;

    struct filter_ctx filter2;
    filter2.is_relevant = false;
    filter2.path_elements_buffer = path_elements_buffer;

    bpf_for_each_map_elem(&relevant_paths, &filter, &filter2, 0);

    if (filter2.is_relevant)
    {
        bpf_printk("yeey");
    }

    // e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    // if (!e)
    //{
    //     bpf_printk("ringbuffer not reserved\n");
    //     return 0;
    // }

    // e->path_elements_length = i;
    // bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";