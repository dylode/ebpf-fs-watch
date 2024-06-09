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
    __uint(value_size, sizeof(path_segment));
    __uint(max_entries, PATH_SEGMENTS);
} cpu_buffer SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct path_elements));
    __uint(max_entries, PATH_SEGMENTS);
} relevant_paths SEC(".maps");

struct filter_ctx
{
    bool is_relevant;
    int last_index;
};

struct exec_params_t
{
    u64 __unused;
    u64 __unused2;
    unsigned int fd;
};
// inline bool local_strcmp(path_segment *a, path_segment *b)
//{
//     unsigned char *x = a[0];
//     unsigned char *y = b[0];
//
//     bpf_printk("%s %s %c %c", a, b, x, y);
//     // bpf_repeat(PATH_SEGMENT_LEN)
//     // {
//     //     bpf_printk("%s %s", a, b);
//     // }
//     return *x == *y;
//
//     // int i;
//
//     // for (int i = 0; i < 16; i++)
//     //{
//     //     if (a[i] != b[i])
//     //         return false;
//     // }
//     // return true;
//
//     // unsigned char c1, c2;
//
//     // for (int i = 0; i < 32; i++)
//     //{
//     //     c1 = *(cs + i);
//     //     c2 = *(ct + i);
//     //     if (c1 == '\0' || c2 == '\0')
//     //     {
//     //         return false;
//     //     }
//
//     //    if (c1 != c2)
//     //    {
//     //        return false;
//     //    }
//     //}
//
//     // for (int i = 0; i < PATH_SEGMENT_LEN; i++)
//     //{
//     //     if (i < a_length)
//     //     {
//     //         c1 = a[i];
//     //         // bpf_printk("%d %d %c", i, a_length, c1);
//     //         //  c2 = *(b + i);
//
//     //        // if (c1 != c2)
//     //        //{
//     //        //    return false;
//     //        //}
//     //    }
//     //    else
//     //    {
//     //        break;
//     //    }
//
//     //    if (i < b_length)
//     //    {
//     //        c2 = b[i];
//     //        // bpf_printk("%d %d %c", i, b_length, c2);
//     //        //  c2 = *(b + i);
//
//     //        // if (c1 != c2)
//     //        //{
//     //        //    return false;
//     //        //}
//     //    }
//     //    else
//     //    {
//     //        break;
//     //    }
//
//     //    if (c1 != c2)
//     //    {
//     //        return false;
//     //    }
//     //}
//
//     // bpf_repeat(PATH_SEGMENT_LEN)
//     //{
//     // }
//
//     return true;
// }

// static int filter(struct bpf_map *map, const void *key, struct path_elements *current_element, struct filter_ctx *ctx)
//{
//     if (current_element->path_elements_length == 0)
//     {
//         return 0; // continue to next entry in map
//     }
//
//     // unsigned char(*path_elements_buffer)[PATH_SEGMENTS] = ctx->path_elements_buffer;
//
//     struct path_elements2 *path_elements_buffer = ctx->path_elements_buffer;
//     if (path_elements_buffer->path_elements_length == 0)
//     {
//         return 1; // stop the foreach if there are no path elements in the buffer
//     }
//
//     if (current_element->path_elements_length > path_elements_buffer->path_elements_length)
//     {
//         return 0;
//     }
//
//     // int i = 0;
//     int j = path_elements_buffer->path_elements_length - 1;
//     int o = 0;
//
//     for (int i = 0; i < PATH_SEGMENTS; i++)
//     {
//         if (j >= 0 && j <= path_elements_buffer->path_elements_length)
//         {
//             unsigned char *a, *b;
//             a = current_element->path_elements[i];
//             struct path_element *e = path_elements_buffer->elements[j];
//
//             //`b = e->name;
//             //`if (e.length != NULL)
//             //`{
//             //`
//             //`    o = e.length;
//             //`}
//
//             // bpf_printk("%s %d", b, o);
//
//             // #pragma unroll
//             //             for (int k = 0; k < 16; k++)
//             //             {
//             //
//             //                 bpf_printk("%c %c", a[0], b[0]);
//             //                 // if (a[k] != b[k])
//             //                 //     return false;
//             //             }
//             //             return true;
//             //
//             //  const char *p;
//
//             //__builtin_memcpy(p, b, 5);
//
//             // bpf_printk("%c %c", a[1], b[1]);
//
//             if (local_strcmp(a, 255, e->name, e->length))
//             {
//                 ctx->is_relevant = true;
//                 return 1;
//             }
//         }
//         // if (j < 0)
//         //{
//         //     break;
//         // }
//
//         // if (j > PATH_SEGMENTS)
//         //{
//         //     j = PATH_SEGMENT_LEN;
//         // }
//
//         j--;
//     }
//
//     // bpf_repeat(PATH_SEGMENTS)
//     //{
//     //     if (i > current_element->path_elements_length - 1)
//     //     {
//     //         break;
//     //     }
//
//     //    if (j < 0)
//     //    {
//     //        break;
//     //    }
//
//     //    // if (i >= 0 && i < PATH_SEGMENTS)
//     //    //{
//     //    //     if (j >= 0 && j < PATH_SEGMENTS)
//     //    //     {
//     //    if (local_strcmp(current_element->path_elements[i], path_elements_buffer->path_elements[j]))
//     //    {
//     //        ctx->is_relevant = true;
//     //        return 1;
//     //    }
//     //    //     }
//     //    // }
//
//     //    i++;
//     //    j--;
//     //}
//
//     // #pragma unroll
//     //     for (int i = 0; i < 64; i++)
//     //     {
//     //         if (i > value->path_elements_length - 1)
//     //         {
//     //             break;
//     //         }
//     //
//     //         if (local_strcmp(value->path_elements[0], path_elements_buffer->path_elements[0], PATH_SEGMENT_LEN))
//     //         {
//     //             ctx->is_relevant = true;
//     //             return 1;
//     //         }
//     //
//     //         j--;
//     //     }
//
//     //__builtin_memcmp();
//
//     // bpf_printk("%d %d", value->path_elements_length, path_elements_buffer->path_elements_length);
//
//     // bpf_printk("%s %s", &value->path_elements[0], &path_elements_buffer->path_elements[0]);
//     return 0;
// }

static int filter(struct bpf_map *map, const void *key, struct path_elements *current_element, struct filter_ctx *ctx)
{
    unsigned int length = current_element->path_elements_length;
    if (length == 0)
    {
        return 0;
    }

    if (length > PATH_SEGMENTS)
    {
        length = PATH_SEGMENTS;
    }
    if (length < 0)
    {
        length = 0;
    }

    int i = 0;
    int j = ctx->last_index;
    bool is_relevant = false;
    for (i = 0; i < length; i++)
    {
        if (j < 0 || i < 0)
        {
            break;
        }

        path_segment *a = bpf_map_lookup_elem(&cpu_buffer, &j);
        if (!a)
        {
            break;
        }

        path_segment *b = current_element->path_elements[i];

        if (__builtin_memcmp(a, b, 1) == 0)
        {
            // bpf_printk("%s equals %s", a, b);
            is_relevant = true;
        }
        else
        {
            // bpf_printk("%s not equals %s", a, b);
            is_relevant = false;
        }

        j--;

        if (!is_relevant)
        {
            break;
        }
    }

    if (is_relevant)
    {
        ctx->is_relevant = true;
        return 1;
    }
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

    int i;
    const char *p;
    bpf_repeat(PATH_SEGMENTS)
    {
        path_segment *segment = bpf_map_lookup_elem(&cpu_buffer, &i);
        if (!segment)
        {
            return 0;
        }

        p = BPF_CORE_READ(d, d_name.name);
        bpf_probe_read_kernel_str(segment, PATH_SEGMENT_LEN, p);

        d_parent = BPF_CORE_READ(d, d_parent);
        if (d == d_parent)
        {
            break;
        }
        d = d_parent;
        i++;
    }

    struct filter_ctx filter_ctx;
    filter_ctx.is_relevant = false;
    filter_ctx.last_index = i;

    bpf_for_each_map_elem(&relevant_paths, &filter, &filter_ctx, 0);

    if (filter_ctx.is_relevant)
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