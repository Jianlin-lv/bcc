#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "maps.bpf.h"
#include "chmodsnoop.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DENTRY_MAX_NUM);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct dentry_buff));
} path_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline int get_path(struct dentry **pdent, struct inode **pinode, struct event *data)
{
    struct dentry_buff dentry_tmp = {};

    unsigned long i_ino = BPF_CORE_READ(*pinode, i_ino);

    if(data->dentry_inum < DENTRY_MAX_NUM && (*pinode && i_ino != 2 && i_ino != 1))
    {
	const unsigned char *p_name = BPF_CORE_READ(*pdent, d_name.name);
	bpf_probe_read_kernel_str(dentry_tmp.dentry_name, DNAME_INLINE_LEN, p_name);
	bpf_map_update_elem(&path_map, &data->dentry_inum, &dentry_tmp, 0);


	struct dentry *d_parent = BPF_CORE_READ(*pdent, d_parent);
	if ( d_parent )
        {
	   *pdent = d_parent;
	   *pinode = BPF_CORE_READ(*pdent, d_inode);
        }
        data->dentry_inum++;
        return 1;
    }
    return 0;
}


SEC("kprobe/chmod_common")
int BPF_KPROBE(kprobe_chmod_common, const struct path *path, umode_t mode)
{
    struct event event= {};
    struct task_struct *task = NULL;

    // Get PID
    event.pid = bpf_get_current_pid_tgid() >> 32;

    // Get COMMAND
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    //file mode
    event.mode = mode;

    // Get Namespace
    task = (struct task_struct *)bpf_get_current_task();
    event.cgroupns_inum = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
    event.netns_inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    event.pidns_inum = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);


    // Get file name
    struct dentry *pdent;
    struct inode *pinode = path->dentry->d_inode;

    pdent = BPF_CORE_READ(path, dentry);
    pinode = BPF_CORE_READ(path, dentry, d_inode);

    //bpf_d_path(path, event.path, 128);
    event.dentry_inum = 0;

    //unroll loop, Max directory 10
    if(!get_path(&pdent, &pinode, &event)) goto submit;
    if(!get_path(&pdent, &pinode, &event)) goto submit;
    if(!get_path(&pdent, &pinode, &event)) goto submit;
    if(!get_path(&pdent, &pinode, &event)) goto submit;
    if(!get_path(&pdent, &pinode, &event)) goto submit;
    if(!get_path(&pdent, &pinode, &event)) goto submit;
    if(!get_path(&pdent, &pinode, &event)) goto submit;
    if(!get_path(&pdent, &pinode, &event)) goto submit;
    if(!get_path(&pdent, &pinode, &event)) goto submit;
    if(!get_path(&pdent, &pinode, &event)) goto submit;


submit:
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
