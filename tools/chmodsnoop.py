#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from struct import pack

# arguments
examples = """examples:
    ./chmodsnoop           # trace all do_fchmodat() event
"""

parser = argparse.ArgumentParser(
    description="Trace Chmod event",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/pid_namespace.h>
#include <net/net_namespace.h>

#define DENTRY_MAX_NUM 10

struct dentry_buff{
    char dentry_name[DNAME_INLINE_LEN];
};

BPF_ARRAY(path_map, struct dentry_buff, DENTRY_MAX_NUM);

struct data_t {
    u32 pid;
    u32 netns_inum;
    u32 cgroupns_inum;
    u32 pidns_inum;
    u32 dentry_inum;
    unsigned short mode;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

static inline int get_path(struct dentry **pdent, struct inode **pinode, struct data_t *data)
{
    struct dentry_buff dentry_tmp = {};

    if(data->dentry_inum < DENTRY_MAX_NUM && (*pinode && (*pinode)->i_ino != 2 && (*pinode)->i_ino != 1))
    {
        bpf_probe_read_kernel(dentry_tmp.dentry_name, DNAME_INLINE_LEN, (*pdent)->d_name.name);
        path_map.update(&data->dentry_inum, &dentry_tmp);

        if(((*pdent)->d_parent))
        {
           *pdent = (*pdent)->d_parent;
           *pinode = (*pdent)->d_inode;
        }
        data->dentry_inum++;
        return 1;
    }
    return 0;
}

int trace_chmod_common(struct pt_regs *ctx)
{
    struct data_t data = {};
    const struct path *path = NULL;
    struct task_struct *task = NULL;

    // Get PID
    data.pid = bpf_get_current_pid_tgid() >> 32;

    // Get COMMAND
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    //file mode
    data.mode = (unsigned short)PT_REGS_PARM2(ctx);

    // Get Namespace
    task = (struct task_struct *)bpf_get_current_task();
    data.cgroupns_inum = task->nsproxy->cgroup_ns->ns.inum;
    data.netns_inum = task->nsproxy->net_ns->ns.inum;
    data.pidns_inum = task->nsproxy->pid_ns_for_children->ns.inum;


    // Get file name
    path = (const struct path *)PT_REGS_PARM1(ctx);

    struct dentry *pdent = path->dentry;
    struct inode *pinode = path->dentry->d_inode;
    data.dentry_inum = 0;

    //unroll loop, Max directory 10
    if(!get_path(&pdent, &pinode, &data)) goto submit;
    if(!get_path(&pdent, &pinode, &data)) goto submit;
    if(!get_path(&pdent, &pinode, &data)) goto submit;
    if(!get_path(&pdent, &pinode, &data)) goto submit;
    if(!get_path(&pdent, &pinode, &data)) goto submit;
    if(!get_path(&pdent, &pinode, &data)) goto submit;
    if(!get_path(&pdent, &pinode, &data)) goto submit;
    if(!get_path(&pdent, &pinode, &data)) goto submit;
    if(!get_path(&pdent, &pinode, &data)) goto submit;
    if(!get_path(&pdent, &pinode, &data)) goto submit;


submit:
    events.perf_submit(ctx, &data, sizeof(struct data_t));

    return 0;
}

"""

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="chmod_common", fn_name="trace_chmod_common")

print("Tracing chmod ... Hit Ctrl-C to end")

print("%-13s %-13s %-8s %-16s %-8s %-16s" % ("CGROUP-NS", "NET-NS", "PID", "COMM", "MOD", "PATH"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-13d %-13d %-8d %-16s %-8o " % (event.cgroupns_inum, event.netns_inum, event.pid, event.comm, event.mode), nl="")

    path_table = b.get_table("path_map")
    for index in range(event.dentry_inum-1, -1, -1):
        dir = path_table.__getitem__(index)
        printb(b"/%s" % (dir.dentry_name), nl="")

    printb(b"")
    b["path_map"].clear()

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
