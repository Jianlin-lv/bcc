#ifndef __CHMODSNOOP_H
#define __CHMODSNOOP_H

#define TASK_COMM_LEN 16
#define DNAME_INLINE_LEN 32
#define DENTRY_MAX_NUM 10

struct dentry_buff{
    char dentry_name[DNAME_INLINE_LEN];
};

struct event{
    pid_t pid;
    unsigned int netns_inum;
    unsigned int cgroupns_inum;
    unsigned int pidns_inum;
    unsigned int dentry_inum;
    unsigned short mode;
    char comm[TASK_COMM_LEN];
};

#endif /* CHMODSNOOP_H */

