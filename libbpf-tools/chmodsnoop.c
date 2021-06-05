#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "chmodsnoop.h"
#include "chmodsnoop.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#define PERF_BUFFER_PAGES   16
#define PERF_POLL_TIMEOUT_MS	100

int map_fd;

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	//return vfprintf(stderr, format, args);
	return 0;
}


static void print_header(void)
{
	printf("Tracing chmod ... Hit Ctrl-C to end\n");
	printf("%-13s %-13s %-8s %-16s %-8s %-16s \n" ,"CGROUP-NS", "NET-NS", "PID", "COMM", "MOD", "PATH");
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	int i = 0;
	struct dentry_buff dentry_tmp = {};

	printf("%-13u %-13u %-8d %-16s %-8o ", e->cgroupns_inum, e->netns_inum, e->pid, e->comm, e->mode);

	for(i=e->dentry_inum-1; i > -1; --i)
	{
		bpf_map_lookup_elem(map_fd, &i, &dentry_tmp);
		printf("/%s",dentry_tmp.dentry_name);
	}
	printf("\n");
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;
	struct chmodsnoop_bpf *obj;
	int err;

	libbpf_set_print(libbpf_print_fn);

	obj = chmodsnoop_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF obj\n");
		return 1;
	}


	err = chmodsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF obj: %d\n", err);
		goto cleanup;
	}

	err = chmodsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n",
				strerror(-err));
		goto cleanup;
	}

	print_header();

	map_fd = bpf_map__fd(obj->maps.path_map);

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* main: poll */
	while (1) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;
	}

cleanup:
	chmodsnoop_bpf__destroy(obj);

	return err != 0;
}
