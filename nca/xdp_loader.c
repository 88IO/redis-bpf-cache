/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

// #include "../common/common_params.h"
// #include "../common/common_user_bpf_xdp.h"
// #include "../common/common_libbpf.h"

static const char *default_filename = "xdp_prog_kern.o";
static const char *default_ifname = "enp1s0f1";

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;
	struct bpf_program *xdp_prog, *tc_prog;
	int xdp_prog_fd;
	struct bpf_object_load_attr load_attr;
	char tc_filename[PATH_MAX];
	char ifname[IF_NAMESIZE];
	int ifindex;
	bool do_unload = false;
	int err, len, opt;
	__u32 xdp_flags = 0;

	strncpy(ifname, default_ifname, IF_NAMESIZE);

	while ((opt = getopt(argc, argv, "d:U")) != -1) {
		switch (opt) {
			case 'd':
				strncpy(ifname, optarg, IF_NAMESIZE);
				break;
			case 'U':
				do_unload = true;
				break;
			default:
				break;
		}
	}

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
	fprintf(stderr,
		"ERR: --dev name unknown err(%d):%s\n",
		errno, strerror(errno));
		return -1;
	}

	xdp_flags |= XDP_FLAGS_DRV_MODE;

	if (do_unload) {
		if (bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) 
			fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n", ifindex);
		printf("successful unload.\n");
		return 0;
	}

	bpf_obj = bpf_object__open(default_filename);
	if (!bpf_obj) {
		fprintf(stderr, "Error: bpf_object__open failed\n");
		return 1;
	}

	xdp_prog = bpf_object__find_program_by_title(bpf_obj, "xdp/rx_filter");
	if (!xdp_prog) {
		fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
		return 1;
	}
	bpf_program__set_type(xdp_prog, BPF_PROG_TYPE_XDP);

	tc_prog = bpf_object__find_program_by_title(bpf_obj, "tc/tx_filter");
	if (!tc_prog) {
		fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
		return 1;
	}
	bpf_program__set_type(tc_prog, BPF_PROG_TYPE_SCHED_CLS);

	load_attr.obj = bpf_obj;
	load_attr.log_level = LIBBPF_WARN;

	err = bpf_object__load_xattr(&load_attr);
	if (err) {
		fprintf(stderr, "Error: bpf_object__load_xattr failed\n");
		return 1;
	}

	len = snprintf(tc_filename, PATH_MAX, "%s/%s/tc_tx_filter", pin_basedir, default_ifname);
	if (len < 0) {
		fprintf(stderr, "Error: Program name 'tc/tx_filter' is invalid\n");
		return -1;
	} else if (len >= PATH_MAX) {
		fprintf(stderr, "Error: Program name 'tc/tx_filter' is too long\n");
		return -1;
	}


retry:
	if (bpf_program__pin_instance(tc_prog, tc_filename, 0)) {
		fprintf(stderr, "Error: Failed to pin program 'tc/tx_filter' to path %s\n", tc_filename);
		if (errno == EEXIST) {
			fprintf(stdout, "BPF program 'tc/tx_filter' already pinned, unpinning it to reload it\n");
			if (bpf_program__unpin_instance(tc_prog, tc_filename, 0)) {
				fprintf(stderr, "Error: Fail to unpin program 'tc/tx_filter' at %s\n", tc_filename);
				return -1;
			}
			goto retry;
		}
		return -1;
	}

	xdp_prog_fd = bpf_program__fd(xdp_prog);
	if (xdp_prog_fd < 0) {
		fprintf(stderr, "Error: bpf_program__fd failed\n");
		return 1;
	}

	if (bpf_set_link_xdp_fd(ifindex, xdp_prog_fd, xdp_flags) < 0) {
		fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n", ifindex);
		return 1;
	} else {
		printf("Main BPF program attached to XDP on interface %d\n", ifindex);
	}

	return 0;
}
