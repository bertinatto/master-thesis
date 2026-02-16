//go:build ignore

#include "bpf_tracing.h"
#include "common.h"

#include <asm/unistd.h>
#include <asm/unistd_64.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENTRIES 100

struct bpf_map_def SEC("maps") index_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};


struct bpf_map_def SEC("maps") alert_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") syscall_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") trash_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = 256,
	.max_entries = MAX_ENTRIES,
};


struct bpf_map_def SEC("maps") ns_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = MAX_ENTRIES,
};

#define PATH_MAX 32

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	char target_process_name[] = "nsenter";
	char comm[16];

	bpf_get_current_comm(&comm, sizeof(comm));
	int result = __builtin_memcmp(comm, target_process_name, sizeof(target_process_name));
	if (result != 0) {
		return 0; // Not the target process, exit
	}

	// We need to deal with the index in an atomically way.
	u32 index_key      = 0;
	u64 index_init_val = 0;
	u64 *index_ptr;
	index_ptr = bpf_map_lookup_elem(&index_map, &index_key);
	if (!index_ptr) {
		bpf_map_update_elem(&index_map, &index_key, &index_init_val, BPF_ANY);
		return 0;
	}

	// Reserves the current index value for the current syscall and atomically increments the index for the next one.
	u32 syscall_index = __sync_fetch_and_add(index_ptr, 1) % MAX_ENTRIES;

	u64 syscall_init_val = 0, *syscall_ptr;
	syscall_ptr          = bpf_map_lookup_elem(&syscall_map, &syscall_index);
	if (!syscall_ptr) {
		bpf_map_update_elem(&syscall_map, &syscall_index, &syscall_init_val, BPF_ANY);
		return 0;
	}

	unsigned long syscall_id = ctx->args[1];

	// Store syscall in our map. This effectively sends the information to user-space.
	*syscall_ptr = syscall_id;

	// Used to grab the args
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

	if (syscall_id == __NR_openat) {
		struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

		int dfd = PT_REGS_PARM1(regs);
		/* const char *pathname = (const char *)PT_REGS_PARM2(regs); */

		// Get string pointer
		/* const char *pathname_ptr; */
		u64 pathname_ptr;
		bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), &PT_REGS_PARM2(regs));

		// Read the string
		char pathname[256];
		int len = bpf_probe_read_str(&pathname, sizeof(pathname), (void *)pathname_ptr);
        bpf_printk("openat path len: %d\n", len);
        bpf_printk("openat path: %s\n", pathname);

		// Store in the map
		bpf_map_update_elem(&trash_map, &syscall_index, &pathname, BPF_ANY);

        /* char blah[] = "blah"; */
		/* bpf_map_update_elem(&trash_map, &syscall_index, &blah, BPF_ANY); */
	}

	if (syscall_id == __NR_setns) {
		// Get string pointer
		u64 nstype;
		bpf_probe_read(&nstype, sizeof(nstype), &PT_REGS_PARM2(regs));

		// Read the string
		/* char pathname[256]; */
		/* bpf_probe_read_str(&pathname, sizeof(pathname), (void *)pathname_ptr); */
		if (nstype == 0x00020000) {
		  bpf_map_update_elem(&ns_map, &syscall_index, &nstype, BPF_ANY);
		}
	}

    u8 match_setns = 0;
    u8 match_openat = 0;

    #pragma unroll
    for (u32 i = 0; i < MAX_ENTRIES; i++) {
      u32 key = i;  // Force verifier to see a valid pointer
      u64 *syscall_value = bpf_map_lookup_elem(&syscall_map, &key);
      if (!syscall_value) {
        continue;
      }

      if (*syscall_value == __NR_setns) {
        u64 *nstype = bpf_map_lookup_elem(&ns_map, &key);
        if (nstype && *nstype == 0x00020000) {
          match_setns = 1;
          continue;
        }
      }
      
      if (*syscall_value == __NR_openat) {
        char buf[32];
        char *valopenat = bpf_map_lookup_elem(&trash_map, &key);
        if (valopenat) {
          const char target_path[] = "/proc/1/ns/mnt";
          bpf_probe_read_str(&buf, sizeof(buf), valopenat);
          if (__builtin_memcmp(buf, target_path, sizeof(target_path) - 1) == 0) {
            match_openat = 1;
            continue;
          }
        }
      }

    } // for loop

    if (match_setns >= 1 && match_openat >= 1) {
      u32 index_key = 0;
      u64 pid_tgid = bpf_get_current_pid_tgid();
      u32 pid = pid_tgid >> 32;
      u64 pid_value = pid;
      bpf_map_update_elem(&alert_map, &index_key, &pid_value, BPF_ANY);
    }

	return 0;
}
