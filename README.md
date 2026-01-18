# Aether-Apex: Advanced Kernel Internals & Stealth Research

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://kernel.org)
[![Category: Research](https://img.shields.io/badge/Category-Security%20Research-red.svg)]()

## 📌 Project Overview
**Aether-Apex** is a sophisticated Linux Kernel Module (LKM) framework designed for the study of **Ring-0 rootkit mechanics**, memory isolation bypasses, and stealth persistence. 

The framework demonstrates how the Linux VFS (Virtual File System) and Network stack can be surgically hooked to manipulate the system's "source of truth." This research is intended for security professionals and kernel developers to better understand **Advanced Persistent Threat (APT)** behavior and improve EDR detection heuristics.

---

## 🛠️ Technical Key Features

### 1. Memory Protection Bypass (SCT Hooking)
Utilizes a **non-destructive `vmap` remapping** technique to bypass the **CR0 Write-Protection (WP)** bit. This allows the framework to safely swap pointers in the System Call Table (SCT) without triggering kernel panics or global CPU instability.

### 2. VFS Stealth (File & Process Cloaking)
Implements a deep hook on the `getdents64` system call. By intercepting and filtering directory entries in kernel space, the framework can:
* **Hide Files:** Any file with a specific prefix (e.g., `ghost_`) becomes invisible to `ls`, `find`, and `du`.
* **Hide Processes:** Cloaks specific PIDs from `/proc`, effectively blinding tools like `ps`, `top`, and `htop`.

### 3. Network Connection Obfuscation
Hooks the `seq_file` operations for `/proc/net/tcp`. This filters the kernel's reporting of active socket connections, allowing specific ports (e.g., 4444) to remain active but invisible to `netstat`, `ss`, and `lsof`.

### 4. Dynamic Symbol Resolution
Leverages **Kprobes** to resolve unexported kernel symbols at runtime. This ensures compatibility with modern kernels (5.7+) where `kallsyms_lookup_name` is no longer exported to modules.

### 5. Modular Self-Erasure
Upon initialization, the module unlinks itself from the `modules` linked list and the `kobject` tree. This achieves a **zero-listing state**, making the module undetectable by `lsmod` or `/sys/module/` checks.

---

## 🚀 Installation & Usage

### Prerequisites
* Linux Kernel Headers (`linux-headers-$(uname -r)`)
* Build essentials (`gcc`, `make`)
* **Environment:** Tested on Kali Linux / Debian (Kernel 6.x+)

### Build
```bash
# Clone the repository
git clone [https://github.com/SS7ZX/Aether-Apex-Kernel-Research.git](https://github.com/SS7ZX/Aether-Apex-Kernel-Research.git)
cd Aether-Apex-Kernel-Research

# Compile the module
make
```
## Deployment & Testing
```bash
# Load the module
sudo insmod aether_apex.ko

# Trigger Privilege Escalation (C2 Interface)
mkdir aether_elevate
whoami # Result: root

# Hide a process
mkdir aether_hide_1234  # Replaces 1234 with target PID
```
## 🔍 Forensic Analysis & Detection
As a security research project, we provide the following detection vectors for blue teams:

SCT Integrity: Compare sys_call_table addresses against System.map.

Memory Discrepancy: Look for executable memory regions with no associated entry in /proc/modules.

Kprobe Auditing: Monitor /sys/kernel/debug/kprobes/list for unauthorized hooks.

## ⚖️ Disclaimer
This project is for educational and research purposes only. Unauthorized use of this tool on systems you do not own is illegal and unethical. The author is not responsible for any misuse.

<p>Author: SS7ZX</p>

<p>Research Group: Aether Apex Team</p>
