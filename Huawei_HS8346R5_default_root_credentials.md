# Huawei HS8346R5 Default Root Credentials Permit Privileged Telnet Access

## Overview

- **Vendor:** Huawei
- **Product:** Huawei HS8346R5 GPON ONT
- **Tested firmware:** `V500R019C20SPC050B031`
- **Operating environment:** Dopra Linux / BusyBox
- **Affected service:** Telnet management service
- **Tested target:** `192.168.1.1`
- **Observed username:** `root`
- **Observed password:** `adminHW`
- **Vulnerability type:** Use of default administrative credentials
- **Required network position:** Access to the Telnet management service, observed on the local management network
- **Observed result:** Authentication succeeded and a privileged-looking BusyBox shell was reached
- **Suggested CWE:** CWE-1392 — Use of Default Credentials
- **Suggested severity:** High

## Vulnerability Basic Information

- **Management protocol:** Telnet
- **Target address used during verification:** `192.168.1.1`
- **Credential:** `root / adminHW`
- **Post-login interface:** Huawei WAP command environment
- **Privilege transition commands observed:** `su`, followed by `shell`
- **Post-transition shell:** BusyBox `ash`
- **Observed shell prompt:** `WAP(Dopra Linux) #`
- **UID 0 output in the supplied screenshot:** Not captured; an `id` screenshot is recommended before final CNA submission
- **Confirmed issue:** The documented credential is accepted by the tested device and grants access to the privileged management path

## Vulnerability Description

The Huawei HS8346R5 device accepts a known default credential over its Telnet management service:

```text
Username: root
Password: adminHW
```

During physical-device verification, the credential was accepted by the Telnet service. The session entered the Huawei WAP management environment. The commands `su` and `shell` then produced a BusyBox `ash` shell with a `#` prompt.

A fixed or widely shared administrative credential creates a direct authentication weakness. Any attacker who can reach the Telnet service and knows the credential can authenticate without possessing a device-unique secret. If the credential remains unchanged across devices or after factory reset, compromise scales beyond a single installation.

The security issue is independent of the `/bin/write_proc` SUID vulnerability. The default credential provides its own access path and must be reported separately. It must not be used as proof that `/bin/write_proc` produced a root shell.

## Runtime Verification

<img width="1002" height="663" alt="8ce56baedd59b55e91c99b1aaf1690b2" src="https://github.com/user-attachments/assets/fbdd8063-d536-438f-8e56-a22cb5d1cf51" />


The observed session was:

```text
Telnet session to admin@192.168.1.1

Welcome Visiting Huawei Home Gateway
Copyright by Huawei Technologies Co., Ltd.

Login:root
Password:
Password is default value, please modify it!
WAP>su
success!
SU_WAP>shell

BusyBox v1.26.2 () built-in shell (ash)
Enter 'help' for a list of built-in commands.

WAP(Dopra Linux) #
```

The message:

```text
Password is default value, please modify it!
```

is strong runtime evidence that the accepted password is recognized by the device as a default value.

### Recommended Final Confirmation

Before public disclosure or CNA submission, capture the following immediately after entering the BusyBox shell:

```sh
id
whoami
```

The ideal evidence is:

```text
uid=0(root) gid=0(root)
root
```

The supplied screenshot already proves credential acceptance and access to a `#` shell, but explicit UID output removes ambiguity about the effective privilege context.

## Complete Authentication Flow

```text
Attacker on reachable management network
        |
        | Telnet to 192.168.1.1
        v
Huawei Home Gateway login prompt
        |
        | username: root
        | password: adminHW
        v
Default password accepted
        |
        v
Huawei WAP command environment
        |
        | su
        | shell
        v
BusyBox ash shell with "#" prompt
```

## Verification Procedure

The following procedure reproduces the observed authentication behavior on an authorized test device.

1. Connect to the Telnet service:

```sh
telnet 192.168.1.1
```

2. Enter the credentials:

```text
Login: root
Password: adminHW
```

3. Observe the device warning:

```text
Password is default value, please modify it!
```

4. Enter the privileged management mode:

```text
WAP>su
success!
```

5. Request a shell:

```text
SU_WAP>shell
```

6. Confirm the effective identity:

```sh
id
whoami
```

The verification should record:

- device model and firmware version;
- Telnet listening address and interface;
- whether the service is LAN-only, WAN-reachable, or operator-network reachable;
- whether the credential works after factory reset;
- whether the password is identical on multiple devices;
- the explicit UID and GID after shell entry.

## Static-Analysis Status

No authentication binary or configuration file proving where `adminHW` is stored was supplied for this report. This report therefore does not invent a decompiled credential comparison.

The primary evidence is the physical-device authentication transcript and the device-generated warning that the password is a default value.

To determine whether the credential is hard-coded, generated, provisioned by an operator, or stored in configuration, the following offline analysis should be added if available:

```sh
grep -R "adminHW" <extracted-firmware-root> 2>/dev/null
grep -R "Password is default value" <extracted-firmware-root> 2>/dev/null
```

Potential binaries and configuration stores should then be examined in IDA or a hex/string viewer. If a fixed credential comparison is confirmed in firmware, CWE-798 may be considered as an additional mapping. Until then, CWE-1392 is the more defensible classification.

## Security Impact

Successful use of an administrative Telnet credential may permit:

- unrestricted device configuration changes;
- access to system and operator settings;
- reading stored credentials and management configuration;
- modification of LAN, WAN, WLAN, firewall, NAT, GPON, CWMP, and service settings;
- installation of persistence mechanisms;
- disabling security controls or management services;
- interception or redirection of traffic processed by the ONT;
- denial of service through configuration changes or process termination.

The exact impact depends on the effective UID and command restrictions after login. Capturing `id`, `whoami`, and a non-destructive permission test will establish the final privilege level.

## Attack Preconditions

The attacker must be able to reach the Telnet service. On the tested system, the target was `192.168.1.1`, which indicates a local or adjacent management-network attack path.

The report should not claim internet-wide remote exploitation unless WAN exposure is independently confirmed.

No prior valid account is required if the default credential is unchanged.

## Affected Scope

The confirmed affected scope is:

```text
Huawei HS8346R5
Firmware V500R019C20SPC050B031
Tested physical device
```

Other firmware builds, operator customizations, and hardware revisions should be listed as affected only after verification.
