GuardMon
=========

Introduction
-------------
GuardMon is a hypervisor based tool for monitoring system register accesses.
GuardMon is capable of logging read and write activities on CR0, CR4, debug
registers, GDT, IDT and MSRs from kernel memory not backed by any images.

This tool is particularly useful for analyzing the Windows built-in kernel patch
protection, a.k.a. PatchGuard as it runs on non-image regions most of time. A
demo movie can be found in Youtube:
- https://www.youtube.com/watch?v=PUcBtd0fZeA

GuardMon is implemented on the top of HyperPlatform and primarily designed for a
demo purpose. See a project page for more details of HyperPlatform:
- https://github.com/tandasat/HyperPlatform


Installation and Uninstallation
--------------------------------
On the x64 platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type
the following command, and then restart the system to activate the change:

    bcdedit /set {current} testsigning on

To install and uninstall the driver, use the 'sc' command. For installation:

    >sc create GuardMon type= kernel binPath= C:\Users\user\Desktop\GuardMon.sys
    >sc start GuardMon

And for uninstallation:

    >sc stop GuardMon
    >sc delete GuardMon

Note that the system must support the Intel VT-x and EPT technology to
successfully install the driver.

To install the driver on a virtual machine on VMware Workstation, see an "Using
VMware Workstation" section in the HyperPlatform User's Documents found in its
project page.
- https://github.com/tandasat/HyperPlatform/tree/master/Documents


Output
-------
All logs are printed out to DbgView and saved in C:\Windows\GuardMon.log.


Supported Platforms
----------------------
- x64 Windows 7, 8.1 and 10
- The system must support the Intel VT-x and EPT technology


License
--------
This software is released under the MIT License, see LICENSE.
