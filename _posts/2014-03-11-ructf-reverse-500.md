---
layout: post
title: "Ructf quals 2014 Reverse 500 \"Arcfour\" write-up"
---
Task description:

{% highlight text %}
Crack me please.
Flag format is "RUCTF_.*"
{% endhighlight %}

Ok so we’re presented with a arcfour.exe binary.

{% highlight text %}
root@kali:~/vmshare/ctf/reverse/original# file arcfour.exe
arcfour.exe: PE32 executable (console) Intel 80386, for MS Windows, UPX сompressed
{% endhighlight %}

Well, simple enough! Just unpack it with `upx -d` and load into IDA :

{% highlight c %}
int __cdecl main(int argc, const char **argv, const char **envp)
{
        int result;
        if ( argc == 2 )
        {
                if ( lstrlenA(argv[1]) == 32 )
                {
                        dword_40337C = (int)argv[1];
                        if ( (unsigned __int8)(lstrcmpA(lpString1, argv[1]) & 1 ^ 1) == 1 )
                                result = puts("good job, put flag into system");
                        else
                                result = puts("nope...");
                }
                else
                {
                        result = 0;
                }
        }
        else
        {
                result = 0;
        }
        return result;
}
{% endhighlight %}
<!-- more -->

lsString1 is easy to find as it's hardcoded – `oh_nasty_boy!you_hacked_me:(hehe`. Pass it as an argument and we get:

{% highlight text %}
good job, put flag into system
{% endhighlight %}

Strange as it is obviously not the correct flag because we know that the valid one starts with `RUCTF_`. At this point I was a bit confused by the fact that `main` function was quite simple and didn't have any obvious jumps or calls. But looking further down the dissasemly I found quite interesting snippet of code that didn’t have any references (or so I though at the moment):

{% highlight text %}
sub_4010D0:
.text:004010E6                 mov     [ebp+var_3C], '¦'
.text:004010EA                 mov     [ebp+var_3B], 'L'
.text:004010EE                 mov     [ebp+var_3A], '¦'
.text:004010F2                 mov     [ebp+var_39], 3
.text:004010F6                 mov     [ebp+var_38], 0FCh
.text:004010FA                 mov     [ebp+var_37], 10h
.text:004010FE                 mov     [ebp+var_36], 28h
.text:00401102                 mov     [ebp+var_35], dl
.text:00401105                 mov     [ebp+var_34], 7Ah
.text:00401109                 mov     [ebp+var_33], cl
.text:0040110C                 mov     [ebp+var_32], 8Ch
.text:00401110                 mov     [ebp+var_31], 94h
.text:00401114                 mov     [ebp+var_30], 2Eh
.text:00401118                 mov     [ebp+var_2F], 0F9h
.text:0040111C                 mov     [ebp+var_2E], 69h
.text:00401120                 mov     [ebp+var_2D], 24h
.text:00401124                 mov     [ebp+var_2C], 9Fh
.text:00401128                 mov     [ebp+var_2B], 7Dh
.text:0040112C                 mov     [ebp+var_2A], 27h
.text:00401130                 mov     [ebp+var_29], 0C1h
.text:00401134                 mov     [ebp+var_28], 0C4h
.text:00401138                 mov     [ebp+var_27], 9
.text:0040113C                 mov     [ebp+var_25], cl
.text:0040113F                 mov     [ebp+var_24], 75h
.text:00401143                 mov     [ebp+var_23], 0EEh
.text:00401147                 mov     [ebp+var_21], 97h
.text:0040114B                 mov     [ebp+var_20], 8Dh
.text:0040114F                 mov     [ebp+var_1F], 0AFh
.text:00401153                 mov     [ebp+var_1E], 79h
.text:00401157                 mov     [ebp+var_1D], dl
.text:0040115A                 mov     [ebp+var_1C], 0
.text:0040115E                 mov     [ebp+oh_nice_key], 86h
.text:00401162                 mov     [ebp+var_17], 0DEh
.text:00401166                 mov     [ebp+var_16], 9Ah
.text:0040116A                 mov     [ebp+var_15], 0F8h
.text:0040116E                 mov     [ebp+var_14], 0DFh
.text:00401172                 mov     [ebp+var_13], 0F5h
.text:00401176                 mov     [ebp+var_12], al
.text:00401179                 mov     [ebp+var_11], 0E9h
.text:0040117D                 mov     [ebp+var_10], 0DDh
.text:00401181                 mov     [ebp+var_F], al
.text:00401184                 mov     [ebp+var_E], 0EFh
.text:00401188                 mov     [ebp+var_D], 0
.text:0040118C                 mov     [ebp+var_1], 0
.text:00401190                 mov     [ebp+var_C], eax
.text:00401193                 mov     [ebp+var_8], esp
{% endhighlight %}

After spending quite some time with unpacked binary I finally decided to give it a try and run the original. Now the hardcoded string doesn't seem to be valid! Sow now it was obvious that there’s something not quite right with the upx unpacking stub. Peeking at the original binary in IDA we see two functions: start and TlsCallback_0. `start` is not really insteresting as it’s pretty much unmodified upx unpacker but TlsCallback_0 is, on the other hand, the one where all the difference is. Tlscallback functions are used with thread programming to initialize data. The interesting thing about them is that these function are executed by windows pe loader before the program's entry point. So if you want to break on a tlscallback function you have to setup your debugger to pause before the default entry point. More info can be found here – <https://isc.sans.edu/diary/How+Malware+Defends+Itself+Using+TLS+Callback+Functions/6655>.

{% highlight text %}
TlsCallback_0:
UPX1:00406D04                 public TlsCallback_0
UPX1:00406D04 TlsCallback_0   proc near           
UPX1:00406D04
UPX1:00406D04 arg_4           = byte ptr  8
UPX1:00406D04
UPX1:00406D04                 nop
UPX1:00406D05                 cmp     [esp+arg_4], 1
UPX1:00406D0A                 jnz     short locret_406D23
UPX1:00406D0C                 mov     eax, large fs:18h
UPX1:00406D12                 mov     eax, [eax+30h]
UPX1:00406D15                 add     byte ptr [eax+2], 0B6h
UPX1:00406D19                 mov     dword ptr ds:loc_406C73+1, 0B0h
UPX1:00406D23
UPX1:00406D23 locret_406D23:                      
UPX1:00406D23                 retn
UPX1:00406D23 TlsCallback_0   endp
{% endhighlight %}

Running original binary leads to unhandled exception caused by invalid opcodes just before string comparison. These invalid bytes are inserted with tlscallback. Skipping tlscallback with a jump over memory editing instructions leads to correct program execution but again treats the hardcoded string `oh_nasty_boy!you_hacked_me:(hehe` as valid. Looking closer at main’s prologue we see a pointer being pushed onto stack:

{% highlight text %}
00401220   55               PUSH EBP
00401221   8BEC             MOV EBP,ESP
00401223   6A FF            PUSH -1
00401225   68 F8214000      PUSH arcfour.004021F8
0040122A   68 241B4000      PUSH arcfour.00401B24   ; JMP to MSVCR90._except_handler3
{% endhighlight %}

This address references a list of exception handlers located at 0x004012AC and 0x004012C5 . So now with breakpoints on both handlers we pass exception to program. Tracing down sub_4010D0 we observe an ascii string `Oh,NiC3_k3Y` generating on stack. Code generation:

{% highlight text %}
.text:004011C3 loc_4011C3:                             
.text:004011C3                 xor     [ebp+eax+oh_nice_key], cl
.text:004011C7                 inc     eax
.text:004011C8                 cmp     eax, 0Bh
.text:004011CB                 jb      short loc_4011C3
{% endhighlight %}

Task's name infers that rc4 stream cipher is used so we might assume that `Oh,NiC3_k3Y` is the corresponding encryption/decryption key. This key is used in sub_401000 to modify argument that is passed to program. Further down the code the modified argument string is compared with a seemingly random buffer in memory. Since encryption/decryption is identical I passed "random" buffer's address to sub_401000, which successfully decrypted the buffer which turn out to be a valid flag.