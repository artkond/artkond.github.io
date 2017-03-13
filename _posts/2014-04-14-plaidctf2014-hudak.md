---
layout: post
title: "Plaidctf 2014 Reverse 250 \"hudak\" write-up"
---
Task description:

{% highlight text %}
Can you reverse this program?
{% endhighlight %}

{% highlight text %}
$ file hudak
hudak: ELF 32-bit LSB executable
{% endhighlight %}

{% highlight text %}
$ strings hudak
hCA[
DCCC@EGhh
read_until
Enter the password.
Wrong!
Congratulations!
;*2$"
{% endhighlight %}

{% highlight text %}
$ ./hudak
Enter the password.
can_i_haz_flag
Wrong!
{% endhighlight %}

So no easy flag today ;) Ok, no problem, fire up IDA + linux_server and let's roll. sub_80484C0 is our main function:

![ida]({{ site.url }}/assets/plaidctf1.jpg)

First branch we encounter checks the input flag for correct length which should be 30 (including \n). If the length is correct we can step further down until we stop at 0x08048597 "call dword ptr [esi+8]", which is dynamically resolved so its easier to see in debugging session:

![ida]({{ site.url }}/assets/plaidctf2.jpg)

The result of this function determines whether the flag is correct or not. The "check_flag" function allocates a buffer and populates it with 4 function pointers. After that it calls one of these functions using implicit "call [eax+8]". This function returns modified string we provided as input and compares it to some hardcoded string in memory:

![ida]({{ site.url }}/assets/plaidctf3.jpg)

String located at 0x8048D60 is most likely our flag, but it looks gibberish so it's probably encrypted. Indeed, at the end of table_func4 our input string is XORed with 0x37.

![ida]({{ site.url }}/assets/plaidctf4.jpg)

XORing buffer at 0x8048D60 with 0x37 we get a readable string (except for 9th byte) "3..\_tvl3\xffstttwrp__1mea4as4i1_.". Not surprisingly it's not a valid flag. Apparently, XOR is not the only transformation of input. Let’s check our random input "iklumoyegxnjufqberxwzpdxaxeso" in memory just before the XOR operation. Interestingly enough, ESI points to an array of 30 strings. First string in array is the copy of our input string shifted several chars left, while the second one is shifted left one char compared to the first one, third string is shifted two chars and so on. Strings in this array are sorted i.e. first start with "axeso", second with "berx" and so on. Basically, this “xor” loop takes the last char from each of the strings (ebx = 29, so ecx+ebx is the last char), XORes it with 0x37 and appends it to the resulting buffer. So before being XORed our input buffer "iklumoyegxnjufqberxwzpdxaxeso" transforms to "xqpybxue\xffnikuxmszfeejlxdagrowo" (0xff is appended to input string at the very beginning). Knowing the algorithm we can find out which character precedes any given character.

{% highlight python %}
shuffled_flag = "3.._tvl3\xffstttwrp__1mea4as4i1_."
sorted_flag = ''.join(sorted(shuffled_flag))
 
for c1, c2 in zip(shuffled_flag, sorted_flag):
    print c1, '->', c2
{% endhighlight %}

Output:

{% highlight text %}
3 -> .
. -> .
. -> .
_ -> 1
t -> 1
v -> 3
l -> 3
3 -> 4
\xff -> 4
s -> _
t -> _
t -> _
t -> _
w -> a
r -> a
p -> e
_ -> i
_ -> l
1 -> m
m -> p
e -> r
a -> s
4 -> s
a -> t
s -> t
4 -> t
i -> t
1 -> v
_ -> w
. -> \xff
{% endhighlight %}

Since one character may occur several times in the string there are several possible strings that can be derived from this table. After some guessing it’s not too hard to find the one that makes sense – "4t_l34st_it_was_1mperat1v3…"
