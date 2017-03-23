---
layout: post
title: "Pivoting kerberos golden tickets in Linux"
---
Kerberos golden ticket allows attacker to establish persistent and covert authenticated access to Windows domain. The attack works as follows:

1. Attacker gains administrator privileges in domain
2. Attacker extracts ntlm hash of a domain user "krbtgt" and obtains SID of the target domain
3. The attacker forges kerberos ticket
4. This ticket is used to authenticate in domain with privileges of domain administrator


Here's a detailed walkthough on how to use golden tickets on Kali Linux.

Let's start with obtaining krbtgt ntlm hash. I use an encoded version of mimikatz utility that gets me krbtgt hash without alerting AV (<https://github.com/artkond/bat-armor/blob/master/examples/krbtgt.bat>):

![Dcsync]({{ site.url }}/assets/golden1.png)
<!-- more -->

Stripping last number from krbtgt SID (in out case 502) we obtain domain SID S-1-5-21-3251500307-1840725093-2229733580.
Now to generate the ticket we use ticketer.py utility from Impacket (<https://github.com/CoreSecurity/impacket/blob/master/examples/ticketer.py>):

![ticketer.py]({{ site.url }}/assets/golden2.png)

Almost ready. Just need to export system variable, so impacket's psexec.py can use the ticket. When running psexec.py use -k key for kerberos authentication:

![KRB5CCNAME]({{ site.url }}/assets/golden3.png)

Same thing goes for other impacket tools such as wmiexec.py (which is more covert than psexec.py as it does not upload any binaries and starts no services) or atexec.py (uses scheduled tasks to exec your code):

![wmiexec.py]({{ site.url }}/assets/golden4.png)

Now that's all fine but what if you want to upload some files? Most probably you'll want to use smbclient for this task. Using kerberos with smbclient is a bit more complicated. You have to add your kerberos realm to config file located @ /etc/krb5.conf. In case you don't have krb5.conf you might want to install krb5-user package from your distro's repo.

{% highlight text %}
[realms]
    PENTESTO.LOC = {
        kdc = tcp/dc01:88
    }
{% endhighlight %}

TCP is preferable as you will be able to tunnel your requests to kerberos server over socks proxy if you decide to do some fun pivoting. Notice that realm should be uppercase.

![smbclient.py]({{ site.url }}/assets/golden5.png)

### Pivoting

Using kerberos ticket over socks tunnel requires a bit more extra work. Most likely you don't have direct access to active directory name servers so you have to edit /etc/hosts file. Add target server, domain controller (which is also kerberos server), and domain's FQDN. This is mandatory because kerberos only works with hostnames and will fail if you specify IP-address.

{% highlight text %}
$ cat /etc/hosts
...
10.0.0.89  pentesto.loc
10.0.0.89  dc01
...
{% endhighlight %}

I my case target server is the domain controller. Edit proxychains. Add your socks proxy and comment proxy_dns directive:

{% highlight text %}
$ cat proxychains.conf
...
#Proxy DNS requests - no leak for DNS data
#proxy_dns 
...
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  172.16.46.157 3128
{% endhighlight %}

In case you've set up /etc/hosts and /etc/krb5.conf correctly there should be no trouble running smbclient or psexec.py over socks:

![psexec.py]({{ site.url }}/assets/golden6.png)

![smbclient.py]({{ site.url }}/assets/golden7.png)

Note that psexec.py is sensitive to the info you provide. Domain name and username should be exact same you entered when forging ticket with ticketer.py.


