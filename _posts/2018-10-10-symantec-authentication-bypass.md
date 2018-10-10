---
layout: post
comments: true
title: "Symantec Messaging Gateway authentication bypass"
description: "A tale of discovering a critical vulnerability in Symantec Messaging Gateway during a pentest engagement"
---

When conducting security assessments sometimes there is no quick way past external perimeter of the customer's network. As a last resort option one may commit to an extensive research of the few software appliances the client has exposed. This approach will often yield results, as it was the case with Symantec Messaging Gateway.

![Symantec Messaging Gateway]({{ site.url }}/assets/symantec_2018/symantec_login.png)
<!-- more -->

Like in most login interfaces a password reset feature is present. "Forgot password" link appears after unsuccessful login attempt. The username is prompted afterwards. What happens under the hood is that SMG creates a password reset link. It puts an encrypted token in the link in order to make sure that the password is reset by the genuine owner of the account. 

That's where the vulnerability is present. The string format of the token before encryption is "username:password". Sounds fair enough as this enables SMG to check the token against a valid user password. Incidentally, when we tried "admin:" for a token, the system behaved in an unusual way. It generated a valid administrator session! 

Of course the token is encrypted, so how do we get the key? Luckily there has been a previous research for a similar [bug](https://seclists.org/fulldisclosure/2017/Aug/28) in Symantec Gateway. Philip Pettersson found an authentication bypass that encrypted a parameter in a similar manner. He talks about a hardcoded key:

```
Fortunately, the encryption is just PBEWithMD5AndDES using a static password, 
conveniently included in the code itself. I won't include the encryption password 
or a fully encrypted notify string in this post.
```

Indeed, the key is static across SMG installations. We won't disclose the key in this post. If one encrypts the following string - "admin:" and passes it as a value for GET parameter "authorization" he will receive a valid admin session. Example request:

```
GET /brightmail/action2.do?method=passwordReset&authorization=<..>%3d HTTP/1.1
Host: 192.168.17.15
Connection: close
Cache-Control: max-age=0
Origin: https://192.168.17.15
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```

Expected response:

```
HTTP/1.1 302 Found
Server: Apache-Coyote/1.1
Cache-Control: no-store,no-cache
Pragma: no-cache
Expires: Thu, 01 Jan 1970 00:00:00 GMT
X-Frame-Options: SAMEORIGIN
Set-Cookie: JSESSIONID=97B8786DB8CC163EB2A4C595D1028E1D; Path=/brightmail; Secure; HttpOnly
Location: /brightmail/viewWelcome.do?userID=1
Content-Type: text/html;charset=UTF-8
Content-Length: 0
Connection: close
```

![Symantec Messaging Gateway]({{ site.url }}/assets/symantec_2018/symantec_burp1.png)

Surely enough the cookie generated is a valid administrator session:

![Symantec Messaging Gateway Admin Login]({{ site.url }}/assets/symantec_2018/symantec_admin_login.png)


To our knowledge the vulnerability is only present if the password reset feature is enabled in the appliance. At the time of testing the vulnerable version was 10.6.5. Symantec has released an advisory for this issue:

- <https://support.symantec.com/en_US/article.SYMSA1461.html>


## Disclosure timeline

* Vendor contacted - 11/07/2018
* Vendor assigned Tracking ID - 11/07/2018
* Vendor published vulnerability advisory, patched software versions released - 12/09/2018

We would like to thank Symantec for their prompt response and professionalism in dealing with the vulnerability.