mod_authn_ntlm
==============

Apache 2.4 SSPI NTLM based authentication module for windows

Inspired by mod_auth_sspi project from Tim Castello <tjcostel@users.sourceforge.net>

Using the module from Tim worked only on Apache versions <2.4.

In addition to that if you misstype your credentials the Apache responded with a
"incorrect credentials messages" and you need to close the browser to retry.
If you used a Internet Explorer in the wrong domain a login would fail as well.

This version works on APache 2.4 using NTLM authentication and asks for correct
credentials for 3 times.

We needed that for our own and as many in the net were asking for a working version 
for Apache 2.4 we decided to share this project to the community.
