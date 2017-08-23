
Apache 2.4 SSPI NTLM based authentication module for windows

Inspired by mod_auth_sspi project from Tim Castello <tjcostel@users.sourceforge.net>

Using the module from Tim worked only on Apache versions < 2.4.

In addition to that if you mistype your credentials the Apache responded with a
"incorrect credentials messages" and you need to close the browser to retry.
If you used a Internet Explorer in the wrong domain a login would fail as well.

This version works on Apache 2.4 using NTLM authentication and asks for correct
credentials for 3 times.

We needed that for our own and as many in the net were asking for a working version 
for Apache 2.4 we decided to share this project to the community.

Installation
============

Add the following line to your server config file:

`LoadModule auth_ntlm_module modules/mod_authn_ntlm.so`

Dependencies
============

You need to activate the following module (ldap_module) as well. Normally it is in your server config file, so just uncomment it:

`LoadModule ldap_module modules/mod_ldap.s`

If you want to add the authenticated user to your http header, load the following module as well and see below the sample config:

`LoadModule rewrite_module modules/mod_rewrite.s`

Sample Config
=============

    <Location /authenticate >
        #AllowOverride None
        AuthName "Private location"
        AuthType SSPI
        NTLMAuth On
        NTLMAuthoritative On
        <RequireAll>
            <RequireAny>
                Require valid-user
                #require sspi-user EMEA\group_name
            </RequireAny>
            <RequireNone>
                Require user "ANONYMOUS LOGON"
                Require user "NT-AUTORITÄT\ANONYMOUS-ANMELDUNG"
            </RequireNone>
        </RequireAll>
        # use this to add the authenticated username to you header
        # so any backend system can fetch the current user
        # rewrite_module needs to be loaded then
        # while X_ISRW_PROXY_AUTH_USER is your header name
        RequestHeader set X_ISRW_PROXY_AUTH_USER expr=%{REMOTE_USER}
    </Location>

List of available parameters
=============================

**Note:**

    if you want to set "NTLMDomain" or "NTLMDefaultDomain", please set both
    "NTLMOffserBasic" and "NTLMBasicPreferred" to "on". this is because
    we can't modify NTLMv2 response, we have to let user send clear text
    username and password, then ntlm module will use username and password
    to generate NTLM context, and do the authentication.

- `NTLMAuth` => set to 'on' to activate NTLM authentication here
- `NTLMOfferNTLM` => set to 'off' to allow access control to be passed along to lower modules if the UserID is not known to this module
- `NTLMAuthoritative` => set to 'off' to allow access control to be passed along to lower modules if the UserID is not known to this module
- `NTLMOfferBasic` => set to 'on' to allow the client to authenticate against NT with 'Basic' authentication instead of using the NTLM protocol
- `NTLMPackage` => set to the name of the package you want to use to authenticate users
- `NTLMPackages` => set to the name of the package you want to use to authenticate users
- `NTLMDomain` => force users to authenticated against for cleartext authentication if specified.
- `NTLMDefaultDomain` => set to the domain you want users authenticated against for cleartext authentication - if not specified, the local machine, then all trusted domains are checked
- `NTLMOmitDomain` => set to 'on' if you want to omit / exclude the domain name. set to 'off' if you want the usernames to include the domain name
- `NTLMUsernameCase` => set to 'lower' if you want the username and domain to be lowercase, set to 'upper' if you want the username and domain to be uppercase, if not specified, username and domain case conversion is disabled
- `NTLMBasicPreferred` => set to 'on' if you want basic authentication to be the higher priority
- `NTLMMSIE3Hack` => set to 'on' if you expect MSIE 3 clients to be using this server
- `NTLMPerRequestAuth` => set to 'on' if you want authorization per request instead of per connection
- `NTLMChainAuth` => set to 'on' if you want an alternative authorization module like SVNPathAuthz to work at the same level
- `NTLMNotForced` => Set to on to allow requests pass even when user not really authorized This is needed if same resources can be access with and without NTLM auth

Configure several groups
========================

If you want to add more then one group then use the following syntax, so the module can process them correctly.

    <RequireAny>
        require sspi-group "DOMAIN\GROUP2" "DOMAIN\GROUP1"
    </RequireAny>

Configure server to allow local ntlm authentication
===================================================

If you set apache to listen to a FQDN you might not be able to authenticate against the site if you are open this site on the server itself.

You can read about the cause and the workaround here:

https://support.microsoft.com/en-us/kb/896861

> I did test method 1 and added the FQDN domain in the registry, after ntlm authentication works on the local server.

Build instructions
===================

- Install the latest CMake from https://cmake.org/download/
- Download Win64 Apache 2.4 from https://www.apachelounge.com/download/ (or use your own version)
- Extract it to this folder (so there is a folder called Apache24 inside this folder)

**Open command prompt:**

`mkdir build`

`cd build`

`cmake -G "YOUR_GENERATOR" ..`

---

Open solution found in build folder
Build solution for **Debug** and **Release**
Find the build output at: `build\debug` or `build\release`

> You may have to rename the `.dll` to a `.so`

---

Example Generators
==================

- Visual Studio 15 2017 [arch] = Generates Visual Studio 2017 project files. Optional [arch] can be "Win64" or "ARM".
- Visual Studio 14 2015 [arch] = Generates Visual Studio 2015 project files. Optional [arch] can be "Win64" or "ARM".
- Visual Studio 12 2013 [arch] = Generates Visual Studio 2013 project files. Optional [arch] can be "Win64" or "ARM".
- Visual Studio 11 2012 [arch] = Generates Visual Studio 2012 project files. Optional [arch] can be "Win64" or "ARM".
- Visual Studio 10 2010 [arch] = Generates Visual Studio 2010 project files. Optional [arch] can be "Win64" or "IA64".
- Visual Studio  9 2008 [arch] = Generates Visual Studio 2008 project files. Optional [arch] can be "Win64" or "IA64".
- Visual Studio  8 2005 [arch] = Deprecated.  Generates Visual Studio 2005 project files.  Optional [arch] can be "Win64".

> **Note:** if no arch is specified it compiles for x86 aka Win32
> For a full list see "cmake --help"
