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

---

#List of available parameters

- `NTLMAuth` => set to 'on' to activate NTLM authentication here
- `NTLMOfferNTLM` => set to 'off' to allow access control to be passed along to lower modules if the UserID is not known to this module
- `NTLMAuthoritative` => set to 'off' to allow access control to be passed along to lower modules if the UserID is not known to this module
- `NTLMOfferBasic` => set to 'on' to allow the client to authenticate against NT with 'Basic' authentication instead of using the NTLM protocol
- `NTLMPackage` => set to the name of the package you want to use to authenticate users
- `NTLMPackages` => set to the name of the package you want to use to authenticate users
- `NTLMDomain` => set to the domain you want users authenticated against for cleartext authentication - if not specified, the local machine, then all trusted domains are checked
- `NTLMOmitDomain` => set to 'on' if you want the usernames to have the domain set to 'on' if you want the usernames to have the domain
- `NTLMUsernameCase` => set to 'lower' if you want the username and domain to be lowercase, set to 'upper' if you want the username and domain to be uppercase, if not specified, username and domain case conversion is disabled
- `NTLMBasicPreferred` => set to 'on' if you want basic authentication to be the higher priority
- `NTLMMSIE3Hack` => set to 'on' if you expect MSIE 3 clients to be using this server
- `NTLMPerRequestAuth` => set to 'on' if you want authorization per request instead of per connection
- `NTLMChainAuth` => set to 'on' if you want an alternative authorization module like SVNPathAuthz to work at the same level
- `NTLMNotForced` => Set to on to allow requests pass even when user not really authorized This is needed if same resources can be access with and without NTLM auth

#Configure several groups

If you want to add more then one group then use the following syntax, so the module can process them correctly.

    <RequireAny>
        require sspi-group "DOMAIN\\GROUP2" "DOMAIN\\GROUP1"
    </RequireAny>
