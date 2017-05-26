/* ====================================================================
 * This code is copyright 2013 TQsoft GmbH <info@tqsoft.de>
 * Inspired by mod_auth_sspi project from Tim Castello <tjcostel@users.sourceforge.net>
 *
 * It may be freely distributed, as long as the above notices are reproduced.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/* ---------------------------------------------------------------------------
 * mod_ntlm.c
 * Apache 2.4 module code for NTLM.
 * Developed based on the example module for Apache 2.4
 * -------------------------------------------------------------------------*/

#include "mod_ntlm.h"

/* An apache module is identified by httpd with a well 
   defined data structure: AP_MODULE_DECLARE_DATA */
module AP_MODULE_DECLARE_DATA auth_ntlm_module;

sspi_module_rec sspiModuleInfo = { 0, };

/* commands& their bindings that this module understands */
static const command_rec sspi_cmds[] = {
	AP_INIT_FLAG("NTLMAuth", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec, sspi_on), OR_AUTHCFG,
		     "set to 'on' to activate NTLM authentication here"),
	AP_INIT_FLAG("NTLMOfferNTLM", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec, sspi_offersspi),
		     OR_AUTHCFG,
		     "set to 'off' to allow access control to be passed along to "
		     "lower modules if the UserID is not known to this module"),
	AP_INIT_FLAG("NTLMAuthoritative", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec, sspi_authoritative),
		     OR_AUTHCFG,
		     "set to 'off' to allow access control to be passed along to "
		     "lower modules if the UserID is not known to this module"),
	AP_INIT_FLAG("NTLMOfferBasic", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec, sspi_offerbasic),
		     OR_AUTHCFG,
		     "set to 'on' to allow the client to authenticate against NT "
		     "with 'Basic' authentication instead of using the NTLM protocol"),
	AP_INIT_TAKE1("NTLMPackage", ap_set_string_slot,
		      (void *)APR_OFFSETOF(sspi_config_rec, sspi_package_basic),
		      OR_AUTHCFG,
		      "set to the name of the package you want to use to "
		      "authenticate users"),
	AP_INIT_TAKE1("NTLMPackages", ap_set_string_slot,
		      (void *)APR_OFFSETOF(sspi_config_rec, sspi_packages),
		      OR_AUTHCFG,
		      "set to the name of the package you want to use to "
		      "authenticate users"),
	AP_INIT_TAKE1("NTLMDomain", ap_set_string_slot,
		      (void *)APR_OFFSETOF(sspi_config_rec, sspi_domain),
		      OR_AUTHCFG,
		      "set to the domain you want users authenticated against for "
		      "cleartext authentication - if not specified, the local "
		      "machine, then all trusted domains are checked"),
	AP_INIT_TAKE1("NTLMDefaultDomain", ap_set_string_slot,
		      (void *)APR_OFFSETOF(sspi_config_rec,
					   sspi_default_domain), OR_AUTHCFG,
		      "set the default domain you want to user to authenticate with, it "
		      "will try to add default domain in the NTLM SSPI header if there"
		      "is no domain set in NTLM response"),
	AP_INIT_FLAG("NTLMOmitDomain", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec, sspi_omitdomain),
		     OR_AUTHCFG,
		     "set to 'on' if you want the usernames to have the domain "
		     "prefix OMITTED, on = user, off = DOMAIN\\user"),
	AP_INIT_TAKE1("NTLMUsernameCase", ap_set_string_slot,
		      (void *)APR_OFFSETOF(sspi_config_rec, sspi_usernamecase),
		      OR_AUTHCFG,
		      "set to 'lower' if you want the username and domain to be lowercase, "
		      "set to 'upper' if you want the username and domain to be uppercase, "
		      "if not specified, username and domain case conversion is disabled"),
	AP_INIT_FLAG("NTLMBasicPreferred", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec, sspi_basicpreferred),
		     OR_AUTHCFG,
		     "set to 'on' if you want basic authentication to be the "
		     "higher priority"),
	AP_INIT_FLAG("NTLMMSIE3Hack", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec, sspi_msie3hack),
		     OR_AUTHCFG,
		     "set to 'on' if you expect MSIE 3 clients to be using this server"),
	AP_INIT_FLAG("NTLMPerRequestAuth", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec,
					  sspi_per_request_auth), OR_AUTHCFG,
		     "set to 'on' if you want authorization per request instead of per connection"),
	AP_INIT_FLAG("NTLMChainAuth", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec, sspi_chain_auth),
		     OR_AUTHCFG,
		     "set to 'on' if you want an alternative authorization module like SVNPathAuthz to work at the same level"),
	AP_INIT_FLAG("NTLMNotForced", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(sspi_config_rec, sspi_optional),
		     OR_AUTHCFG,
		     "Set to on to allow requests pass even when user not really authorized "
		     "This is needed if same resources can be access with and without NTLM auth"),

	{NULL}
};

/* module cleanup */
static apr_status_t sspi_module_cleanup(void *unused)
{
	UNREFERENCED_PARAMETER(unused);

	/* unloading microsoft's security.dll */
	if (sspiModuleInfo.securityDLL != NULL) {
		if (sspiModuleInfo.functable != NULL) {
			sspiModuleInfo.functable->
			    FreeContextBuffer(sspiModuleInfo.pkgInfo);
		}
		FreeLibrary(sspiModuleInfo.securityDLL);
	}

	return APR_SUCCESS;
}

/* module initialization */
static int init_module(apr_pool_t *pconf, apr_pool_t *ptemp,
		       apr_pool_t *plog, server_rec *s)
{
	GUID userDataKey;
	OLECHAR userDataKeyString[UUID_STRING_LEN];
	LPSTR lpDllName = NULL;
	INIT_SECURITY_INTERFACE pInit;
	SECURITY_STATUS ss = SEC_E_INTERNAL_ERROR;

	if (sspiModuleInfo.lpVersionInformation == NULL) {
		/* finding current OS */
		sspiModuleInfo.lpVersionInformation =
		    apr_pcalloc(pconf, sizeof(OSVERSIONINFO));
		sspiModuleInfo.lpVersionInformation->dwOSVersionInfoSize =
		    sizeof(OSVERSIONINFO);
		GetVersionEx(sspiModuleInfo.lpVersionInformation);

		/* initializating the OS support for authentication to true. 
		   This can be reset later. */
		sspiModuleInfo.supportsSSPI = TRUE;
		sspiModuleInfo.defaultPackage = DEFAULT_SSPI_PACKAGE;

		/* Unique ID for connection info storage. */
		CoInitializeEx(NULL,
			       COINIT_MULTITHREADED | COINIT_SPEED_OVER_MEMORY);
		CoCreateGuid(&userDataKey);
		StringFromGUID2(&userDataKey, userDataKeyString,
				UUID_STRING_LEN);
		WideCharToMultiByte(CP_ACP, 0, userDataKeyString, -1,
				    sspiModuleInfo.userDataKeyString,
				    UUID_STRING_LEN, NULL, NULL);
		CoUninitialize();

		/* For older version of Windows security.dll is called secur32.dll */
		if (sspiModuleInfo.lpVersionInformation->dwPlatformId ==
		    VER_PLATFORM_WIN32_NT) {
			lpDllName = WINNT_SECURITY_DLL;
		} else {
			lpDllName = WIN9X_SECURITY_DLL;
		}

		/* Loading the security dll */
		__try {
			/* checking id the security dll can be loaded */
			if (!
			    (sspiModuleInfo.securityDLL =
			     LoadLibrary(lpDllName))) {
				ap_log_error(APLOG_MARK, APLOG_CRIT,
					     APR_FROM_OS_ERROR(GetLastError()),
					     s,
					     "%s: could not load security support provider DLL",
					     MOD_NTLM_MODULE_NAME);
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			/* checking dll's entry point */
			if (!
			    (pInit =
			     (INIT_SECURITY_INTERFACE)
			     GetProcAddress(sspiModuleInfo.securityDLL,
					    SECURITY_ENTRYPOINT))) {
				ap_log_error(APLOG_MARK, APLOG_CRIT,
					     APR_FROM_OS_ERROR(GetLastError()),
					     s,
					     "%s: could not locate security support provider entrypoint in DLL",
					     MOD_NTLM_MODULE_NAME);
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			if (!(sspiModuleInfo.functable = pInit())) {
				ap_log_error(APLOG_MARK, APLOG_CRIT,
					     APR_FROM_OS_ERROR(GetLastError()),
					     s,
					     "%s: could not get security support provider function table from initialisation function",
					     MOD_NTLM_MODULE_NAME);
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			ss = sspiModuleInfo.functable->
			    EnumerateSecurityPackages(&sspiModuleInfo.
						      numPackages,
						      &sspiModuleInfo.pkgInfo);
		}
		__finally {
			if (ss != SEC_E_OK) {
				sspi_module_cleanup(NULL);
				sspiModuleInfo.supportsSSPI = FALSE;
			}
		}
	}

	apr_pool_cleanup_register(pconf, NULL, sspi_module_cleanup,
				  sspi_module_cleanup);

	ap_add_version_component(pconf, apr_psprintf(pconf, "%s/%d.%d.%d",
						     MOD_NTLM_MODULE_NAME,
						     MOD_NTLM_VERSION_MAJOR,
						     MOD_NTLM_VERSION_MID,
						     MOD_NTLM_VERSION_MINOR));

	return OK;
}

/* binding the function that does user authentication */
static const authz_provider authz_sspi_user_provider = {
	&sspi_user_check_authorization,
	NULL,
};

/* binding the function that does group authentication */
static const authz_provider authz_sspi_group_provider = {
	&sspi_group_check_authorization,
	NULL,
};

/* binding the function that does the last step of valid check authentication */
static const authz_provider authz_sspi_valid_provider = {
	&sspi_valid_check_authorization,
	NULL,
};

/* API hooks as specified in Apache 2.4 module development */
static void register_hooks(apr_pool_t *p)
{
	/* Register authorization provider */
	ap_hook_check_authn(authenticate_sspi_user, NULL, NULL, APR_HOOK_MIDDLE,
			    AP_AUTH_INTERNAL_PER_CONF);

	/* Register authorization user provider */
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "sspi-user",
				  AUTHZ_PROVIDER_VERSION,
				  &authz_sspi_user_provider,
				  AP_AUTH_INTERNAL_PER_CONF);

	/* Register authorization group provider */
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "sspi-group",
				  AUTHZ_PROVIDER_VERSION,
				  &authz_sspi_group_provider,
				  AP_AUTH_INTERNAL_PER_CONF);

	/* Register authorization valid check provider */
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-sspi-user",
				  AUTHZ_PROVIDER_VERSION,
				  &authz_sspi_valid_provider,
				  AP_AUTH_INTERNAL_PER_CONF);

	ap_hook_post_config(init_module, NULL, NULL, APR_HOOK_FIRST);
}

/* AP_DECLARE_MODULE macro to declare modules */
AP_DECLARE_MODULE(auth_ntlm) = {
	STANDARD20_MODULE_STUFF, create_sspi_dir_config,	/* dir config creater */
	    NULL,		/* dir merger --- default is to override */
	    NULL,		/* server config */
	    NULL,		/* merge server config */
	    sspi_cmds,		/* command apr_table_t */
	    register_hooks	/* register hooks */
};

sspi_config_rec *get_sspi_config_rec(request_rec *r)
{
	return (sspi_config_rec *)
	    ap_get_module_config(r->per_dir_config, &auth_ntlm_module);
}
