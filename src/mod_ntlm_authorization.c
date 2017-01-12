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
 * mod_ntlm_authorization.c
 * Apache 2.4 authorization part for NTLM module
 * -------------------------------------------------------------------------*/

#include "mod_ntlm.h"

/* APLOG_USE_MODULE macro for multi-file modules */
APLOG_USE_MODULE(auth_ntlm);

/* is_member() checks if current user is allowed in the group which is 
   identified by a security identifier (SID) */
int is_member(request_rec *r, HANDLE usertoken, const char *w)
{
	PSID pGroupSid = NULL;
	int sidsize = 0;
	char domain_name[_MAX_PATH];
	int domainlen = _MAX_PATH;
	SID_NAME_USE snu;
	int member = 0;

	/* Get the security identifier (SID) for the group pointed by w */
	LookupAccountName(NULL, w, pGroupSid, &sidsize, domain_name, &domainlen,
			  &snu);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		if (pGroupSid = apr_palloc(r->pool, sidsize)) {
			if (LookupAccountName
			    (NULL, w, pGroupSid, &sidsize, domain_name,
			     &domainlen, &snu)) {
				BOOL IsMember;
				/* Check if the current user is allowed in this SID */
				if (CheckTokenMembership
				    (usertoken, pGroupSid, &IsMember)) {
					if (IsMember) {
						member = 1;
					}
				} else {
					/* Error logs */
					ap_log_rerror(APLOG_MARK,
						      APLOG_NOERRNO |
						      APLOG_ALERT, 0, r,
						      "CheckTokenMembership(): error %d",
						      GetLastError());
				}
			} else {
				ap_log_rerror(APLOG_MARK,
					      APLOG_NOERRNO | APLOG_ALERT, 0, r,
					      "LookupAccountName(2): error %d",
					      GetLastError());
			}
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ALERT,
				      0, r,
				      "An error occured in is_member(): apr_palloc() failed.");
		}
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ALERT, 0, r,
			      "LookupAccountName(1): error %d", GetLastError());
	}

	return member;
}

/* sspi_common_authz_check() does the common authentication for the 3 types discussed before
   1) user authorization
   2) group authorization
   3) valid check authorization 
   */
int sspi_common_authz_check(request_rec *r,
			    const sspi_config_rec *crec,
			    sspi_connection_rec **pscr, authz_status * pas)
{
	int res = 1;

	/* If the switch isn't on issue error log and status to denied */
	if (!crec->sspi_on) {

		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SSPILOGNO(00004)
			      "Access to %s failed, reason: SSPIAuth is off",
			      r->uri);

		*pas = AUTHZ_DENIED;
		res = 0;
	}

	/* If no user was authenticated, deny */
	if (res && !r->user) {

		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SSPILOGNO(00005)
			      "Access to %s failed, reason: No user authenticated",
			      r->uri);

		*pas = AUTHZ_DENIED_NO_USER;
		res = 0;
	}

	/* Retrieve SSPI Connection Record */
	if (res) {
		apr_pool_userdata_get(pscr, sspiModuleInfo.userDataKeyString,
				      r->connection->pool);

		/* Is user authenticated? If not, we don't want to do further checking */
		if (*pscr == 0 || (*pscr)->username != r->user) {

			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				      SSPILOGNO(00006)
				      "Access to %s failed, reason: inconsistent SSPI record",
				      r->uri);

			*pas = AUTHZ_DENIED;
			res = 0;
		}
	}

	return res;
}

/* common_deny_actions() deals with notifying that the authentification has failed */
static void common_deny_actions(request_rec *r, sspi_connection_rec *scr)
{

	/* under the Apache request_rec structure, if main is pointing to null, 
	   it doesnot make sense to continue with the connection. This could mean
	   that the current request is the main request itself   */
	if (r->main == NULL) {
		cleanup_sspi_connection(scr);
	}

	/* error logs */
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, SSPILOGNO(00003)
		      "access to %s failed, reason: user '%s' does not meet "
		      "'require'ments for user to be allowed access",
		      r->uri, r->user);

	/* notification that the authentication has failed */
	note_sspi_auth_failure(r);
}

/* sspi_user_check_authorization(): deals with checking of user authorization */
authz_status sspi_user_check_authorization(request_rec *r,
					   const char *require_args,
					   const void *parsed_require_args)
{
	const sspi_config_rec *crec = get_sspi_config_rec(r);
	char *user = r->user;
	sspi_connection_rec *scr;
	const char *t, *w;
	authz_status as;

	/* Checking if a user was authenticated */
	if (!sspi_common_authz_check(r, crec, &scr, &as)) {
		return as;
	}

	/* There is a valid user so checking user requirements */
	t = require_args;
	while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
		if (!strcmp(user, w)) {
			return AUTHZ_GRANTED;
		}
	}

	/* preparing for try again */
	common_deny_actions(r, scr);

	return AUTHZ_DENIED;
}

/* sspi_group_check_authorization() deals with authorization of group. This comes into picture
   when we ask for credientials DOMAIN\GROUP_NAME.
   The steps are same as that of sspi_user_check_authorization()   */
authz_status sspi_group_check_authorization(request_rec *r,
					    const char *require_args,
					    const void *parsed_require_args)
{
	const sspi_config_rec *crec = get_sspi_config_rec(r);
	char *user = r->user;
	sspi_connection_rec *scr;
	const char *t, *w;
	authz_status as;

	/* Checking if a user was authenticated */
	if (!sspi_common_authz_check(r, crec, &scr, &as)) {
		return as;
	}

	/* There is a valid user so checking user requirements */
	t = require_args;
	while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
		if (is_member(r, scr->usertoken, w)) {
			return AUTHZ_GRANTED;
		}
	}

	/* preparing for try again */
	common_deny_actions(r, scr);

	return AUTHZ_DENIED;
}

/* sspi_valid_check_authorization() deals with the last category ie 
   valid check provider authorization */
authz_status sspi_valid_check_authorization(request_rec *r,
					    const char *require_args,
					    const void *parsed_require_args)
{
	const sspi_config_rec *crec = get_sspi_config_rec(r);
	char *user = r->user;
	sspi_connection_rec *scr;
	authz_status as;

	if (!sspi_common_authz_check(r, crec, &scr, &as)) {
		return as;
	}

	/* Now we know there is a valid user so grant access */

	return AUTHZ_GRANTED;
}
