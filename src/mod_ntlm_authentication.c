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
 * mod_ntlm_authentication.c
 * Deals with NTLM authentication stuff
 * -------------------------------------------------------------------------*/

#include "mod_ntlm.h"

/* APLOG_USE_MODULE macro for multi-file modules */
APLOG_USE_MODULE(auth_ntlm);

/* getting the mjaximum token size from the given security package info */
static int get_package_max_token_size(PSecPkgInfo pkgInfo, ULONG numPackages,
				      char *package)
{
	ULONG ctr;

	for (ctr = 0; ctr < numPackages; ctr++) {
		if (!strcmp(package, pkgInfo[ctr].Name)) {
			return pkgInfo[ctr].cbMaxToken;
		}
	}

	return 0;
}

/* obtaining credentials for the secure authentication connection */
static int obtain_credentials(sspi_auth_ctx *ctx)
{
	SECURITY_STATUS ss;
	TimeStamp throwaway;
	sspi_header_rec *auth_id;

#ifdef UNICODE
#define SEC_WINNT_AUTH_IDENTITY_UNICODE 0x2
	ctx->hdr.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
#else
#define SEC_WINNT_AUTH_IDENTITY_ANSI 0x1
	ctx->hdr.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
#endif

	/* setting values based on the basic type authentication and the 
	   secured SSPI based authentication */
	if (ctx->hdr.authtype == typeBasic) {
		auth_id = &ctx->hdr;
		if (auth_id->Domain == NULL && ctx->crec->sspi_domain != NULL) {
			auth_id->Domain = ctx->crec->sspi_domain;
			auth_id->DomainLength =
			    (unsigned long)strlen(ctx->crec->sspi_domain);
		}
	} else {
		auth_id = NULL;
	}

	/* if credentials cant be acquired for SSPI authentication then return error */
	if (!
	    (ctx->scr->client_credentials.dwLower
	     || ctx->scr->client_credentials.dwUpper)) {
		if ((ss =
		     sspiModuleInfo.functable->AcquireCredentialsHandle(NULL,
									DEFAULT_SSPI_PACKAGE,
									SECPKG_CRED_OUTBOUND,
									NULL,
									auth_id,
									NULL,
									NULL,
									&ctx->
									scr->
									client_credentials,
									&throwaway)
		    ) != SEC_E_OK) {
			if (ss == SEC_E_SECPKG_NOT_FOUND) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR,
					      APR_FROM_OS_ERROR(GetLastError()),
					      ctx->r,
					      "access to %s failed, reason: unable to acquire credentials "
					      "handle", ctx->r->uri,
					      ctx->scr->package);
			}
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	/* if credentials cant be acquired for SSPI authentication then return error */
	if (!
	    (ctx->scr->server_credentials.dwLower
	     || ctx->scr->server_credentials.dwUpper)) {
		if ((ss =
		     sspiModuleInfo.functable->AcquireCredentialsHandle(NULL,
									DEFAULT_SSPI_PACKAGE,
									SECPKG_CRED_INBOUND,
									NULL,
									NULL,
									NULL,
									NULL,
									&ctx->
									scr->
									server_credentials,
									&throwaway)
		    ) != SEC_E_OK) {
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	ctx->scr->have_credentials = TRUE;

	return OK;
}

/* clean up of the sspi connection */
apr_status_t cleanup_sspi_connection(void *param)
{
	sspi_connection_rec *scr = (sspi_connection_rec *) param;

	if (scr != NULL) {
		if (scr->client_credentials.dwLower
		    || scr->client_credentials.dwUpper) {
			sspiModuleInfo.functable->FreeCredentialHandle(&scr->
								       client_credentials);
			scr->client_credentials.dwLower = 0;
			scr->client_credentials.dwUpper = 0;
		}

		if (scr->server_credentials.dwLower
		    || scr->server_credentials.dwUpper) {
			sspiModuleInfo.functable->FreeCredentialHandle(&scr->
								       server_credentials);
			scr->server_credentials.dwLower = 0;
			scr->server_credentials.dwUpper = 0;
		}

		if (scr->client_context.dwLower || scr->client_context.dwUpper) {
			sspiModuleInfo.functable->DeleteSecurityContext(&scr->
									client_context);
			scr->client_context.dwLower = 0;
			scr->client_context.dwUpper = 0;
		}

		if (scr->server_context.dwLower || scr->server_context.dwUpper) {
			sspiModuleInfo.functable->DeleteSecurityContext(&scr->
									server_context);
			scr->server_context.dwLower = 0;
			scr->server_context.dwUpper = 0;
		}

		scr->have_credentials = FALSE;

		if (scr->usertoken) {
			CloseHandle(scr->usertoken);
			scr->usertoken = NULL;
			/* if the connection is not closed these memory are still valid thereby eating up memory
			   and when too many connections are open, then this could lead to DOS issues */
			scr->username = NULL;
			scr->groups = NULL;
		}
	}

	return APR_SUCCESS;
}

/* getting the username from the context handle */
static char *get_username_from_context(apr_pool_t *p,
				       SecurityFunctionTable *functable,
				       CtxtHandle *context)
{
	SecPkgContext_Names names;
	SECURITY_STATUS ss;
	char *retval = NULL;

	/* QueryContextAttributes: Enables a transport application to query a security package 
	   for certain attributes of a security context. */
	if ((ss = functable->QueryContextAttributes(context,
						    SECPKG_ATTR_NAMES, &names)
	    ) == SEC_E_OK) {
		retval = apr_pstrdup(p, names.sUserName);
		functable->FreeContextBuffer(names.sUserName);
	}

	return retval;
}

/* logging of the failures in Apache error log files */
static void log_sspi_auth_failure(request_rec *r, sspi_header_rec *hdr,
				  apr_status_t errcode, char *reason)
{
	if (hdr->User && hdr->Domain) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errcode, r,
			      "user %s\\%s: authentication failure for \"%s\"%s",
			      hdr->Domain, hdr->User, r->uri, reason);
	} else if (hdr->User) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errcode, r,
			      "user %s: authentication failure for \"%s\"%s",
			      hdr->User, r->uri, reason);
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errcode, r,
			      "authentication failure for \"%s\": user unknown%s",
			      r->uri, reason);
	}
}

/* wrapper for function log_sspi_auth_failure() to wrap different denial/invalid conditions */
static void log_sspi_logon_denied(request_rec *r, sspi_header_rec *hdr,
				  apr_status_t errcode)
{
	log_sspi_auth_failure(r, hdr, errcode, "");
}

/* wrapper for function log_sspi_auth_failure() to wrap different denial/invalid conditions */
static void log_sspi_invalid_token(request_rec *r, sspi_header_rec *hdr,
				   apr_status_t errcode)
{
	log_sspi_auth_failure(r, hdr, errcode,
			      ", reason: cannot generate context");
}

/* getting the client context from the input credentials */
static SECURITY_STATUS gen_client_context(SecurityFunctionTable *functable,
					  CredHandle *credentials,
					  CtxtHandle *context,
					  TimeStamp *ctxtexpiry, BYTE *in,
					  DWORD *inlen, BYTE *out,
					  DWORD *outlen, LPSTR package)
{
	SecBuffer inbuf, outbuf;
	SecBufferDesc inbufdesc, outbufdesc;
	SECURITY_STATUS ss;
	ULONG ContextAttributes;
	BOOL havecontext = (context->dwLower || context->dwUpper);

	outbuf.cbBuffer = *outlen;
	outbuf.BufferType = SECBUFFER_TOKEN;
	outbuf.pvBuffer = out;
	outbufdesc.ulVersion = SECBUFFER_VERSION;
	outbufdesc.cBuffers = 1;
	outbufdesc.pBuffers = &outbuf;

	if (in) {
		inbuf.cbBuffer = *inlen;
		inbuf.BufferType = SECBUFFER_TOKEN;
		inbuf.pvBuffer = in;
		inbufdesc.ulVersion = SECBUFFER_VERSION;
		inbufdesc.cBuffers = 1;
		inbufdesc.pBuffers = &inbuf;
	}

	/* InitializeSecurityContext function initiates the client side, 
	   outbound security context from a credential handle */
	ss = functable->InitializeSecurityContext(credentials,
						  havecontext ? context : NULL,
						  package,
						  ISC_REQ_DELEGATE,
						  0,
						  SECURITY_NATIVE_DREP,
						  in ? &inbufdesc : NULL,
						  0,
						  context,
						  &outbufdesc,
						  &ContextAttributes,
						  ctxtexpiry);

	/* these are the different stages in the authentication proc */
	if (ss == SEC_I_COMPLETE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {
		functable->CompleteAuthToken(context, &outbufdesc);
	}

	*outlen = outbuf.cbBuffer;

	return ss;
}

/* helps to generate the server context for the SSPI authentication */
static SECURITY_STATUS gen_server_context(SecurityFunctionTable *functable,
					  CredHandle *credentials,
					  CtxtHandle *context,
					  TimeStamp *ctxtexpiry, BYTE *in,
					  DWORD *inlen, BYTE *out,
					  DWORD *outlen)
{
	SecBuffer inbuf, outbuf;
	SecBufferDesc inbufdesc, outbufdesc;
	SECURITY_STATUS ss;
	ULONG ContextAttributes;
	BOOL havecontext = (context->dwLower || context->dwUpper);

	outbuf.cbBuffer = *outlen;
	outbuf.BufferType = SECBUFFER_TOKEN;
	outbuf.pvBuffer = out;
	outbufdesc.ulVersion = SECBUFFER_VERSION;
	outbufdesc.cBuffers = 1;
	outbufdesc.pBuffers = &outbuf;

	inbuf.cbBuffer = *inlen;
	inbuf.BufferType = SECBUFFER_TOKEN;
	inbuf.pvBuffer = in;
	inbufdesc.ulVersion = SECBUFFER_VERSION;
	inbufdesc.cBuffers = 1;
	inbufdesc.pBuffers = &inbuf;

	/* AcceptSecurityContext function enables the server component 
	   of a transport application to establish a security context between 
	   the server and a remote client */
	ss = functable->AcceptSecurityContext(credentials,
					      havecontext ? context : NULL,
					      &inbufdesc,
					      ASC_REQ_DELEGATE,
					      SECURITY_NATIVE_DREP,
					      context,
					      &outbufdesc,
					      &ContextAttributes, ctxtexpiry);

	if (ss == SEC_I_COMPLETE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {
		functable->CompleteAuthToken(context, &outbufdesc);
	}

	*outlen = outbuf.cbBuffer;

	return ss;
}

/* does the clear text authentication. called when the negotiated authentication
   is of type basic */
static int check_cleartext_auth(sspi_auth_ctx *ctx)
{
	DWORD cbOut, cbIn, maxTokenSize;
	BYTE *clientbuf, *serverbuf;
	SECURITY_STATUS ss;

	/* follows the same way authnticate SSPI user */
	maxTokenSize =
	    get_package_max_token_size(sspiModuleInfo.pkgInfo,
				       sspiModuleInfo.numPackages,
				       ctx->scr->package);
	serverbuf = apr_palloc(ctx->r->pool, maxTokenSize);
	clientbuf = NULL;
	cbOut = 0;

	do {
		cbIn = cbOut;
		cbOut = maxTokenSize;

		ss = gen_client_context(sspiModuleInfo.functable,
					&ctx->scr->client_credentials,
					&ctx->scr->client_context,
					&ctx->scr->client_ctxtexpiry, clientbuf,
					&cbIn, serverbuf, &cbOut,
					ctx->scr->package);

		/* these 3 conditions are ok */
		if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED
		    || ss == SEC_I_COMPLETE_AND_CONTINUE) {
			if (clientbuf == NULL) {
				clientbuf =
				    apr_palloc(ctx->r->pool, maxTokenSize);
			}

			cbIn = cbOut;
			cbOut = maxTokenSize;

			ss = gen_server_context(sspiModuleInfo.functable,
						&ctx->scr->server_credentials,
						&ctx->scr->server_context,
						&ctx->scr->server_ctxtexpiry,
						serverbuf, &cbIn, clientbuf,
						&cbOut);
		}
	} while (ss == SEC_I_CONTINUE_NEEDED
		 || ss == SEC_I_COMPLETE_AND_CONTINUE);

	switch (ss) {
	case SEC_E_OK:
		return OK;

	case SEC_E_INVALID_HANDLE:
	case SEC_E_INTERNAL_ERROR:
	case SEC_E_NO_AUTHENTICATING_AUTHORITY:
	case SEC_E_INSUFFICIENT_MEMORY:
		ap_log_rerror(APLOG_MARK, APLOG_ERR,
			      APR_FROM_OS_ERROR(GetLastError()), ctx->r,
			      "access to %s failed, reason: cannot generate context",
			      ctx->r->uri);
		return HTTP_INTERNAL_SERVER_ERROR;

	case SEC_E_INVALID_TOKEN:
	case SEC_E_LOGON_DENIED:
	default:
		log_sspi_logon_denied(ctx->r, &ctx->hdr,
				      APR_FROM_OS_ERROR(GetLastError()));
		note_sspi_auth_failure(ctx->r);
		cleanup_sspi_connection(ctx->scr);
		return HTTP_UNAUTHORIZED;
	}
}

/* construct username from the HTTP header */
static void construct_username(sspi_auth_ctx *ctx)
{
	/* removing the domain part from the username */
	if (ctx->crec->sspi_omitdomain) {
		char *s = strchr(ctx->scr->username, '\\');

		if (s)
			ctx->scr->username = s + 1;
	}

	if (ctx->crec->sspi_usernamecase == NULL) {
	} else if (!lstrcmpi(ctx->crec->sspi_usernamecase, "Lower")) {
		_strlwr_s(ctx->scr->username, strlen(ctx->scr->username) + 1);
	} else if (!lstrcmpi(ctx->crec->sspi_usernamecase, "Upper")) {
		_strupr_s(ctx->scr->username, strlen(ctx->scr->username) + 1);
	};
}

/* setting up/initalizing the connection details */
static int set_connection_details(sspi_auth_ctx *ctx)
{
	SECURITY_STATUS ss;

	if (ctx->scr->username == NULL) {
		ctx->scr->username =
		    get_username_from_context(ctx->r->connection->pool,
					      sspiModuleInfo.functable,
					      &ctx->scr->server_context);
	}

	if (ctx->scr->username == NULL)
		return HTTP_INTERNAL_SERVER_ERROR;
	else
		construct_username(ctx);

	if (ctx->r->user == NULL) {
		ctx->r->user = ctx->scr->username;
		ctx->r->ap_auth_type = ctx->scr->package;
	}

	if (ctx->scr->usertoken == NULL) {
		if ((ss =
		     sspiModuleInfo.functable->ImpersonateSecurityContext(&ctx->
									  scr->
									  server_context))
		    != SEC_E_OK) {
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (!OpenThreadToken
		    (GetCurrentThread(), TOKEN_QUERY_SOURCE | TOKEN_READ, TRUE,
		     &ctx->scr->usertoken)) {
			sspiModuleInfo.functable->RevertSecurityContext(&ctx->
									scr->
									server_context);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if ((ss =
		     sspiModuleInfo.functable->RevertSecurityContext(&ctx->scr->
								     server_context))
		    != SEC_E_OK) {
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	return OK;
}

/**
 * Tell whether Internet Explorer is asking for re-authentication before
 * sending POST data.
 *
 * This behavior is IE specific and will cause a bug with the following
 * conditions:
 *		* method is POST
 *		* Context-Length is 0
 *		* an SSPI connection record already exists for this connection
 *
 * Normally, this SSPI module will NOT treat this as a request for
 * re-authentication but as a POST request with no body (thus "dropping" the
 * contents of the POST, as seen in this bug:
 * http://sourceforge.net/tracker/index.php?func=detail&aid=1499289&group_id=162518&atid=824098
 *
 * Thanks to 'nobody' on 2007-02-01 for the details on why this occurs.
 *
 * The previous work-around was to force this module to reauthenticate
 * every request, which causes a lot of extra 401 errors and traffic to
 * your domain controller.
 *
 * Instead, we can now check for IE's behaviour and reauthenticate only when
 * needed.
 *
 * @param ctx The SSPI Authentication context of the current request.
 */
static int ie_post_needs_reauth(const sspi_auth_ctx *ctx)
{

	const char *contentLen =
	    apr_table_get(ctx->r->headers_in, "Content-Length");

	if (lstrcmpi(ctx->r->method, "POST") == 0 && contentLen != NULL &&
	    lstrcmpi(contentLen, "0") == 0 &&
	    ctx->scr != NULL && ctx->scr->username != NULL) {
		return 1;
	} else {
		return 0;
	}
}

/*
 * IE sends POST requests without body if it insists on still using auth.
 * Use NTLMNotForced flag to enable scenarios where same pages can be accessed with and without NTLM auth
*@param ctx The SSPI Authentication context of the current request.
*/
static int ie_post_empty(const sspi_auth_ctx *ctx)
{

	const char *contentLen =
	    apr_table_get(ctx->r->headers_in, "Content-Length");

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->r->server,
		     "SSPI: Testing for IE bug, request %s %s", ctx->r->method,
		     contentLen);

	if (lstrcmpi(ctx->r->method, "POST") == 0 && contentLen != NULL &&
	    lstrcmpi(contentLen, "0") == 0) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->r->server,
			     "SSPI: Found empty POST request");
		return 1;
	}
	return 0;
}

/* Security context is negotiated between the client and server ie here between the 
   browser and the Apache server. */
static int accept_security_context(sspi_auth_ctx *ctx)
{
	SECURITY_STATUS ss;
	sspi_header_rec hdrout;

	hdrout.PasswordLength =
	    get_package_max_token_size(sspiModuleInfo.pkgInfo,
				       sspiModuleInfo.numPackages,
				       ctx->scr->package);
	if (!
	    (hdrout.Password =
	     apr_palloc(ctx->r->pool, hdrout.PasswordLength))) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ss = gen_server_context(sspiModuleInfo.functable,
				&ctx->scr->server_credentials,
				&ctx->scr->server_context,
				&ctx->scr->server_ctxtexpiry, ctx->hdr.Password,
				&ctx->hdr.PasswordLength, hdrout.Password,
				&hdrout.PasswordLength);

	switch (ss) {
	case SEC_E_OK:
		return OK;

	case SEC_I_COMPLETE_NEEDED:
	case SEC_I_CONTINUE_NEEDED:
	case SEC_I_COMPLETE_AND_CONTINUE:	/* already completed if 'complete and continue' */
		note_sspi_auth_challenge(ctx,
					 uuencode_binary(ctx->r->pool,
							 hdrout.Password,
							 hdrout.
							 PasswordLength));
		return HTTP_UNAUTHORIZED;

	case SEC_E_INVALID_TOKEN:
		log_sspi_invalid_token(ctx->r, &ctx->hdr,
				       APR_FROM_OS_ERROR(GetLastError()));
		ctx->scr->sspi_failing = 1;
		ctx->scr->package = 0;
		note_sspi_auth_failure(ctx->r);
		cleanup_sspi_connection(ctx->scr);
		return HTTP_UNAUTHORIZED;

	case SEC_E_LOGON_DENIED:
		log_sspi_logon_denied(ctx->r, &ctx->hdr,
				      APR_FROM_OS_ERROR(GetLastError()));
		ctx->scr->sspi_failing++;
		ctx->scr->package = 0;
		note_sspi_auth_failure(ctx->r);
		cleanup_sspi_connection(ctx->scr);
		return HTTP_UNAUTHORIZED;

	case SEC_E_INVALID_HANDLE:
	case SEC_E_INTERNAL_ERROR:
	case SEC_E_NO_AUTHENTICATING_AUTHORITY:
	case SEC_E_INSUFFICIENT_MEMORY:
		ap_log_rerror(APLOG_MARK, APLOG_ERR,
			      APR_FROM_OS_ERROR(GetLastError()), ctx->r,
			      "access to %s failed, reason: cannot generate server context",
			      ctx->r->uri);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return HTTP_INTERNAL_SERVER_ERROR;
}

/* similar to authenticate a basic user, here the authentication is done for the user
   who opted for a secure SSPI authentication */
int authenticate_sspi_user(request_rec *r)
{
	sspi_auth_ctx ctx;
	const char *current_auth;
	int res;

	/* is SSPI authentication supported? */
	current_auth = ap_auth_type(r);
	if (!current_auth || strcasecmp(current_auth, "SSPI")) {
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		      SSPILOGNO(00001) "Entering authenticate_sspi_user()");

#ifdef _DEBUG
	if (sspiModuleInfo.currentlyDebugging == FALSE) {
		sspiModuleInfo.currentlyDebugging = TRUE;
		DebugBreak();
	}
#endif				/* def _DEBUG */

	/* securezeromemory is needed so that the password is no longer present in the memory
	   this is needed otherwise someone else can read the decrypted password */
	SecureZeroMemory(&ctx, sizeof(ctx));

	ctx.r = r;
	ctx.crec = get_sspi_config_rec(r);

	if (!ctx.crec->sspi_on) {

		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r,
			      SSPILOGNO(00007)
			      "access to %s declined, reason: SSPIAuth is off",
			      r->uri);

		return DECLINED;
	}

	/* checking all the different conditons */
	if (sspiModuleInfo.supportsSSPI == FALSE) {
		if (ctx.crec->sspi_authoritative) {

			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0,
				      r, SSPILOGNO(00002)
				      "access to %s failed, reason: SSPI support is not available",
				      r->uri);

			return HTTP_INTERNAL_SERVER_ERROR;
		} else {

			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0,
				      r, SSPILOGNO(00008)
				      "access to %s declined, reason: SSPIAuth support is not available",
				      r->uri);

			return DECLINED;
		}
	}

	/* checking all the different conditons */
	if (ctx.crec->sspi_package_basic == NULL) {
		ctx.crec->sspi_package_basic = ctx.crec->sspi_packages;

		if (ctx.crec->sspi_package_basic == NULL) {
			ctx.crec->sspi_package_basic =
			    sspiModuleInfo.defaultPackage;
		}
	}

	if (ctx.crec->sspi_packages == NULL) {
		ctx.crec->sspi_packages = ctx.crec->sspi_package_basic;
	}

	/*
	 * Use Basic authentication, because we have no idea how to modify
	 * the domain on NTLMv2 response. normally, it's not safe, but we
	 * can enable SSL I think, if we enable SSL, even Basic should be
	 * secure enough.
	 */
	if (ctx.crec->sspi_offerbasic && ctx.crec->sspi_basicpreferred)
		ctx.crec->sspi_packages = "Basic";

	apr_pool_userdata_get(&ctx.scr, sspiModuleInfo.userDataKeyString,
			      r->connection->pool);

	if (ctx.scr == NULL) {
		ctx.scr =
		    apr_pcalloc(r->connection->pool,
				sizeof(sspi_connection_rec));
		apr_pool_userdata_setn(ctx.scr,
				       sspiModuleInfo.userDataKeyString,
				       cleanup_sspi_connection,
				       r->connection->pool);
	} else if (ie_post_needs_reauth(&ctx)) {
		// Internet Explorer wants to re authenticate, not POST
		ctx.scr->username = NULL;

		if (ctx.scr->server_context.dwLower ||
		    ctx.scr->server_context.dwUpper) {
			sspiModuleInfo.functable->DeleteSecurityContext(&ctx.
									scr->
									server_context);
			ctx.scr->server_context.dwLower = 0;
			ctx.scr->server_context.dwUpper = 0;

			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
				     "SSPI:	starting IE re authentication");
		}
	}

	if (ctx.scr->username == NULL) {

		if (res = get_sspi_header(&ctx)) {
			if (!ie_post_empty(&ctx) && ctx.crec->sspi_optional) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
					     r->server,
					     "SSPI: Optional auth exercised phase 1");
				ctx.r->user = "NT AUTHORITY\\ANONYMOUS LOGON";
				ctx.r->ap_auth_type = "Basic";
				return OK;
			}
			return res;
		}

		if ((!ctx.scr->have_credentials) &&
		    (res = obtain_credentials(&ctx))) {
			if (!ie_post_empty(&ctx) && ctx.crec->sspi_optional) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
					     r->server,
					     "SSPI: Optional auth exercised phase 2");
				ctx.r->user = "NT AUTHORITY\\ANONYMOUS LOGON";
				ctx.r->ap_auth_type = "Basic";
				return OK;
			}
			return res;
		}

		if (ctx.hdr.authtype == typeSSPI) {

			if (res = accept_security_context(&ctx)) {
				if (!ie_post_empty(&ctx) &&
				    ctx.crec->sspi_optional) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
						     r->server,
						     "SSPI: Optional auth exercised phase 3");
					ctx.r->user =
					    "NT AUTHORITY\\ANONYMOUS LOGON";
					ctx.r->ap_auth_type = "Basic";
					return OK;
				}
				return res;
			}
		} else if (ctx.hdr.authtype == typeBasic) {
			res = check_cleartext_auth(&ctx);
			/* don't forget to clean up open user password */
			SecureZeroMemory(&ctx.hdr, sizeof(ctx.hdr));
			if (res) {
				return res;
			}
		}

		/* we should stick with per-request auth - per connection can cause 
		 * problems with POSTing and would be difficult to code such that different
		 * configs were allowed on the same connection (eg. CGI that referred to 
		 * images in another directory. */
		if (ctx.crec->sspi_per_request_auth) {
			apr_pool_cleanup_kill(r->connection->pool, ctx.scr,
					      cleanup_sspi_connection);
			apr_pool_cleanup_register(r->pool, ctx.scr,
						  cleanup_sspi_connection,
						  apr_pool_cleanup_null);
		}
	}

	if (res = set_connection_details(&ctx)) {
		return res;
	}
	/* logging */
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SSPILOGNO(00009)
		      "Authenticated user: %s", r->user);

	return OK;
}
