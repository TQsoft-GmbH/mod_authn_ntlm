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
 * mod_ntlm_interface.c
 * Deals with interface functions needed for authorization and authentication
 * modules like creating server config, getting user password, 
 * generating base64 for NTLM handshakes etc
 * -------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include "mod_ntlm.h"

/* APLOG_USE_MODULE macro for multi-file modules */
APLOG_USE_MODULE(auth_ntlm);

/* constructor function for initializing and memory allocation for the SSPI
   server context */
void *create_sspi_server_config(apr_pool_t *p, server_rec *s)
{
	sspi_config_rec *crec =
	    (sspi_config_rec *) apr_pcalloc(p, sizeof(sspi_config_rec));

	/* Set the defaults to true */
	crec->sspi_offersspi = TRUE;
	crec->sspi_authoritative = TRUE;

	return crec;
}

/* constructor function for initializing and memory allocation for the SSPI
   dir context which is needed to be specified in an APACHE module */
void *create_sspi_dir_config(apr_pool_t *p, char *d)
{
	sspi_config_rec *crec =
	    (sspi_config_rec *) apr_pcalloc(p, sizeof(sspi_config_rec));

	/* Set the defaults to true */
	crec->sspi_offersspi = TRUE;
	crec->sspi_authoritative = TRUE;

	return crec;
}

/* TODO: this function can be removed */
void *merge_sspi_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
	sspi_config_rec *merged_rec = create_sspi_dir_config(p, 0);
	sspi_config_rec *base_rec = base_conf;
	sspi_config_rec *new_rec = new_conf;

#ifdef _DEBUG
	if (sspiModuleInfo.currentlyDebugging == FALSE) {
		sspiModuleInfo.currentlyDebugging = TRUE;
		DebugBreak();
	}
#endif				/* def _DEBUG */

	if (base_rec->sspi_on && !new_rec->sspi_on)
		memcpy(merged_rec, base_rec, sizeof(sspi_config_rec));
	else if (!base_rec->sspi_on && new_rec->sspi_on)
		memcpy(merged_rec, new_rec, sizeof(sspi_config_rec));

	return merged_rec;
}

/* this function gets called when the brower has negotiated that
   it can send an encrypted password. The encrypted password is again
   encoded in base64 which needs to be decoded */
static int get_sspi_userpass(sspi_auth_ctx *ctx, const char *auth_line)
{
	int len;

	/* we are decoding the base64 encoded password */
	if (auth_line) {
		ctx->hdr.Password = uudecode_binary(ctx->r->pool,
						    auth_line, &len);
		ctx->hdr.PasswordLength = len;
		ctx->hdr.authtype = typeSSPI;
	} else {
		if (ctx->crec->sspi_authoritative) {
			return HTTP_BAD_REQUEST;
		} else {
			return DECLINED;
		}
	}
	/* if password is empty decline the login request */
	if (!ctx->hdr.PasswordLength || !ctx->hdr.Password) {
		if (ctx->crec->sspi_authoritative) {
			return HTTP_BAD_REQUEST;
		} else {
			return DECLINED;
		}
	}

	return OK;
}

/* this function gets called when the brower has negotiated that
   it can only do basic authentication ie the password is sent in
   clear text format with base64 encoding */
static int get_basic_userpass(sspi_auth_ctx *ctx, const char *auth_line)
{
	char *ptr, *domainptr;
	int len;

	/* decoding the base64 decoded password */
	if (!(ptr = uudecode_binary(ctx->r->pool, auth_line, &len))) {
		/* if decoding was not successful then issue an authentication
		   failure */
		note_sspi_auth_failure(ctx->r);
		if (ctx->crec->sspi_authoritative) {
			return HTTP_BAD_REQUEST;
		} else {
			return DECLINED;
		}
	}

	/* ap_getword_nulls will preserve empty entries */
	ctx->hdr.User = ap_getword_nulls(ctx->r->pool, &ptr, ':');
	if (ctx->hdr.User) {
		ctx->hdr.UserLength = (unsigned long)strlen(ctx->hdr.User);
	} else {
		/* send failure as user is null */
		note_sspi_auth_failure(ctx->r);
		if (ctx->crec->sspi_authoritative) {
			return HTTP_BAD_REQUEST;
		} else {
			return DECLINED;
		}
	}

	/* trying to split the domain name from the user name */
	for (domainptr = ctx->hdr.User;
	     (unsigned long)(domainptr - ctx->hdr.User) < ctx->hdr.UserLength;
	     domainptr++) {

		/* people can enter username in both ways like DOMAIN\USERNAME or DOMAIN/USERNAME
		   so we have to take care of both slashes */
		if (*domainptr == '\\' || *domainptr == '/') {
			/* when we get a slash we put a null character so that
			   the domainptr will have the domain name as the string */
			*domainptr = '\0';
			ctx->hdr.Domain = ctx->hdr.User;
			ctx->hdr.DomainLength =
			    (unsigned long)strlen(ctx->hdr.Domain);
			ctx->hdr.User = domainptr + 1;
			ctx->hdr.UserLength =
			    (unsigned long)strlen(ctx->hdr.User);
			break;
		} else if (*domainptr == '@') {
			*domainptr = '\0';
			ctx->hdr.Domain = domainptr + 1;
			ctx->hdr.DomainLength =
			    (unsigned long)strlen(ctx->hdr.Domain);
			ctx->hdr.UserLength =
			    (unsigned long)strlen(ctx->hdr.User);
			break;
		}
	}

	ctx->hdr.Password = ptr;
	if (ctx->hdr.Password) {
		ctx->hdr.PasswordLength =
		    (unsigned long)strlen(ctx->hdr.Password);
	} else {
		/* if no password send authentication failure */
		note_sspi_auth_failure(ctx->r);
		if (ctx->crec->sspi_authoritative) {
			return HTTP_BAD_REQUEST;
		} else {
			return DECLINED;
		}
	}
	/* since this is cleartext authetication set the auth type to basic */
	ctx->hdr.authtype = typeBasic;

	return OK;
}


/* needed for the authentication part in a HTTP header */
const char *get_authorization_header_name(request_rec *r)
{
	return (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authorization"
	    : "Authorization";
}

/* needed for the authentication part in a HTTP header */
const char *get_authenticate_header_name(request_rec *r)
{
	return (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate"
	    : "WWW-Authenticate";
}

/* checking if the package is valid */
static int check_package_valid(sspi_auth_ctx *ctx, char *scheme)
{
	if (0 != ctx->scr->package && 0 != lstrcmpi(scheme, ctx->scr->package))
		return HTTP_INTERNAL_SERVER_ERROR;

	if (0 == ctx->crec->sspi_packages)
		return HTTP_INTERNAL_SERVER_ERROR;
	else {
		const char *list = ctx->crec->sspi_packages;
		char *w;
		while (list && list[0]) {
			w = ap_getword_white(ctx->r->pool, &list);
			if (w && w[0] && lstrcmpi(w, scheme) == 0)
				return OK;
		}
	}

	return HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * The difference between sspi_set_domain() and sspi_set_default_domain() is:
 * sspi_set_domain() will force to set the Domain if you NTLMDomain on
 * httpd.conf, and don't care users specified the domain already or not.
 *
 * Instead, sspi_set_default_domain() will check use specified the domain or
 * not, only add set default domain if you have config NTLMDefaultDomain on
 * httpd.conf, and users are not specified it on Basic request.
 */
static void sspi_set_domain(sspi_auth_ctx *ctx)
{
	if (!ctx->crec->sspi_domain ||
	    !ctx->crec->sspi_domain[0])
		return;

	ctx->hdr.Domain = ctx->crec->sspi_domain;
	ctx->hdr.DomainLength = strlen(ctx->crec->sspi_domain);
}

static void sspi_set_default_domain(sspi_auth_ctx *ctx)
{
	if (!ctx->crec->sspi_default_domain ||
	    !ctx->crec->sspi_default_domain[0])
		return;

	/* Ignore it, if it has been set. */
	if (ctx->hdr.Domain && ctx->hdr.Domain[0])
		return;

	ctx->hdr.Domain = ctx->crec->sspi_default_domain;
	ctx->hdr.DomainLength = strlen(ctx->crec->sspi_default_domain);
}

/* working up with SSPI header */
int get_sspi_header(sspi_auth_ctx *ctx)
{
	int ret;
	char *scheme;
	/* Finding if its Proxy-Authorization or WWW authenticate one */
	const char *auth_line = apr_table_get(ctx->r->headers_in,
					      get_authorization_header_name
					      (ctx->r));

	/* If the client didn't supply an Authorization: (or Proxy-Authorization) 
	 * header, we need to reply 401 and supply a WWW-Authenticate
	 * (or Proxy-Authenticate) header indicating acceptable authentication
	 * schemes */
	if (!auth_line) {
		note_sspi_auth_failure(ctx->r);
		return HTTP_UNAUTHORIZED;
	}

	/* Do a quick check of the Authorization: header. If it is 'Basic', and we're
	 * allowed, try a cleartext logon. Else if it isn't the selected package 
	 * and we're authoritative, reply 401 again */
	scheme = ap_getword_white(ctx->r->pool, &auth_line);

	if (ctx->crec->sspi_offerbasic &&
	    ctx->crec->sspi_basicpreferred &&
	    0 == lstrcmpi(scheme, "Basic")) {
		ctx->scr->package = ctx->crec->sspi_package_basic;
		ret = get_basic_userpass(ctx, auth_line);
		sspi_set_domain(ctx);
		sspi_set_default_domain(ctx);
		return ret;
	} else if (ctx->crec->sspi_offersspi &&
		   0 == check_package_valid(ctx, scheme)) {
		if (0 == ctx->scr->package)
			ctx->scr->package =
			    apr_pstrdup(ctx->r->connection->pool, scheme);
		return get_sspi_userpass(ctx, auth_line);
	}

	/* check if its authoritative */
	if (ctx->crec->sspi_authoritative) {
		/* error logs */
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, ctx->r,
			      "client used wrong authentication scheme: %s for %s (needed %s)",
			      ctx->scr->package, ctx->r->uri,
			      ctx->crec->sspi_packages);
		note_sspi_auth_failure(ctx->r);
		return HTTP_UNAUTHORIZED;
	} else {
		return DECLINED;
	}

	return HTTP_INTERNAL_SERVER_ERROR;
}

/* handles when the authentication fails */
void note_sspi_auth_failure(request_rec *r)
{
	const char *auth_hdr = get_authenticate_header_name(r);
	sspi_config_rec *crec = get_sspi_config_rec(r);

	char *basicline = 0;

	/* remove the values from the hash table */
	apr_table_unset(r->err_headers_out, auth_hdr);

	/* if basic authentication is offered */
	if (crec->sspi_offerbasic) {
		basicline =
		    apr_psprintf(r->pool, "Basic realm=\"%s\"",
				 ap_auth_name(r));
	}

	/* if secured authentication is negotiated */
	if (crec->sspi_offersspi) {
		sspi_connection_rec *scr = 0;
		/* getting user data */
		apr_pool_userdata_get(&scr, sspiModuleInfo.userDataKeyString,
				      r->connection->pool);

		if (scr == 0 || scr->sspi_failing <= MAX_RETRYS) {
			char *w;
			const char *package_list = crec->sspi_packages;

			/* populating the HTTP headers that needs to be send out */
			if (crec->sspi_offerbasic && crec->sspi_basicpreferred) {
				apr_table_addn(r->err_headers_out, auth_hdr,
					       basicline);
				basicline = 0;
			}

			if (package_list)
				while (*package_list) {
					/* Copies everything from package_list to a new string */
					w = ap_getword_white(r->pool,
							     &package_list);
					if (w[0]) {
						/* add to the hashtable */
						apr_table_addn(r->
							       err_headers_out,
							       auth_hdr, w);
					}
				}
		}
	}

	if (basicline != 0) {
		/* add to the hashtable */
		apr_table_addn(r->err_headers_out, auth_hdr, basicline);
	}
}

/* to generate the authentification challenge key */
void note_sspi_auth_challenge(sspi_auth_ctx *ctx, const char *challenge)
{
	/* to find if Proxy-Authenticate or WWW-Authenticate */
	const char *auth_hdr = get_authenticate_header_name(ctx->r);

	apr_table_setn(ctx->r->err_headers_out, auth_hdr,
		       apr_psprintf(ctx->r->pool, "%s %s", ctx->scr->package,
				    challenge));

	if (ctx->r->connection->keepalives)
		--ctx->r->connection->keepalives;

	/* sending the header with content length to 0 to stop browser from
	   closing down the connection  */
	if ((ctx->crec->sspi_msie3hack)
	    && (ctx->r->proto_num < HTTP_VERSION(1, 1))) {
		apr_table_setn(ctx->r->err_headers_out, "Content-Length", "0");
	}
}

/* does the encoding of the input to base 64 format */
char *uuencode_binary(apr_pool_t *p, const char *data, int len)
{
	int encodelength;
	char *encoded;

	encodelength = apr_base64_encode_len(len);
	encoded = apr_palloc(p, encodelength);

	if (encoded != NULL) {
		if (apr_base64_encode_binary(encoded, data, len) > 0) {
			return encoded;
		}
	}

	return NULL;
}

/* does the decoding of the base64 input */
unsigned char *uudecode_binary(apr_pool_t *p, const char *data,
			       int *decodelength)
{
	char *decoded;

	*decodelength = apr_base64_decode_len(data);
	decoded = apr_palloc(p, *decodelength);

	if (decoded != NULL) {
		*decodelength = apr_base64_decode_binary(decoded, data);
		if (*decodelength > 0) {
			decoded[(*decodelength)] = '\0';
			return decoded;
		}
	}

	return NULL;
}
