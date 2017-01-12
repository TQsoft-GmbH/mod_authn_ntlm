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

#ifndef _MOD_NTLM_VERSION_H_
#define _MOD_NTLM_VERSION_H_

#define MOD_NTLM_MODULE_NAME "mod_authn_ntlm"

#define MOD_NTLM_VERSION_MAJOR 1
#define MOD_NTLM_VERSION_MID 0
#define MOD_NTLM_VERSION_MINOR 7
#define STRINGIFY(n) STRINGIFY_HELPER(n)
#define STRINGIFY_HELPER(n) #n

#define MOD_NTLM_VERSION_STR \
    STRINGIFY(MOD_NTLM_VERSION_MAJOR) "." \
    STRINGIFY(MOD_NTLM_VERSION_MID) "." \
    STRINGIFY(MOD_NTLM_VERSION_MINOR)

#endif				/* ndef _MOD_NTLM_VERSION_H_ */
