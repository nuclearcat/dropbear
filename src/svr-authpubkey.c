/*
 * Dropbear - a SSH2 server
 *
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */
/*
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * 	Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * 	Redistribution and use in source and binary forms, with or without
 * 	modification, are permitted provided that the following conditions
 * 	are met:
 * 	1. Redistributions of source code must retain the above copyright
 * 	   notice, this list of conditions and the following disclaimer.
 * 	2. Redistributions in binary form must reproduce the above copyright
 * 	   notice, this list of conditions and the following disclaimer in the
 * 	   documentation and/or other materials provided with the distribution.
 *
 * 	THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * 	IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * 	OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * 	IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * 	INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * 	NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * 	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * 	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * 	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * 	THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This copyright and permission notice applies to the code parsing public keys
 * options string which can also be found in OpenSSH auth2-pubkey.c file
 * (user_key_allowed2). It has been adapted to work with buffers.
 *
 */

/* Process a pubkey auth request */

#include "includes.h"
#include "session.h"
#include "dbutil.h"
#include "buffer.h"
#include "signkey.h"
#include "auth.h"
#include "ssh.h"
#include "packet.h"
#include "algo.h"
#include "runopts.h"
#include "cert.h"

#if DROPBEAR_SVR_PUBKEY_AUTH

#define MIN_AUTHKEYS_LINE 10 /* "ssh-rsa AB" - short but doesn't matter */
#define MAX_AUTHKEYS_LINE 4200 /* max length of a line in authkeys */

static char * authorized_keys_filepath(void);
static int checkpubkey(const char* keyalgo, unsigned int keyalgolen,
		const unsigned char* keyblob, unsigned int keybloblen);
static int checkpubkeyperms(void);
static void send_msg_userauth_pk_ok(const char* sigalgo, unsigned int sigalgolen,
		const unsigned char* keyblob, unsigned int keybloblen);
static int checkfileperm(char * filename);
#if DROPBEAR_CERT_KEYS
static int checkpubkey_cert(const char* keyalgo, unsigned int keyalgolen,
		const unsigned char* keyblob, unsigned int keybloblen);
#endif

/* process a pubkey auth request, sending success or failure message as
 * appropriate */
void svr_auth_pubkey(int valid_user) {

	unsigned char testkey; /* whether we're just checking if a key is usable */
	char* sigalgo = NULL;
	unsigned int sigalgolen;
	const char* keyalgo;
	unsigned int keyalgolen;
	unsigned char* keyblob = NULL;
	unsigned int keybloblen;
	unsigned int sign_payload_length;
	buffer * signbuf = NULL;
	sign_key * key = NULL;
	char* fp = NULL;
	enum signature_type sigtype;
	enum signkey_type keytype;
    int auth_failure = 1;

	TRACE(("enter pubkeyauth"))

	/* 0 indicates user just wants to check if key can be used, 1 is an
	 * actual attempt*/
	testkey = (buf_getbool(ses.payload) == 0);

	sigalgo = buf_getstring(ses.payload, &sigalgolen);
	keybloblen = buf_getint(ses.payload);
	keyblob = buf_getptr(ses.payload, keybloblen);

	if (!valid_user) {
		/* Return failure once we have read the contents of the packet
		required to validate a public key.
		Avoids blind user enumeration though it isn't possible to prevent
		testing for user existence if the public key is known */
		send_msg_userauth_failure(0, 0);
		goto out;
	}

	sigtype = signature_type_from_name(sigalgo, sigalgolen);
	if (sigtype == DROPBEAR_SIGNATURE_NONE) {
		send_msg_userauth_failure(0, 0);
		goto out;
	}

	keytype = signkey_type_from_signature(sigtype);
	keyalgo = signkey_name_from_type(keytype, &keyalgolen);

#if DROPBEAR_PLUGIN
    if (svr_ses.plugin_instance != NULL) {
        char *options_buf;
        if (svr_ses.plugin_instance->checkpubkey(
                    svr_ses.plugin_instance,
                    &ses.plugin_session,
                    keyalgo,
                    keyalgolen,
                    keyblob,
                    keybloblen,
                    ses.authstate.username) == DROPBEAR_SUCCESS) {
            /* Success */
            auth_failure = 0;

            /* Options provided? */
            options_buf = ses.plugin_session->get_options(ses.plugin_session);
            if (options_buf) {
                struct buf temp_buf = {
                    .data = (unsigned char *)options_buf,
                    .len = strlen(options_buf),
                    .pos = 0,
                    .size = 0
                };
                int ret = svr_add_pubkey_options(&temp_buf, 0, "N/A");
                if (ret == DROPBEAR_FAILURE) {
                    /* Fail immediately as the plugin provided wrong options */
                    send_msg_userauth_failure(0, 0);
                    goto out;
                }
            }
        }
    }
#endif
	/* check if the key is valid */
	if (auth_failure) {
	    auth_failure = checkpubkey(keyalgo, keyalgolen, keyblob, keybloblen) == DROPBEAR_FAILURE;
	}

	if (auth_failure) {
		/* MAX_PUBKEY_QUERIES allows a greater limit of pubkey queries
		 * than the standard maxauthtries.
		 * Start counting failures (incrfail) only when it's reaching
		 * the limit.
		 */
		unsigned int free_query_limit = 0;
			MAX(0, (int)svr_opts.maxauthtries - MAX_PUBKEY_QUERIES);
		int incrfail = ses.authstate.serv_pubkey_query_count > free_query_limit;
		send_msg_userauth_failure(0, incrfail);
		ses.authstate.serv_pubkey_query_count++;
		goto out;
	}

	/* let them know that the key is ok to use */
	if (testkey) {
		send_msg_userauth_pk_ok(sigalgo, sigalgolen, keyblob, keybloblen);
		goto out;
	}

	/* now we can actually verify the signature */

	/* get the key */
	key = new_sign_key();
	if (buf_get_pub_key(ses.payload, key, &keytype) == DROPBEAR_FAILURE) {
		send_msg_userauth_failure(0, 1);
		goto out;
	}

#if DROPBEAR_SK_ECDSA || DROPBEAR_SK_ED25519
	key->sk_flags_mask = SSH_SK_USER_PRESENCE_REQD;
#if DROPBEAR_SVR_PUBKEY_OPTIONS_BUILT
	if (ses.authstate.pubkey_options && ses.authstate.pubkey_options->no_touch_required_flag) {
		key->sk_flags_mask &= ~SSH_SK_USER_PRESENCE_REQD;
	}
	if (ses.authstate.pubkey_options && ses.authstate.pubkey_options->verify_required_flag) {
		key->sk_flags_mask |= SSH_SK_USER_VERIFICATION_REQD;
	}
#endif /* DROPBEAR_SVR_PUBKEY_OPTIONS */
#endif

	/* create the data which has been signed - this a string containing
	 * session_id, concatenated with the payload packet up to the signature */
	assert(ses.payload_beginning <= ses.payload->pos);
	sign_payload_length = ses.payload->pos - ses.payload_beginning;
	signbuf = buf_new(ses.payload->pos + 4 + ses.session_id->len);
	buf_putbufstring(signbuf, ses.session_id);

	/* The entire contents of the payload prior. */
	buf_setpos(ses.payload, ses.payload_beginning);
	buf_putbytes(signbuf,
		buf_getptr(ses.payload, sign_payload_length),
		sign_payload_length);
	buf_incrpos(ses.payload, sign_payload_length);

	buf_setpos(signbuf, 0);

	/* ... and finally verify the signature */
	fp = sign_key_fingerprint(keyblob, keybloblen);
	if (buf_verify(ses.payload, key, sigtype, signbuf) == DROPBEAR_SUCCESS) {
		if (svr_opts.multiauthmethod && (ses.authstate.authtypes & ~AUTH_TYPE_PUBKEY)) {
			/* successful pubkey authentication, but extra auth required */
			dropbear_log(LOG_NOTICE,
					"Pubkey auth succeeded for '%s' with %s key %s from %s, extra auth required",
					ses.authstate.pw_name,
					signkey_name_from_type(keytype, NULL), fp,
					svr_ses.addrstring);
			ses.authstate.authtypes &= ~AUTH_TYPE_PUBKEY; /* pubkey auth ok, delete the method flag */
			send_msg_userauth_failure(1, 0); /* Send partial success */
		} else {
			/* successful authentication */
			dropbear_log(LOG_NOTICE,
					"Pubkey auth succeeded for '%s' with %s key %s from %s",
					ses.authstate.pw_name,
					signkey_name_from_type(keytype, NULL), fp,
					svr_ses.addrstring);
			send_msg_userauth_success();
		}
#if DROPBEAR_PLUGIN
		if ((ses.plugin_session != NULL) && (svr_ses.plugin_instance->auth_success != NULL)) {
		    /* Was authenticated through the external plugin. tell plugin that signature verification was ok */
		    svr_ses.plugin_instance->auth_success(ses.plugin_session);
		}
#endif
	} else {
		dropbear_log(LOG_WARNING,
				"Pubkey auth bad signature for '%s' with key %s from %s",
				ses.authstate.pw_name, fp, svr_ses.addrstring);
		send_msg_userauth_failure(0, 1);
	}
	m_free(fp);

out:
	/* cleanup stuff */
	if (signbuf) {
		buf_free(signbuf);
	}
	if (sigalgo) {
		m_free(sigalgo);
	}
	if (key) {
		sign_key_free(key);
		key = NULL;
	}
	/* Retain pubkey options only if auth succeeded */
	if (!ses.authstate.authdone) {
		svr_pubkey_options_cleanup();
	}
	TRACE(("leave pubkeyauth"))
}

/* Reply that the key is valid for auth, this is sent when the user sends
 * a straight copy of their pubkey to test, to avoid having to perform
 * expensive signing operations with a worthless key */
static void send_msg_userauth_pk_ok(const char* sigalgo, unsigned int sigalgolen,
		const unsigned char* keyblob, unsigned int keybloblen) {

	TRACE(("enter send_msg_userauth_pk_ok"))
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_PK_OK);
	buf_putstring(ses.writepayload, sigalgo, sigalgolen);
	buf_putstring(ses.writepayload, (const char*)keyblob, keybloblen);

	encrypt_packet();
	TRACE(("leave send_msg_userauth_pk_ok"))

}

/* Content for SSH_PUBKEYINFO is optionally returned malloced in ret_info (will be
   freed if already set */
static int checkpubkey_line(buffer* line, int line_num, const char* filename,
		const char* algo, unsigned int algolen,
		const unsigned char* keyblob, unsigned int keybloblen,
		char ** ret_info) {
	buffer *options_buf = NULL;
	char *info_str = NULL;
	unsigned int pos, len, infopos, infolen;
	int ret = DROPBEAR_FAILURE;

	if (line->len < MIN_AUTHKEYS_LINE || line->len > MAX_AUTHKEYS_LINE) {
		TRACE(("checkpubkey_line: bad line length %d", line->len))
		goto out;
	}

	if (memchr(line->data, 0x0, line->len) != NULL) {
		TRACE(("checkpubkey_line: bad line has null char"))
		goto out;
	}

	/* compare the algorithm. +3 so we have enough bytes to read a space and some base64 characters too. */
	if (line->pos + algolen+3 > line->len) {
		goto out;
	}
	/* check the key type */
	if (strncmp((const char *) buf_getptr(line, algolen), algo, algolen) != 0) {
		int is_comment = 0;
		unsigned char *options_start = NULL;
		int options_len = 0;
		int escape, quoted;

		/* skip over any comments or leading whitespace */
		while (line->pos < line->len) {
			const char c = buf_getbyte(line);
			if (c == ' ' || c == '\t') {
				continue;
			} else if (c == '#') {
				is_comment = 1;
				break;
			}
			buf_decrpos(line, 1);
			break;
		}
		if (is_comment) {
			/* next line */
			goto out;
		}

		/* remember start of options */
		options_start = buf_getptr(line, 1);
		quoted = 0;
		escape = 0;
		options_len = 0;

		/* figure out where the options are */
		while (line->pos < line->len) {
			const char c = buf_getbyte(line);
			if (!quoted && (c == ' ' || c == '\t')) {
				break;
			}
			escape = (!escape && c == '\\');
			if (!escape && c == '"') {
				quoted = !quoted;
			}
			options_len++;
		}
		options_buf = buf_new(options_len);
		buf_putbytes(options_buf, options_start, options_len);

		/* compare the algorithm. +3 so we have enough bytes to read a space and some base64 characters too. */
		if (line->pos + algolen+3 > line->len) {
			goto out;
		}
		if (strncmp((const char *) buf_getptr(line, algolen), algo, algolen) != 0) {
			goto out;
		}
	}
	buf_incrpos(line, algolen);

	/* check for space (' ') character */
	if (buf_getbyte(line) != ' ') {
		TRACE(("checkpubkey_line: space character expected, isn't there"))
		goto out;
	}

	/* find the length of base64 data */
	pos = line->pos;
	for (len = 0; line->pos < line->len; len++) {
		if (buf_getbyte(line) == ' ') {
			break;
		}
	}

	/* find out the length of the public key info, stop at the first space */
	infopos = line->pos;
	for (infolen = 0; line->pos < line->len; infolen++) {
		const char c = buf_getbyte(line);
		if (c == ' ') {
			break;
		}
		/* We have an allowlist - authorized_keys lines can't be fully trusted,
		some shell scripts may do unsafe things with env var values */
		if (!(isalnum(c) || strchr(".,_-+@", c))) {
			TRACE(("Not setting SSH_PUBKEYINFO, special characters"))
			infolen = 0;
			break;
		}
	}
	if (infolen > 0) {
		info_str = m_malloc(infolen + 1);
		buf_setpos(line, infopos);
	strncpy(info_str, buf_getptr(line, infolen), infolen);
	}

	/* truncate to base64 data length */
	buf_setpos(line, pos);
	buf_setlen(line, line->pos + len);

	TRACE(("checkpubkey_line: line pos = %d len = %d", line->pos, line->len))

	ret = cmp_base64_key(keyblob, keybloblen, (const unsigned char *) algo, algolen, line, NULL);

	/* free pubkey_info if it is filled */
	if (ret_info && *ret_info) {
		m_free(*ret_info);
		*ret_info = NULL;
	}

	if (ret == DROPBEAR_SUCCESS) {
		if (options_buf) {
			ret = svr_add_pubkey_options(options_buf, line_num, filename);
		}
		if (ret_info) {
			/* take the (optional) public key information */
			*ret_info = info_str;
			info_str = NULL;
		}
	}

out:
	if (options_buf) {
		buf_free(options_buf);
	}
	if (info_str) {
		m_free(info_str);
	}
	return ret;
}

/* Returns the full path to the user's authorized_keys file in an
 * allocated string which caller must free. */
static char *authorized_keys_filepath() {
	size_t len = 0;
	char *pathname = NULL, *dir = NULL;
	const char *filename = "authorized_keys";

	dir = expand_homedir_path_home(svr_opts.authorized_keys_dir,
				       ses.authstate.pw_dir);

	/* allocate max required pathname storage,
	 * = dir + "/" + "authorized_keys" + '\0' */;
	len = strlen(dir) + strlen(filename) + 2;
	pathname = m_malloc(len);
	snprintf(pathname, len, "%s/%s", dir, filename);
	m_free(dir);
	return pathname;
}

/* Checks whether a specified publickey (and associated algorithm) is an
 * acceptable key for authentication */
/* Returns DROPBEAR_SUCCESS if key is ok for auth, DROPBEAR_FAILURE otherwise */
static int checkpubkey(const char* keyalgo, unsigned int keyalgolen,
		const unsigned char* keyblob, unsigned int keybloblen) {

	FILE * authfile = NULL;
	char * filename = NULL;
	int ret = DROPBEAR_FAILURE;
	buffer * line = NULL;
	int line_num;
	uid_t origuid;
	gid_t origgid;

	TRACE(("enter checkpubkey"))

#if DROPBEAR_CERT_KEYS
	{
		enum signkey_type keytype = signkey_type_from_name(keyalgo, keyalgolen);
		if (signkey_is_cert_type(keytype)) {
			return checkpubkey_cert(keyalgo, keyalgolen, keyblob, keybloblen);
		}
	}
#endif

#if DROPBEAR_SVR_MULTIUSER
	/* access the file as the authenticating user. */
	origuid = getuid();
	origgid = getgid();
	if ((setegid(ses.authstate.pw_gid)) < 0 ||
		(seteuid(ses.authstate.pw_uid)) < 0) {
		dropbear_exit("Failed to set euid");
	}
#endif
	/* check file permissions, also whether file exists */
	if (checkpubkeyperms() == DROPBEAR_FAILURE) {
		TRACE(("bad authorized_keys permissions, or file doesn't exist"))
	} else {
		/* we don't need to check pw and pw_dir for validity, since
		 * its been done in checkpubkeyperms. */
		filename = authorized_keys_filepath();
		authfile = fopen(filename, "r");
		if (!authfile) {
			TRACE(("checkpubkey: failed opening %s: %s", filename, strerror(errno)))
		}
	}
#if DROPBEAR_SVR_MULTIUSER
	if ((seteuid(origuid)) < 0 ||
		(setegid(origgid)) < 0) {
		dropbear_exit("Failed to revert euid");
	}
#endif

	if (authfile == NULL) {
		goto out;
	}
	TRACE(("checkpubkey: opened authorized_keys OK"))

	line = buf_new(MAX_AUTHKEYS_LINE);
	line_num = 0;

	/* iterate through the lines */
	do {
		if (buf_getline(line, authfile) == DROPBEAR_FAILURE) {
			/* EOF reached */
			TRACE(("checkpubkey: authorized_keys EOF reached"))
			break;
		}
		line_num++;

		ret = checkpubkey_line(line, line_num, filename, keyalgo, keyalgolen,
			keyblob, keybloblen,
#if DROPBEAR_SVR_PUBKEY_OPTIONS_BUILT
			&ses.authstate.pubkey_info
#else
			NULL
#endif
		);
		if (ret == DROPBEAR_SUCCESS) {
			break;
		}

		/* We continue to the next line otherwise */
	} while (1);

out:
	if (authfile) {
		fclose(authfile);
	}
	if (line) {
		buf_free(line);
	}
	m_free(filename);
	TRACE(("leave checkpubkey: ret=%d", ret))
	return ret;
}

#if DROPBEAR_CERT_KEYS
/* Check a certificate against authorized_keys cert-authority entries.
 * Parses the cert, finds matching CA key, verifies CA signature,
 * checks principals, time validity, and processes cert options. */
static int checkpubkey_cert(const char* keyalgo, unsigned int keyalgolen,
		const unsigned char* keyblob, unsigned int keybloblen) {

	FILE * authfile = NULL;
	char * filename = NULL;
	int ret = DROPBEAR_FAILURE;
	buffer * line = NULL;
	buffer * certbuf = NULL;
	sign_key * cert_key = NULL;
	int line_num;
	uid_t origuid;
	gid_t origgid;

	TRACE(("enter checkpubkey_cert"))

#if !DROPBEAR_SVR_PUBKEY_OPTIONS_BUILT
	/* Both certificate permissions and CA-line restrictions require options
	 * support. Do not authenticate a certificate we cannot restrict. */
	dropbear_log(LOG_WARNING,
		"Certificate authentication requires public key options support");
	goto out;
#endif

	/* Parse the certificate to extract CA key and metadata */
	if (keybloblen > MAX_CERT_SIZE) {
		TRACE(("checkpubkey_cert: cert blob too large %u", keybloblen))
		goto out;
	}
	cert_key = new_sign_key();
	certbuf = buf_new(keybloblen);
	buf_putbytes(certbuf, keyblob, keybloblen);
	buf_setpos(certbuf, 0);

	{
		enum signkey_type cert_keytype = signkey_type_from_name(keyalgo, keyalgolen);
		if (buf_get_pub_key(certbuf, cert_key, &cert_keytype) == DROPBEAR_FAILURE) {
			TRACE(("checkpubkey_cert: failed to parse certificate"))
			goto out;
		}
	}

	if (cert_key->cert_info == NULL) {
		TRACE(("checkpubkey_cert: no cert_info after parse"))
		goto out;
	}

	/* Only user certificates are valid for authentication */
	if (cert_key->cert_info->cert_type != SSH_CERT_TYPE_USER) {
		dropbear_log(LOG_WARNING, "Certificate is not a user certificate");
		goto out;
	}

#if DROPBEAR_SVR_MULTIUSER
	origuid = getuid();
	origgid = getgid();
	if ((setegid(ses.authstate.pw_gid)) < 0 ||
		(seteuid(ses.authstate.pw_uid)) < 0) {
		dropbear_exit("Failed to set euid");
	}
#endif
	if (checkpubkeyperms() == DROPBEAR_FAILURE) {
		TRACE(("bad authorized_keys permissions, or file doesn't exist"))
	} else {
		filename = authorized_keys_filepath();
		authfile = fopen(filename, "r");
		if (!authfile) {
			TRACE(("checkpubkey_cert: failed opening %s: %s", filename, strerror(errno)))
		}
	}
#if DROPBEAR_SVR_MULTIUSER
	if ((seteuid(origuid)) < 0 ||
		(setegid(origgid)) < 0) {
		dropbear_exit("Failed to revert euid");
	}
#endif

	if (authfile == NULL) {
		goto out;
	}

	line = buf_new(MAX_AUTHKEYS_LINE);
	line_num = 0;

	/* Iterate through authorized_keys looking for cert-authority lines */
	do {
		if (buf_getline(line, authfile) == DROPBEAR_FAILURE) {
			break;
		}
		line_num++;

		/* Parse line looking for cert-authority entries.
		 * Format: cert-authority[,options] algo base64key [comment]
		 * or: options,cert-authority[,options] algo base64key [comment] */
		{
			buffer *options_buf = NULL;
			unsigned int pos;
			unsigned int len;
			int found_cert_authority = 0;
			int is_comment = 0;
			unsigned char *options_start = NULL;
			int options_len = 0;
			int escape, quoted;
			const char *ca_algo;
			unsigned int ca_algolen;

			if (line->len < MIN_AUTHKEYS_LINE || line->len > MAX_AUTHKEYS_LINE) {
				continue;
			}
			if (memchr(line->data, 0x0, line->len) != NULL) {
				continue;
			}

			buf_setpos(line, 0);

			/* Skip leading whitespace and check for comments */
			while (line->pos < line->len) {
				const char c = buf_getbyte(line);
				if (c == ' ' || c == '\t') {
					continue;
				} else if (c == '#') {
					is_comment = 1;
					break;
				}
				buf_decrpos(line, 1);
				break;
			}
			if (is_comment) {
				continue;
			}

			/* Remember start of options/cert-authority field */
			options_start = buf_getptr(line, 1);
			quoted = 0;
			escape = 0;
			options_len = 0;

			/* Read the first field (could be "cert-authority", options, or algo) */
			while (line->pos < line->len) {
				const char c = buf_getbyte(line);
				if (!quoted && (c == ' ' || c == '\t')) {
					break;
				}
				escape = (!escape && c == '\\');
				if (!escape && c == '"') {
					quoted = !quoted;
				}
				options_len++;
			}

			/* Check if this field contains "cert-authority" */
			{
				const char *field = (const char *)options_start;
				int flen = options_len;
				const char *cert_auth_str = "cert-authority";
				int cert_auth_len = 14;

				/* Check for exact match or comma-delimited match,
				   using quote-aware tokenization */
				if (flen >= cert_auth_len) {
					const char *p = field;
					const char *end = field + flen;
					while (p < end) {
						const char *tok_start = p;
						int in_q = 0, esc = 0;
						while (p < end) {
							char c = *p;
							if (esc) { esc = 0; }
							else if (c == '\\') { esc = 1; }
							else if (c == '"') { in_q = !in_q; }
							else if (!in_q && c == ',') { break; }
							p++;
						}
						if ((int)(p - tok_start) == cert_auth_len
								&& memcmp(tok_start, cert_auth_str, cert_auth_len) == 0) {
							found_cert_authority = 1;
							break;
						}
						if (p < end) p++; /* skip comma */
					}
				}
			}

			if (!found_cert_authority) {
				continue;
			}

			/* Build options buffer excluding "cert-authority" keyword */
			{
				/* Parse the comma-separated options, removing cert-authority */
				buffer *full_opts = buf_new(options_len);
				const char *p = (const char *)options_start;
				const char *end = p + options_len;
				const char *cert_auth_str = "cert-authority";
				int cert_auth_len = 14;

				while (p < end) {
					/* Find next token using quote-aware scanning */
					const char *tok_start = p;
					int in_q = 0, esc = 0;
					int token_len;
					while (p < end) {
						char c = *p;
						if (esc) { esc = 0; }
						else if (c == '\\') { esc = 1; }
						else if (c == '"') { in_q = !in_q; }
						else if (!in_q && c == ',') { break; }
						p++;
					}
					token_len = (int)(p - tok_start);

					if (token_len == cert_auth_len
							&& memcmp(tok_start, cert_auth_str, cert_auth_len) == 0) {
						/* skip cert-authority token */
					} else if (token_len > 0) {
						if (full_opts->len > 0) {
							buf_putbyte(full_opts, ',');
						}
						buf_putbytes(full_opts, (const unsigned char *)tok_start, token_len);
					}
					if (p < end) {
						p++; /* skip comma */
					}
				}
				if (full_opts->len > 0) {
					options_buf = full_opts;
				} else {
					buf_free(full_opts);
				}
			}

			/* Skip whitespace after options */
			while (line->pos < line->len) {
				const char c = buf_getbyte(line);
				if (c != ' ' && c != '\t') {
					buf_decrpos(line, 1);
					break;
				}
			}

			/* Read the CA algorithm name */
			pos = line->pos;
			for (ca_algolen = 0; line->pos < line->len; ca_algolen++) {
				if (buf_getbyte(line) == ' ') {
					break;
				}
			}
			ca_algo = (const char *)&line->data[pos];

			/* Expect space after algo */
			if (ca_algolen == 0) {
				if (options_buf) buf_free(options_buf);
				continue;
			}

			/* Read base64 CA key data */
			pos = line->pos;
			for (len = 0; line->pos < line->len; len++) {
				if (buf_getbyte(line) == ' ') {
					break;
				}
			}

			/* Truncate line to base64 data for comparison */
			buf_setpos(line, pos);
			buf_setlen(line, pos + len);

			/* Compare the CA key in authorized_keys with the cert's CA key */
			{
				int match;
				buf_setpos(cert_key->cert_info->ca_pubkey_blob, 0);
				match = cmp_base64_key(
					cert_key->cert_info->ca_pubkey_blob->data,
					cert_key->cert_info->ca_pubkey_blob->len,
					(const unsigned char *)ca_algo, ca_algolen,
					line, NULL);

				if (match != DROPBEAR_SUCCESS) {
					if (options_buf) buf_free(options_buf);
					continue;
				}
			}

			TRACE(("checkpubkey_cert: found matching CA key on line %d", line_num))

			/* CA key matches. Now verify the certificate. */

			/* 1. Verify CA signature on the certificate */
			if (cert_verify_ca_signature(cert_key) != DROPBEAR_SUCCESS) {
				dropbear_log(LOG_WARNING,
					"Certificate CA signature verification failed");
				if (options_buf) buf_free(options_buf);
				goto out;
			}

			/* 2. Check valid principals */
			if (cert_check_principal(cert_key->cert_info,
					ses.authstate.pw_name) != DROPBEAR_SUCCESS) {
				dropbear_log(LOG_WARNING,
					"Certificate principal check failed for user '%s'",
					ses.authstate.pw_name);
				if (options_buf) buf_free(options_buf);
				goto out;
			}

			/* 3. Check time validity */
			if (cert_check_time(cert_key->cert_info) != DROPBEAR_SUCCESS) {
				if (options_buf) buf_free(options_buf);
				goto out;
			}

			/* 4. Process authorized_keys line options */
			if (options_buf) {
				if (svr_add_pubkey_options(options_buf, line_num, filename)
						!= DROPBEAR_SUCCESS) {
					buf_free(options_buf);
					goto out;
				}
				buf_free(options_buf);
				options_buf = NULL;
			}

			/* 5. Process certificate critical options and extensions */
			if (cert_check_critical_options(cert_key->cert_info)
					!= DROPBEAR_SUCCESS) {
				dropbear_log(LOG_WARNING,
					"Certificate has unrecognized critical options");
				goto out;
			}
#if DROPBEAR_SVR_PUBKEY_OPTIONS_BUILT
			if (cert_apply_options(cert_key->cert_info,
					&ses.authstate.pubkey_options) != DROPBEAR_SUCCESS) {
				dropbear_log(LOG_WARNING,
					"Certificate options processing failed");
				goto out;
			}
#endif

			/* All checks passed */
			ret = DROPBEAR_SUCCESS;
			break;
		}
	} while (1);

out:
	if (authfile) {
		fclose(authfile);
	}
	if (line) {
		buf_free(line);
	}
	if (certbuf) {
		buf_free(certbuf);
	}
	if (cert_key) {
		sign_key_free(cert_key);
	}
	m_free(filename);
	TRACE(("leave checkpubkey_cert: ret=%d", ret))
	return ret;
}
#endif /* DROPBEAR_CERT_KEYS */

/* Returns DROPBEAR_SUCCESS if file permissions for pubkeys are ok,
 * DROPBEAR_FAILURE otherwise.
 * Checks that the authorized_keys path permissions are all owned by either
 * root or the user, and are g-w, o-w.
 * When this path is inside the user's home dir it checks up to and including
 * the home dir, otherwise it checks every path component. */
static int checkpubkeyperms() {
	char *path = authorized_keys_filepath(), *sep = NULL;
	int ret = DROPBEAR_SUCCESS;

	TRACE(("enter checkpubkeyperms"))

	/* Walk back up path checking permissions, stopping at either homedir,
	 * or root if the path is outside of the homedir. */
	while ((sep = strrchr(path, '/')) != NULL) {
		if (sep == path) {	/* root directory */
			sep++;
		}
		*sep = '\0';
		if (checkfileperm(path) != DROPBEAR_SUCCESS) {
			TRACE(("checkpubkeyperms: bad perm on %s", path))
			ret = DROPBEAR_FAILURE;
		}
		if (strcmp(path, ses.authstate.pw_dir) == 0 || strcmp(path, "/") == 0) {
			break;
		}
	}

	/* all looks ok, return success */
	m_free(path);

	TRACE(("leave checkpubkeyperms"))
	return ret;
}

/* Checks that a file is owned by the user or root, and isn't writable by
 * group or other */
/* returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int checkfileperm(char * filename) {
	struct stat filestat;
	int badperm = 0;

	TRACE(("enter checkfileperm(%s)", filename))

	if (stat(filename, &filestat) != 0) {
		TRACE(("leave checkfileperm: stat() != 0"))
		return DROPBEAR_FAILURE;
	}
	/* check ownership - user or root only*/
	if (filestat.st_uid != ses.authstate.pw_uid
			&& filestat.st_uid != 0) {
		badperm = 1;
		TRACE(("wrong ownership"))
	}
	/* check permissions - don't want group or others +w */
	if (filestat.st_mode & (S_IWGRP | S_IWOTH)) {
		badperm = 1;
		TRACE(("wrong perms"))
	}
	if (badperm) {
		if (!ses.authstate.perm_warn) {
			ses.authstate.perm_warn = 1;
			dropbear_log(LOG_INFO, "%s must be owned by user or root, and not writable by group or others", filename);
		}
		TRACE(("leave checkfileperm: failure perms/owner"))
		return DROPBEAR_FAILURE;
	}

	TRACE(("leave checkfileperm: success"))
	return DROPBEAR_SUCCESS;
}

#if DROPBEAR_FUZZ
int fuzz_checkpubkey_line(buffer* line, int line_num, char* filename,
		const char* algo, unsigned int algolen,
		const unsigned char* keyblob, unsigned int keybloblen) {
	return checkpubkey_line(line, line_num, filename, algo, algolen, keyblob, keybloblen, NULL);
}
#endif

#endif
