#include "includes.h"

#if DROPBEAR_CERT_KEYS

#include "dbutil.h"
#include "cert.h"
#include "buffer.h"
#include "signkey.h"
#include "ssh.h"

#if DROPBEAR_SVR_PUBKEY_OPTIONS_BUILT
#include "auth.h"
#endif

int signkey_is_cert_type(enum signkey_type type) {
	switch (type) {
#if DROPBEAR_RSA
		case DROPBEAR_SIGNKEY_RSA_CERT:
#endif
#if DROPBEAR_DSS
		case DROPBEAR_SIGNKEY_DSS_CERT:
#endif
#if DROPBEAR_ECDSA
		case DROPBEAR_SIGNKEY_ECDSA_NISTP256_CERT:
		case DROPBEAR_SIGNKEY_ECDSA_NISTP384_CERT:
		case DROPBEAR_SIGNKEY_ECDSA_NISTP521_CERT:
#endif
#if DROPBEAR_ED25519
		case DROPBEAR_SIGNKEY_ED25519_CERT:
#endif
			return 1;
		default:
			return 0;
	}
}

enum signkey_type cert_base_keytype(enum signkey_type cert_type) {
	switch (cert_type) {
#if DROPBEAR_RSA
		case DROPBEAR_SIGNKEY_RSA_CERT:
			return DROPBEAR_SIGNKEY_RSA;
#endif
#if DROPBEAR_DSS
		case DROPBEAR_SIGNKEY_DSS_CERT:
			return DROPBEAR_SIGNKEY_DSS;
#endif
#if DROPBEAR_ECDSA
		case DROPBEAR_SIGNKEY_ECDSA_NISTP256_CERT:
			return DROPBEAR_SIGNKEY_ECDSA_NISTP256;
		case DROPBEAR_SIGNKEY_ECDSA_NISTP384_CERT:
			return DROPBEAR_SIGNKEY_ECDSA_NISTP384;
		case DROPBEAR_SIGNKEY_ECDSA_NISTP521_CERT:
			return DROPBEAR_SIGNKEY_ECDSA_NISTP521;
#endif
#if DROPBEAR_ED25519
		case DROPBEAR_SIGNKEY_ED25519_CERT:
			return DROPBEAR_SIGNKEY_ED25519;
#endif
		default:
			dropbear_exit("Bad cert key type %d", cert_type);
			return DROPBEAR_SIGNKEY_NONE;
	}
}

void cert_info_free(struct dropbear_cert_info *info) {
	if (info == NULL) {
		return;
	}
	m_free(info->key_id);
	buf_free(info->valid_principals);
	buf_free(info->critical_options);
	buf_free(info->extensions);
	buf_free(info->ca_pubkey_blob);
	buf_free(info->signed_data);
	buf_free(info->signature);
	m_free(info);
}

/* Parse a certificate blob. The buffer should be positioned at the start
 * of the outer certificate blob (including the 4-byte length prefix that
 * buf_get_pub_key has NOT yet consumed — we rewind past the type string).
 *
 * Actually, cert_parse is called after buf_get_pub_key() has read the type
 * name and rewound. So buf is positioned at the start of the cert type string.
 *
 * Populates key's base key pointers (rsakey, ed25519key, etc.) and
 * allocates/fills key->cert_info.
 */
/* Check that the next string field in buf won't trigger a fatal
   dropbear_exit in buf_getstring/buf_getstringbuf. Returns 0 if safe. */
static int cert_nextstring_unsafe(const buffer *buf) {
	unsigned int slen;
	if (buf->len - buf->pos < 4) {
		return 1;
	}
	slen = ((unsigned int)buf->data[buf->pos] << 24)
		| ((unsigned int)buf->data[buf->pos+1] << 16)
		| ((unsigned int)buf->data[buf->pos+2] << 8)
		| buf->data[buf->pos+3];
	if (slen > MAX_STRING_LEN || buf->pos + 4 + slen > buf->len) {
		return 1;
	}
	return 0;
}

int cert_parse(buffer *buf, sign_key *key, enum signkey_type cert_keytype) {
	struct dropbear_cert_info *ci = NULL;
	enum signkey_type base_keytype;
	const char *base_keyname;
	unsigned int base_keynamelen;
	buffer *synthetic_buf = NULL;
	unsigned int cert_start;
	unsigned int key_fields_start;
	unsigned int key_fields_consumed;
	unsigned int signed_data_end;
	int ret = DROPBEAR_FAILURE;

	TRACE(("enter cert_parse"))

	ci = m_malloc(sizeof(*ci));
	memset(ci, 0, sizeof(*ci));

	base_keytype = cert_base_keytype(cert_keytype);
	base_keyname = signkey_name_from_type(base_keytype, &base_keynamelen);

	/* Record start of cert data for CA signature verification */
	cert_start = buf->pos;

	/* Read and skip the certificate type name string */
	if (cert_nextstring_unsafe(buf)) goto out;
	buf_eatstring(buf);

	/* Read and skip the nonce */
	if (cert_nextstring_unsafe(buf)) goto out;
	buf_eatstring(buf);

	/* Now at the key fields. We need to extract them and parse as
	 * a regular public key. Build a synthetic buffer with the base
	 * key type name prepended to the remaining cert data. */
	key_fields_start = buf->pos;

	{
		unsigned int remaining = buf->len - buf->pos;
		unsigned int synth_size = 4 + base_keynamelen + remaining;
		enum signkey_type parse_type = base_keytype;

		synthetic_buf = buf_new(synth_size);
		buf_putstring(synthetic_buf, base_keyname, base_keynamelen);
		buf_putbytes(synthetic_buf, buf_getptr(buf, remaining), remaining);
		buf_setpos(synthetic_buf, 0);

		/* Parse the embedded public key using the normal path */
		if (buf_get_pub_key(synthetic_buf, key, &parse_type) == DROPBEAR_FAILURE) {
			TRACE(("cert_parse: failed to parse embedded public key"))
			goto out;
		}

		/* Calculate how many bytes of key data were consumed from the cert.
		 * synthetic_buf consumed: 4 + base_keynamelen + key_fields_consumed */
		key_fields_consumed = synthetic_buf->pos - 4 - base_keynamelen;
	}

	/* Advance the cert buffer past the key fields */
	buf_incrpos(buf, key_fields_consumed);

	/* Read certificate metadata */
	ci->serial = buf_getint64(buf);
	ci->cert_type = buf_getint(buf);

	if (ci->cert_type != SSH_CERT_TYPE_USER && ci->cert_type != SSH_CERT_TYPE_HOST) {
		TRACE(("cert_parse: bad cert type %u", ci->cert_type))
		goto out;
	}

	/* Validate each string field before reading, so malformed cert
	   blobs cause a graceful failure instead of dropbear_exit. */
	if (cert_nextstring_unsafe(buf)) goto out;
	ci->key_id = buf_getstring(buf, NULL);
	if (cert_nextstring_unsafe(buf)) goto out;
	ci->valid_principals = buf_getstringbuf(buf);
	ci->valid_after = buf_getint64(buf);
	ci->valid_before = buf_getint64(buf);
	if (cert_nextstring_unsafe(buf)) goto out;
	ci->critical_options = buf_getstringbuf(buf);
	if (cert_nextstring_unsafe(buf)) goto out;
	ci->extensions = buf_getstringbuf(buf);

	/* Skip reserved field */
	if (cert_nextstring_unsafe(buf)) goto out;
	buf_eatstring(buf);

	/* Record the end of signed data (everything up to and including
	 * the signature key, which we read next) */
	if (cert_nextstring_unsafe(buf)) goto out;
	ci->ca_pubkey_blob = buf_getstringbuf(buf);

	/* The signed data is everything from cert_start to current position */
	signed_data_end = buf->pos;
	ci->signed_data = buf_new(signed_data_end - cert_start);
	buf_putbytes(ci->signed_data, &buf->data[cert_start],
			signed_data_end - cert_start);
	buf_setpos(ci->signed_data, 0);

	/* Read the CA signature */
	if (cert_nextstring_unsafe(buf)) goto out;
	ci->signature = buf_getstringbuf(buf);

	key->cert_info = ci;
	ci = NULL;
	ret = DROPBEAR_SUCCESS;

	TRACE(("leave cert_parse: success, serial=%llu type=%u key_id=%s",
		(unsigned long long)key->cert_info->serial,
		key->cert_info->cert_type,
		key->cert_info->key_id))

out:
	if (synthetic_buf) {
		buf_free(synthetic_buf);
	}
	if (ci) {
		cert_info_free(ci);
	}
	return ret;
}

/* Verify the CA's signature on the certificate. */
int cert_verify_ca_signature(const sign_key *key) {
	sign_key *ca_key = NULL;
	enum signkey_type ca_keytype = DROPBEAR_SIGNKEY_ANY;
	enum signature_type ca_sigtype;
	const struct dropbear_cert_info *ci = key->cert_info;
	buffer *sig_buf = NULL;
	char *sig_type_name = NULL;
	unsigned int sig_type_name_len;
	int ret = DROPBEAR_FAILURE;

	TRACE(("enter cert_verify_ca_signature"))

	if (ci == NULL || ci->ca_pubkey_blob == NULL || ci->signature == NULL) {
		goto out;
	}

	/* Deserialize the CA public key */
	ca_key = new_sign_key();
	buf_setpos(ci->ca_pubkey_blob, 0);
	if (buf_get_pub_key(ci->ca_pubkey_blob, ca_key, &ca_keytype)
			== DROPBEAR_FAILURE) {
		TRACE(("cert_verify_ca_signature: failed to parse CA key"))
		goto out;
	}

	/* Determine the CA signature type from the signature blob.
	 * The signature blob format is: string sig_type_name, then sig data.
	 * buf_verify expects: uint32 blob_len, string sig_type_name, sig data.
	 * We need to wrap it so buf_verify can read it. */
	buf_setpos(ci->signature, 0);
	sig_type_name = buf_getstring(ci->signature, &sig_type_name_len);
	ca_sigtype = signature_type_from_name(sig_type_name, sig_type_name_len);
	m_free(sig_type_name);

	if (ca_sigtype == DROPBEAR_SIGNATURE_NONE) {
		TRACE(("cert_verify_ca_signature: unknown CA signature type"))
		goto out;
	}

	/* Build a buffer that buf_verify can consume:
	 * uint32 blob_length, then the raw signature blob contents */
	sig_buf = buf_new(4 + ci->signature->len);
	buf_putint(sig_buf, ci->signature->len);
	buf_setpos(ci->signature, 0);
	buf_putbytes(sig_buf, ci->signature->data, ci->signature->len);
	buf_setpos(sig_buf, 0);

	ret = buf_verify(sig_buf, ca_key, ca_sigtype, ci->signed_data);

	TRACE(("cert_verify_ca_signature: result %d", ret))

out:
	if (ca_key) {
		sign_key_free(ca_key);
	}
	if (sig_buf) {
		buf_free(sig_buf);
	}
	return ret;
}

/* Check that username matches one of the certificate's valid principals. */
int cert_check_principal(const struct dropbear_cert_info *info,
		const char *username) {
	buffer *principals;
	unsigned int userlen;

	TRACE(("enter cert_check_principal"))

	if (info == NULL || info->valid_principals == NULL) {
		return DROPBEAR_FAILURE;
	}

	principals = info->valid_principals;
	buf_setpos(principals, 0);

	/* Empty principals list means valid for any principal (matches OpenSSH
	   behavior). This is often a configuration mistake, so log a warning. */
	if (principals->len == 0) {
		dropbear_log(LOG_WARNING,
			"Certificate has empty principals list, valid for any user");
		return DROPBEAR_SUCCESS;
	}

	userlen = strlen(username);

	while (principals->pos < principals->len) {
		char *principal = buf_getstring(principals, NULL);
		unsigned int plen = strlen(principal);
		int match = (plen == userlen && memcmp(principal, username, userlen) == 0);
		m_free(principal);
		if (match) {
			TRACE(("cert_check_principal: matched '%s'", username))
			return DROPBEAR_SUCCESS;
		}
	}

	TRACE(("cert_check_principal: no match for '%s'", username))
	return DROPBEAR_FAILURE;
}

/* Check certificate time validity against current wall clock time. */
int cert_check_time(const struct dropbear_cert_info *info) {
	time_t now;
	uint64_t now64;

	TRACE(("enter cert_check_time"))

	if (info == NULL) {
		return DROPBEAR_FAILURE;
	}

	now = time(NULL);
	if (now == (time_t)-1) {
		dropbear_log(LOG_WARNING, "Certificate time check: unable to get current time");
		return DROPBEAR_FAILURE;
	}

	now64 = (uint64_t)now;

	if (now64 < info->valid_after) {
		dropbear_log(LOG_WARNING,
			"Certificate not yet valid (valid after %llu, now %llu)",
			(unsigned long long)info->valid_after,
			(unsigned long long)now64);
		return DROPBEAR_FAILURE;
	}

	if (now64 >= info->valid_before) {
		dropbear_log(LOG_WARNING,
			"Certificate has expired (valid before %llu, now %llu)",
			(unsigned long long)info->valid_before,
			(unsigned long long)now64);
		return DROPBEAR_FAILURE;
	}

	TRACE(("cert_check_time: valid"))
	return DROPBEAR_SUCCESS;
}

/* Helper: check if a name matches in a sorted tuple buffer.
 * Tuples are: string name, string data */
static int cert_option_present(buffer *opts, const char *name) {
	unsigned int namelen = strlen(name);
	buf_setpos(opts, 0);

	while (opts->pos < opts->len) {
		char *opt_name;
		unsigned int opt_namelen;
		opt_name = buf_getstring(opts, &opt_namelen);
		buf_eatstring(opts); /* skip data */
		if (opt_namelen == namelen && memcmp(opt_name, name, namelen) == 0) {
			m_free(opt_name);
			return 1;
		}
		m_free(opt_name);
	}
	return 0;
}

/* Helper: get the string value of a named option from a tuple buffer.
 * Returns malloced string or NULL if not found. */
static char *cert_option_get_str(buffer *opts, const char *name) {
	unsigned int namelen = strlen(name);
	buf_setpos(opts, 0);

	while (opts->pos < opts->len) {
		char *opt_name;
		unsigned int opt_namelen;
		opt_name = buf_getstring(opts, &opt_namelen);
		if (opt_namelen == namelen && memcmp(opt_name, name, namelen) == 0) {
			buffer *val_buf;
			char *val;
			m_free(opt_name);
			/* The data field is a string containing the actual value string */
			val_buf = buf_getstringbuf(opts);
			buf_setpos(val_buf, 0);
			val = buf_getstring(val_buf, NULL);
			buf_free(val_buf);
			return val;
		}
		m_free(opt_name);
		buf_eatstring(opts); /* skip data */
	}
	return NULL;
}

/* Validate certificate critical options — reject if any are unrecognized. */
int cert_check_critical_options(const struct dropbear_cert_info *info) {
	TRACE(("enter cert_check_critical_options"))

	if (info == NULL) {
		return DROPBEAR_FAILURE;
	}

	if (info->critical_options && info->critical_options->len > 0) {
		buffer *copts = info->critical_options;
		buf_setpos(copts, 0);

		while (copts->pos < copts->len) {
			char *opt_name;
			unsigned int opt_namelen;
			opt_name = buf_getstring(copts, &opt_namelen);
			buf_eatstring(copts); /* skip data */

			if (strcmp(opt_name, "force-command") == 0) {
#if DROPBEAR_SVR_PUBKEY_OPTIONS_BUILT
				/* recognized */
#else
				dropbear_log(LOG_WARNING,
					"Certificate critical option '%s' is unsupported in this build",
					opt_name);
				m_free(opt_name);
				return DROPBEAR_FAILURE;
#endif
			} else if (strcmp(opt_name, "verify-required") == 0) {
				/* recognized */
			} else {
				dropbear_log(LOG_WARNING,
					"Certificate has unrecognized critical option '%s'",
					opt_name);
				m_free(opt_name);
				return DROPBEAR_FAILURE;
			}
			m_free(opt_name);
		}
	}

	TRACE(("leave cert_check_critical_options: success"))
	return DROPBEAR_SUCCESS;
}

#if DROPBEAR_SVR_PUBKEY_OPTIONS_BUILT
/* Apply certificate critical options and extensions to PubKeyOptions.
 * If *opts_p is NULL, allocates a new one. */
int cert_apply_options(const struct dropbear_cert_info *info,
		struct PubKeyOptions **opts_p) {
	struct PubKeyOptions *opts;

	TRACE(("enter cert_apply_options"))

	if (info == NULL || opts_p == NULL) {
		return DROPBEAR_FAILURE;
	}

	if (*opts_p == NULL) {
		*opts_p = m_malloc(sizeof(struct PubKeyOptions));
		memset(*opts_p, 0, sizeof(struct PubKeyOptions));
	}
	opts = *opts_p;

	/* Apply force-command from critical options */
	if (info->critical_options && info->critical_options->len > 0) {
		char *cmd = cert_option_get_str(info->critical_options, "force-command");
		if (cmd) {
			if (opts->forced_command) {
				if (strcmp(opts->forced_command, cmd) != 0) {
					dropbear_log(LOG_WARNING,
						"Certificate force-command conflicts with authorized_keys command");
					m_free(cmd);
					return DROPBEAR_FAILURE;
				}
				m_free(cmd);
			} else {
				opts->forced_command = cmd;
			}
		}
	}

	/* Apply verify-required from critical options */
	if (info->critical_options && info->critical_options->len > 0) {
		if (cert_option_present(info->critical_options, "verify-required")) {
#if DROPBEAR_SK_ECDSA || DROPBEAR_SK_ED25519
			opts->verify_required_flag = 1;
#endif
		}
	}

	/* Process extensions — absence of a permit extension means denied.
	 * Extensions use the inverse logic of authorized_keys: in certs,
	 * you must have the permit-* extension to allow a capability. */
	if (info->extensions) {
		if (!cert_option_present(info->extensions, "permit-pty")) {
			opts->no_pty_flag = 1;
		}
		if (!cert_option_present(info->extensions, "permit-port-forwarding")) {
			opts->no_port_forwarding_flag = 1;
		}
#if DROPBEAR_SVR_AGENTFWD
		if (!cert_option_present(info->extensions, "permit-agent-forwarding")) {
			opts->no_agent_forwarding_flag = 1;
		}
#endif
#if DROPBEAR_X11FWD
		if (!cert_option_present(info->extensions, "permit-X11-forwarding")) {
			opts->no_x11_forwarding_flag = 1;
		}
#endif
#if DROPBEAR_SK_ECDSA || DROPBEAR_SK_ED25519
		if (cert_option_present(info->extensions, "no-touch-required")) {
			opts->no_touch_required_flag = 1;
		}
#endif
	}

	TRACE(("leave cert_apply_options: success"))
	return DROPBEAR_SUCCESS;
}
#endif /* DROPBEAR_SVR_PUBKEY_OPTIONS_BUILT */

#endif /* DROPBEAR_CERT_KEYS */
