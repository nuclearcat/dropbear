#ifndef DROPBEAR_CERT_H_
#define DROPBEAR_CERT_H_

#include "includes.h"

#if DROPBEAR_CERT_KEYS

#include "buffer.h"
#include "signkey.h"

struct dropbear_cert_info {
	uint64_t serial;
	uint32_t cert_type;        /* SSH_CERT_TYPE_USER or SSH_CERT_TYPE_HOST */
	char *key_id;              /* CA-provided identifier, malloced */
	buffer *valid_principals;  /* packed strings buffer */
	uint64_t valid_after;
	uint64_t valid_before;
	buffer *critical_options;  /* packed name/data tuples */
	buffer *extensions;        /* packed name/data tuples */
	buffer *ca_pubkey_blob;    /* raw CA public key blob */

	/* For CA signature verification: the signed portion of the cert
	 * (everything from the start through the signature key field) */
	buffer *signed_data;
	buffer *signature;         /* CA's signature blob */
};

/* Returns 1 if the key type is a certificate variant */
int signkey_is_cert_type(enum signkey_type type);

/* Maps a certificate key type to its underlying base key type.
 * e.g. DROPBEAR_SIGNKEY_ED25519_CERT -> DROPBEAR_SIGNKEY_ED25519 */
enum signkey_type cert_base_keytype(enum signkey_type cert_type);

/* Parse a certificate blob. Populates the sign_key's base key pointers
 * (rsakey, ed25519key, etc.) and allocates/fills key->cert_info.
 * buf should be positioned at the start of the certificate blob. */
int cert_parse(buffer *buf, sign_key *key, enum signkey_type cert_keytype);

/* Verify the CA's signature on the certificate.
 * Must be called after cert_parse(). */
#if DROPBEAR_SIGNKEY_VERIFY
int cert_verify_ca_signature(const sign_key *key);
#endif

/* Check that username matches one of the certificate's valid principals.
 * Empty principals list allows any principal. */
int cert_check_principal(const struct dropbear_cert_info *info,
		const char *username);

/* Check certificate time validity against current wall clock time. */
int cert_check_time(const struct dropbear_cert_info *info);

/* Validate certificate critical options — rejects if any unrecognized.
 * Does NOT apply options (caller must do that with cert_apply_options). */
int cert_check_critical_options(const struct dropbear_cert_info *info);

#if DROPBEAR_SVR_PUBKEY_OPTIONS_BUILT
struct PubKeyOptions;
/* Apply certificate extensions and critical options to a PubKeyOptions struct.
 * If *opts_p is NULL, allocates a new one. Must be called after
 * cert_check_critical_options() succeeds. */
int cert_apply_options(const struct dropbear_cert_info *info,
		struct PubKeyOptions **opts_p);
#endif

/* Free a dropbear_cert_info and all its contents. */
void cert_info_free(struct dropbear_cert_info *info);

#endif /* DROPBEAR_CERT_KEYS */

#endif /* DROPBEAR_CERT_H_ */
