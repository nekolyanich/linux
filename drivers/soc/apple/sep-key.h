/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Userspace interface for the SEP key store: keys whose private half never
 * leaves the enclave.
 *
 * A key is an opaque blob the enclave wraps under the caller's own keybag (one
 * per Linux user, created on the user's first CREATE): userspace keeps the
 * blob, the enclave keeps nothing per key, and a blob works only under the bag
 * that made it, so another user's blob is refused. Forgetting the blob deletes
 * the key. The fd carries the uid that opened it.
 *
 * Every ioctl copies its struct back, also when it fails with the enclave's
 * refusal: sep_status is the enclave's own status then.
 *
 * A key created with SEP_KEY_CREATE_BIOMETRY is gated by a finger: the
 * enclave signs or derives with it only within a context a match has
 * credited. SEP_KEY_AUTH starts a Touch ID verify for this file (the sensor is
 * busy for /dev/sep-bio meanwhile, and the other way round: EBUSY),
 * SEP_KEY_AUTH_POLL reports it, and on a match the file holds a credit: one
 * operation by default, or every operation within window_s seconds. The
 * credit ends after its operation, at the window's end, on SEP_KEY_AUTH_CANCEL,
 * on a new SEP_KEY_AUTH, when the file is closed and when the system sleeps
 * (also a match not yet polled). The credit belongs to the open file
 * description, not to a process: whoever shares it (dup, fork, SCM_RIGHTS)
 * shares the credit, so open the device O_CLOEXEC to keep it from an exec'd
 * program, and do not pass the fd on while it holds one. Without a credit an
 * operation on a gated key fails with EACCES. A gated key outlives adding and
 * deleting fingers while one stays enrolled; once every finger is gone and one
 * is enrolled anew, its operations fail with EKEYREVOKED. Gated keys need the
 * opener's fingers in the enclave: INFO's SEP_KEY_INFO_BIOMETRY says whether
 * this uid can have them.
 */

#pragma once

#include <linux/ioctl.h>
#include <linux/types.h>

#define SEP_KEY_IFACE_VERSION 2

#define SEP_KEY_BLOB_MAX   1024 /* the enclave's stored set {rk={..}}, ~260 B */
#define SEP_KEY_PUB_MAX    97   /* P-384 04||X||Y */
#define SEP_KEY_SIG_MAX    112  /* DER ECDSA P-384, or Ed25519's 64 B */
#define SEP_KEY_DATA_MAX   1024 /* ECDSA: the digest; Ed25519: the message */
#define SEP_KEY_SECRET_MAX 48

/* The enclave's key types (AKSRefKeyType). */
enum {
  SEP_KEY_X25519   = 1, /* ECDH */
  SEP_KEY_ED25519  = 3, /* sign */
  SEP_KEY_P256     = 4, /* sign, ECDH */
  SEP_KEY_P256_PKA = 5, /* the same on the enclave's PKA engine */
  SEP_KEY_P384     = 7, /* sign, ECDH */
  SEP_KEY_P384_PKA = 8,
};

#define SEP_KEY_CLASS_DEFAULT 9

/* sep_key_info.flags */
#define SEP_KEY_INFO_BAG_STORED 1u /* this uid has a keybag */
#define SEP_KEY_INFO_BAG_LOADED 2u /* and it is loaded in the enclave now */
#define SEP_KEY_INFO_BIOMETRY   4u /* this uid can create finger-gated keys */
#define SEP_KEY_INFO_CREDIT     8u /* this file holds an AUTH credit now */

/* sep_key_create.flags */
#define SEP_KEY_CREATE_BIOMETRY 1u /* sign/ECDH only after a match (SEP_KEY_AUTH) */

/* sep_key_pubkey.flags */
#define SEP_KEY_PUBKEY_BIOMETRY 1u /* the blob is finger-gated */

struct sep_key_info {
  __u32 version;
  __u32 uid;
  __u32 flags;
  __u32 types;    /* 1 << SEP_KEY_* of the types CREATE takes */
  __u32 data_max; /* SEP_KEY_DATA_MAX */
  __u32 reserved[3];
};

struct sep_key_create {
  __u32 type;       /* in: SEP_KEY_* */
  __u32 class;      /* in: 0 or SEP_KEY_CLASS_DEFAULT; nothing else in v1 */
  __u32 flags;      /* in: 0 or SEP_KEY_CREATE_BIOMETRY */
  __s32 sep_status; /* out */
  __u32 blob_len;   /* out */
  __u32 pub_len;    /* out */
  __u32 reserved[2];
  __u8  blob[SEP_KEY_BLOB_MAX]; /* out */
  __u8  pub[SEP_KEY_PUB_MAX];   /* out: 32 B for X25519/Ed25519, else 04||X||Y */
  __u8  pad[3];
};

/*
 * ECDSA signs data as the digest the caller computed (a longer one is cut to
 * the curve's size, as FIPS 186 does) and returns DER SEQUENCE { r, s };
 * Ed25519 signs data as the whole message and returns 64 B.
 */
struct sep_key_sign {
  __u32 blob_len;   /* in */
  __u32 data_len;   /* in: 1..SEP_KEY_DATA_MAX */
  __u32 sig_len;    /* out */
  __s32 sep_status; /* out */
  __u32 reserved[4];
  __u8  blob[SEP_KEY_BLOB_MAX];
  __u8  data[SEP_KEY_DATA_MAX];
  __u8  sig[SEP_KEY_SIG_MAX];  /* out */
};

/* Raw ECDH: the shared x coordinate (32/48 B), or X25519's 32 B. */
struct sep_key_ecdh {
  __u32 blob_len;   /* in */
  __u32 peer_len;   /* in: the peer's public key, as pub above */
  __u32 secret_len; /* out */
  __s32 sep_status; /* out */
  __u32 reserved[4];
  __u8  blob[SEP_KEY_BLOB_MAX];
  __u8  peer[SEP_KEY_PUB_MAX];
  __u8  secret[SEP_KEY_SECRET_MAX]; /* out */
  __u8  pad[3];
};

/* The blob's type and public key, read from the blob: no enclave operation. */
struct sep_key_pubkey {
  __u32 blob_len; /* in */
  __u32 type;     /* out */
  __u32 pub_len;  /* out */
  __u32 flags;    /* out: SEP_KEY_PUBKEY_* */
  __u32 reserved[4];
  __u8  blob[SEP_KEY_BLOB_MAX];
  __u8  pub[SEP_KEY_PUB_MAX];   /* out */
  __u8  pad[3];
};

/* sep_key_auth.flags */
#define SEP_KEY_AUTH_WINDOW 1u /* every operation within window_s, not just one */

#define SEP_KEY_AUTH_WINDOW_MAX 300 /* seconds */
#define SEP_KEY_AUTH_HOLD_S     30  /* how long a one-operation credit waits */

/* sep_key_auth_poll.state */
enum {
  SEP_KEY_AUTH_IDLE    = 0, /* no AUTH on this file */
  SEP_KEY_AUTH_PENDING = 1, /* touch the sensor */
  SEP_KEY_AUTH_MATCH   = 2, /* the file holds a credit */
  SEP_KEY_AUTH_NOMATCH = 3, /* not an enrolled finger of this user */
  SEP_KEY_AUTH_FAILED  = 4, /* not compared: status says why (sep-bio's) */
};

struct sep_key_auth {
  __u32 flags;    /* in: 0 or SEP_KEY_AUTH_WINDOW */
  __u32 window_s; /* in: 1..SEP_KEY_AUTH_WINDOW_MAX with SEP_KEY_AUTH_WINDOW */
  __u32 reserved[6];
};

struct sep_key_auth_poll {
  __u32 state;     /* out: SEP_KEY_AUTH_* */
  __u32 status;    /* out: with SEP_KEY_AUTH_FAILED */
  __u32 guidance;  /* out: sep-bio's guidance while pending */
  __u32 remaining_ms; /* out: with MATCH, how long the credit lasts */
  __u32 reserved[4];
};

#define SEP_KEY_IOC_MAGIC 0xB2

#define SEP_KEY_GET_INFO _IOR (SEP_KEY_IOC_MAGIC, 0x01, struct sep_key_info)
#define SEP_KEY_CREATE   _IOWR(SEP_KEY_IOC_MAGIC, 0x02, struct sep_key_create)
#define SEP_KEY_SIGN     _IOWR(SEP_KEY_IOC_MAGIC, 0x03, struct sep_key_sign)
#define SEP_KEY_ECDH     _IOWR(SEP_KEY_IOC_MAGIC, 0x04, struct sep_key_ecdh)
#define SEP_KEY_PUBKEY   _IOWR(SEP_KEY_IOC_MAGIC, 0x05, struct sep_key_pubkey)
#define SEP_KEY_AUTH        _IOW (SEP_KEY_IOC_MAGIC, 0x06, struct sep_key_auth)
#define SEP_KEY_AUTH_POLL   _IOR (SEP_KEY_IOC_MAGIC, 0x07, struct sep_key_auth_poll)
#define SEP_KEY_AUTH_CANCEL _IO  (SEP_KEY_IOC_MAGIC, 0x08)
