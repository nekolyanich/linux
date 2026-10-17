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
 */

#pragma once

#include <linux/ioctl.h>
#include <linux/types.h>

#define SEP_KEY_IFACE_VERSION 1

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
  __u32 flags;      /* in: 0 (access control comes later) */
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
  __u32 reserved[5];
  __u8  blob[SEP_KEY_BLOB_MAX];
  __u8  pub[SEP_KEY_PUB_MAX];   /* out */
  __u8  pad[3];
};

#define SEP_KEY_IOC_MAGIC 0xB2

#define SEP_KEY_GET_INFO _IOR (SEP_KEY_IOC_MAGIC, 0x01, struct sep_key_info)
#define SEP_KEY_CREATE   _IOWR(SEP_KEY_IOC_MAGIC, 0x02, struct sep_key_create)
#define SEP_KEY_SIGN     _IOWR(SEP_KEY_IOC_MAGIC, 0x03, struct sep_key_sign)
#define SEP_KEY_ECDH     _IOWR(SEP_KEY_IOC_MAGIC, 0x04, struct sep_key_ecdh)
#define SEP_KEY_PUBKEY   _IOWR(SEP_KEY_IOC_MAGIC, 0x05, struct sep_key_pubkey)
