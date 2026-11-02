/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Userspace interface for the SEP key store: keys whose private half never
 * leaves the enclave.
 *
 * A key is an opaque blob the enclave wraps under the caller's home keybag,
 * one per Linux user as macOS has it: the identity bag (designated to the
 * fingers' SEP user) for uid 1000 once it exists, else the uid's own bag,
 * created on its first CREATE. Every key of a user, plain, gated or an
 * attestation key, lives there. Userspace keeps the blob, the enclave keeps
 * nothing per key, and a blob works only under the bag that made it, so
 * another user's blob is refused. Forgetting the blob deletes the key. The fd
 * carries the uid that opened it. uid 1000's ungated keys made in its own bag
 * before interface 4 keep working: refused by the identity bag as another
 * bag's, an operation on them is tried on that bag too; new keys never go
 * there.
 *
 * Every ioctl copies its struct back, also when it fails with the enclave's
 * refusal: sep_status is the enclave's own status then.
 *
 * A key created with SEP_KEY_CREATE_PRESENCE is gated by a finger or the
 * bag's password (macOS's .userPresence): a match credits it as below; the
 * password half follows the bag's secret, so it changes with that secret.
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
 *
 * Every enrolled finger, whoever enrolled it through /dev/sep-bio, lives under
 * one SEP user, 1000, and only uid 1000 has gated keys: any enrolled finger
 * credits uid 1000's gated keys. On a machine with several people's fingers
 * enrolled, a gated key proves "an enrolled finger", not "this person's".
 */

#pragma once

#include <linux/ioctl.h>
#include <linux/types.h>

#define SEP_KEY_IFACE_VERSION 6 /* 5: password-mode bags, UNLOCK, LOCK; 6: NEW_BAG */

#define SEP_KEY_BLOB_MAX   1024 /* the enclave's stored set {rk={..}}, ~260 B */
#define SEP_KEY_PUB_MAX    97   /* P-384 04||X||Y */
#define SEP_KEY_SIG_MAX    112  /* DER ECDSA P-384, or Ed25519's 64 B */
#define SEP_KEY_DATA_MAX   1024 /* ECDSA: the digest; Ed25519: the message */
#define SEP_KEY_SECRET_MAX 48
#define SEP_KEY_NONCE_MAX  32
#define SEP_KEY_STATEMENT_MAX 4096 /* the largest seen: 1460 B */

/* The enclave's key types (AKSRefKeyType). */
enum {
  SEP_KEY_X25519   = 1, /* ECDH */
  SEP_KEY_ED25519  = 3, /* sign */
  SEP_KEY_P256     = 4, /* sign, ECDH */
  SEP_KEY_P256_PKA = 5, /* the same on the enclave's PKA engine */
  SEP_KEY_ATTEST_KEY = 6, /* P-384, attests other keys (SEP_KEY_ATTEST) only */
  SEP_KEY_P384     = 7, /* sign, ECDH */
  SEP_KEY_P384_PKA = 8,
};

#define SEP_KEY_CLASS_DEFAULT 9

/* sep_key_info.flags */
#define SEP_KEY_INFO_BAG_STORED 1u /* this uid's home bag exists */
#define SEP_KEY_INFO_BAG_LOADED 2u /* and it is loaded in the enclave now (never the identity bag: per op) */
#define SEP_KEY_INFO_BIOMETRY   4u /* this uid can create finger-gated keys */
#define SEP_KEY_INFO_CREDIT     8u /* this file holds an AUTH credit now */
#define SEP_KEY_INFO_HOME_IDENTITY 16u /* this uid's home bag is the identity bag */
#define SEP_KEY_INFO_PASSWORD   32u /* this uid's home bag is in password mode */
#define SEP_KEY_INFO_LOCKED     64u /* and closed: ops are ENOKEY until SEP_KEY_UNLOCK */
#define SEP_KEY_INFO_LOGIN_SAME 128u /* and marked as the login password (PAM tries it) */
/*
 * For uid 1000, INFO (as every operation) reads the identity keybag's record
 * and fails with its error when it cannot: EEXIST while provisioning writes
 * it, EINVAL or ENOTSYNC for a record that does not check out, or the
 * error opening it.
 */

/* sep_key_create.flags */
#define SEP_KEY_CREATE_BIOMETRY 1u /* sign/ECDH only after a match (SEP_KEY_AUTH) */
#define SEP_KEY_CREATE_PRESENCE 2u /* after a match or the bag's password: finger or password */
/* an SEP_KEY_ATTEST_KEY takes no flag (it is never gated): EINVAL with any */

/* sep_key_pubkey.flags */
#define SEP_KEY_PUBKEY_BIOMETRY 1u /* the blob is finger-gated */
#define SEP_KEY_PUBKEY_PRESENCE 2u /* the blob is finger-or-password gated */

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
  __u32 flags;      /* in: 0, SEP_KEY_CREATE_BIOMETRY or SEP_KEY_CREATE_PRESENCE */
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

/*
 * The enclave's statement of a key (`oa`): the attester, an
 * SEP_KEY_ATTEST_KEY, signs a per-boot key that vouches for the boot (ECID,
 * measurements, nonce), which signs the subject's type, class, bag and ACL;
 * the subject signs its own part. Returned as the enclave's DER, unparsed.
 * Both keys must be in one bag, the caller's home (EKEYREJECTED for a mix); a
 * gated subject needs no match. X25519 subjects: EOPNOTSUPP. EACCES: the
 * subject's ACL refuses `oa`, which no touch changes.
 */

struct sep_key_attest {
  __u32 attester_len;  /* in */
  __u32 subject_len;   /* in */
  __u32 nonce_len;     /* in: 0..SEP_KEY_NONCE_MAX */
  __s32 sep_status;    /* out */
  __u32 statement_len; /* out */
  __u32 reserved[3];   /* in: 0 */
  __u8  attester[SEP_KEY_BLOB_MAX];
  __u8  subject[SEP_KEY_BLOB_MAX];
  __u8  nonce[SEP_KEY_NONCE_MAX];
  __u8  statement[SEP_KEY_STATEMENT_MAX]; /* out: one DER SEQUENCE */
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

/*
 * A new secret for the caller's home bag: its keys, their certificates and
 * its EK stay (the enclave rewraps the bag, op 0x07 as macOS's
 * aks_change_secret). uid 1000's home is the identity bag; another uid's is
 * its own bag, designated to its SEP user -uid whenever the driver loads it
 * (uid 10 and up). uid 0 and 1..9: EOPNOTSUPP.
 *
 * With SEP_KEY_CHANGE_RANDOM (new_len 0) the kernel makes a random 32 B new
 * secret; else new_secret holds new_len bytes. With SEP_KEY_CHANGE_OLD,
 * old_secret holds old_len bytes the enclave checks (a login password); else
 * (old_len 0) the bag record's secret is the old one. Both are zeroed before
 * the struct goes back. A refusal is EACCES with the enclave's status in
 * sep_status (-5: not the bag's secret). EIO with sep_status 0: the enclave
 * changed the secret but the record was not rewritten; the old record still
 * opens with the old secret, and the next load of the bag uses it.
 */
#define SEP_KEY_CHANGE_RANDOM 1u
#define SEP_KEY_CHANGE_OLD    2u
/*
 * The new secret is a password (password mode): the record stores no secret,
 * the bag is closed at every boot until SEP_KEY_UNLOCK, the kernel keeps the
 * password only while it is open. Without it the record stores the new
 * secret (stored mode; SEP_KEY_CHANGE_RANDOM always is). On a password-mode
 * bag a change needs SEP_KEY_CHANGE_OLD and the bag open (EINVAL, ENOKEY).
 */
#define SEP_KEY_CHANGE_TO_PASSWORD 4u
/* with TO_PASSWORD: the password is the user's login password (PAM tries it) */
#define SEP_KEY_CHANGE_LOGIN_SAME  8u
#define SEP_KEY_CHANGE_SECRET_MAX 128

struct sep_key_change_secret {
  __u32 flags;      /* in: SEP_KEY_CHANGE_RANDOM and/or SEP_KEY_CHANGE_OLD */
  __s32 sep_status; /* out */
  __u32 old_len;    /* in: 1..SEP_KEY_CHANGE_SECRET_MAX with OLD, else 0 */
  __u32 new_len;    /* in: 1..SEP_KEY_CHANGE_SECRET_MAX, 0 with RANDOM */
  __u32 reserved[4]; /* in: 0 */
  __u8  old_secret[SEP_KEY_CHANGE_SECRET_MAX]; /* in, zeroed on the way out */
  __u8  new_secret[SEP_KEY_CHANGE_SECRET_MAX]; /* in, zeroed on the way out */
};

/*
 * Opens a password-mode bag with its password: the caller's own uid, or any
 * uid when the caller has CAP_SYS_ADMIN (a PAM module). The kernel keeps the
 * password while the bag is open, to load it again after a sleep; for uid
 * 1000 the Touch ID bring-up that waited for it runs. A wrong password is
 * EACCES with the enclave's status in sep_status (-5). EINVAL for a bag in
 * stored mode, ENOKEY with no bag. secret is zeroed on the way out.
 *
 * SEP_KEY_UNLOCK_LOGIN is PAM's try with the login password: ENOKEY without
 * a word to the enclave unless the bag is marked as having the login password
 * (no wrong attempt spent); a refusal clears that mark.
 * SEP_KEY_UNLOCK_SET_LOGIN_SAME sets the mark once the password opened the bag.
 */
#define SEP_KEY_UNLOCK_LOGIN          1u
#define SEP_KEY_UNLOCK_SET_LOGIN_SAME 2u

struct sep_key_unlock {
  __u32 flags;      /* in: SEP_KEY_UNLOCK_* */
  __u32 uid;        /* in: whose bag */
  __s32 sep_status; /* out */
  __u32 secret_len; /* in: 1..SEP_KEY_CHANGE_SECRET_MAX */
  __u32 reserved[4]; /* in: 0 */
  __u8  secret[SEP_KEY_CHANGE_SECRET_MAX]; /* in, zeroed on the way out */
};

/*
 * Closes a password-mode bag (the caller's own, or any with CAP_SYS_ADMIN):
 * the enclave locks it, the kernel forgets its password, its ops are ENOKEY
 * until SEP_KEY_UNLOCK (INFO: SEP_KEY_INFO_LOCKED). EINVAL in stored mode.
 */
struct sep_key_lock {
  __u32 flags;      /* in: 0 */
  __u32 uid;        /* in: whose bag */
  __u32 reserved[6]; /* in: 0 */
};

/*
 * A new home bag for the caller (uid 10 and up), made with the password
 * given: the enclave takes it at creation, so no other secret of the bag ever
 * exists. It is designated to -uid in place of the old bag (for uid 1000 the
 * fingers stay, and Touch ID, the per-op loads and the enrolment follow the
 * new bag), open, its record in password mode (with SEP_KEY_NEW_BAG_LOGIN_SAME
 * marked as the login password). The old bag is left as it is and its record
 * (no secret) kept as tanabota-sep-bag-<uid>.retired-<uuid8>.bin. Keys, EKs
 * and certificates of the old bag do not open in the new one: reissue them.
 * The current bag must be in password mode (EINVAL: a stored secret would
 * stay on disk) and open (ENOKEY). uuid: the new bag's, out. secret is zeroed
 * on the way out.
 */
#define SEP_KEY_NEW_BAG_LOGIN_SAME 1u

struct sep_key_new_bag {
  __u32 flags;      /* in: 0 or SEP_KEY_NEW_BAG_LOGIN_SAME */
  __s32 sep_status; /* out */
  __u32 secret_len; /* in: 1..SEP_KEY_CHANGE_SECRET_MAX */
  __u32 reserved[5]; /* in: 0 */
  __u8  uuid[16];   /* out */
  __u8  secret[SEP_KEY_CHANGE_SECRET_MAX]; /* in, zeroed on the way out */
};

/*
 * Bag management (interface 6). Each uid's records: its home bag
 * (tanabota-sep-bag-<uid>.bin), uid 1000's legacy own bag (.legacy.bin) and
 * the bags SEP_KEY_NEW_BAG or SEP_KEY_BAG_USE retired (.retired-<uuid8>.bin,
 * listed in tanabota-sep-bags-<uid>.idx). For the caller's uid, or any as root.
 *
 * SEP_KEY_BAG_LIST: up to SEP_KEY_BAGS_MAX entries: uuid, role
 * (SEP_KEY_BAG_HOME/LEGACY/RETIRED), flags: the record's mode
 * (SEP_KEY_BAG_PASSWORD, SEP_KEY_BAG_LOGIN_SAME) and, for what the kernel
 * holds, SEP_KEY_BAG_OPEN, SEP_KEY_BAG_DESIGNATED, SEP_KEY_BAG_LOADED.
 *
 * SEP_KEY_BAG_DELETE: a non-home bag's record goes (one holding a secret,
 * a stored-mode legacy record, is overwritten with zeros first). EBUSY for
 * the home bag, ENOENT for an unknown uuid. Keys made in it are gone.
 *
 * SEP_KEY_BAG_USE: a retired password-mode bag is the home bag again (the
 * rollback of SEP_KEY_NEW_BAG), opened with its password: a wrong one is
 * EACCES with sep_status -5 and nothing changes. The current home bag is
 * retired in its place. A stored-mode target (a legacy bag) is EINVAL: the
 * home bag stays in password mode. secret is zeroed on the way out.
 */
#define SEP_KEY_BAGS_MAX 16
#define SEP_KEY_BAG_HOME    1
#define SEP_KEY_BAG_LEGACY  2
#define SEP_KEY_BAG_RETIRED 3
#define SEP_KEY_BAG_PASSWORD   0x004u
#define SEP_KEY_BAG_LOGIN_SAME 0x008u
#define SEP_KEY_BAG_OPEN       0x100u
#define SEP_KEY_BAG_DESIGNATED 0x200u
#define SEP_KEY_BAG_LOADED     0x400u

struct sep_key_bag_entry {
  __u8  uuid[16];
  __u32 role;
  __u32 flags;
};

struct sep_key_bag_list {
  __u32 uid;        /* in */
  __u32 count;      /* out */
  __u32 reserved[6]; /* in: 0 */
  struct sep_key_bag_entry bags[SEP_KEY_BAGS_MAX]; /* out */
};

struct sep_key_bag_delete {
  __u32 flags;      /* in: 0 */
  __u32 uid;        /* in */
  __u32 reserved[6]; /* in: 0 */
  __u8  uuid[16];   /* in */
};

struct sep_key_bag_use {
  __u32 flags;      /* in: 0 */
  __u32 uid;        /* in */
  __s32 sep_status; /* out */
  __u32 secret_len; /* in: 1..SEP_KEY_CHANGE_SECRET_MAX */
  __u32 reserved[4]; /* in: 0 */
  __u8  uuid[16];   /* in */
  __u8  secret[SEP_KEY_CHANGE_SECRET_MAX]; /* in, zeroed on the way out */
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
#define SEP_KEY_ATTEST      _IOWR(SEP_KEY_IOC_MAGIC, 0x09, struct sep_key_attest)
#define SEP_KEY_CHANGE_SECRET _IOWR(SEP_KEY_IOC_MAGIC, 0x0a, struct sep_key_change_secret)
#define SEP_KEY_UNLOCK      _IOWR(SEP_KEY_IOC_MAGIC, 0x0b, struct sep_key_unlock)
#define SEP_KEY_LOCK        _IOW (SEP_KEY_IOC_MAGIC, 0x0c, struct sep_key_lock)
#define SEP_KEY_NEW_BAG     _IOWR(SEP_KEY_IOC_MAGIC, 0x0d, struct sep_key_new_bag)
#define SEP_KEY_BAG_LIST    _IOWR(SEP_KEY_IOC_MAGIC, 0x0e, struct sep_key_bag_list)
#define SEP_KEY_BAG_DELETE  _IOW (SEP_KEY_IOC_MAGIC, 0x0f, struct sep_key_bag_delete)
#define SEP_KEY_BAG_USE     _IOWR(SEP_KEY_IOC_MAGIC, 0x10, struct sep_key_bag_use)
