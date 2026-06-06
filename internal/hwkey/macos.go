//go:build darwin && cgo

package hwkey

/*
#cgo CFLAGS: -x objective-c -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework Foundation

#include <stdlib.h>
#include <string.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

// ---- Internal helpers -----------------------------------------------------

// Caller frees with free().
static char *cfStringToC(CFStringRef s) {
    if (s == NULL) return strdup("(null)");
    CFIndex len = CFStringGetLength(s);
    CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    char *buf = (char *)malloc(max);
    if (!buf) return NULL;
    if (!CFStringGetCString(s, buf, max, kCFStringEncodingUTF8)) {
        strncpy(buf, "(unrepresentable)", max - 1);
        buf[max - 1] = '\0';
    }
    return buf;
}

// Caller frees with free().
static char *cfErrorToC(CFErrorRef err) {
    if (err == NULL) return strdup("(no error)");
    CFStringRef desc = CFErrorCopyDescription(err);
    char *out = cfStringToC(desc);
    if (desc) CFRelease(desc);
    return out;
}

// Build a CFData from a Go byte slice copy.
static CFDataRef makeCFData(const void *bytes, int len) {
    return CFDataCreate(NULL, (const UInt8 *)bytes, (CFIndex)len);
}

// Build the tag CFData from a NUL-terminated C string.
static CFDataRef makeTag(const char *tag) {
    return CFDataCreate(NULL, (const UInt8 *)tag, (CFIndex)strlen(tag));
}

// ---- Query: does a key with this tag exist? ------------------------------
// Returns 1 if found, 0 if not, -1 on real error (err_out set, caller frees).
static int seFindPrivateKey(const char *tag, SecKeyRef *out, char **err_out) {
    *out = NULL;
    *err_out = NULL;

    CFDataRef tagData = makeTag(tag);
    const void *keys[] = {
        kSecClass,
        kSecAttrApplicationTag,
        kSecAttrKeyType,
        kSecReturnRef,
    };
    const void *values[] = {
        kSecClassKey,
        tagData,
        kSecAttrKeyTypeECSECPrimeRandom,
        kCFBooleanTrue,
    };
    CFDictionaryRef query = CFDictionaryCreate(
        NULL, keys, values, 4,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFRelease(tagData);

    CFTypeRef ref = NULL;
    OSStatus status = SecItemCopyMatching(query, &ref);
    CFRelease(query);

    if (status == errSecSuccess) {
        *out = (SecKeyRef)ref;
        return 1;
    }
    if (status == errSecItemNotFound) {
        return 0;
    }
    // Some other failure (missing entitlement, etc.).
    char buf[64];
    snprintf(buf, sizeof(buf), "SecItemCopyMatching OSStatus %d", (int)status);
    *err_out = strdup(buf);
    return -1;
}

// ---- Create a fresh Secure Enclave key -----------------------------------
// Returns 0 on success, sets err_out (caller frees) on failure.
static int seCreateKey(const char *tag, char **err_out) {
    *err_out = NULL;

    CFErrorRef cfErr = NULL;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(
        NULL,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        &cfErr);
    if (ac == NULL) {
        *err_out = cfErrorToC(cfErr);
        if (cfErr) CFRelease(cfErr);
        return -1;
    }

    CFDataRef tagData = makeTag(tag);

    const void *privKeys[] = {
        kSecAttrIsPermanent,
        kSecAttrApplicationTag,
        kSecAttrAccessControl,
    };
    const void *privValues[] = {
        kCFBooleanTrue,
        tagData,
        ac,
    };
    CFDictionaryRef privAttrs = CFDictionaryCreate(
        NULL, privKeys, privValues, 3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    int keySize = 256;
    CFNumberRef keySizeNum = CFNumberCreate(NULL, kCFNumberIntType, &keySize);

    const void *keys[] = {
        kSecAttrKeyType,
        kSecAttrKeySizeInBits,
        kSecAttrTokenID,
        kSecPrivateKeyAttrs,
    };
    const void *values[] = {
        kSecAttrKeyTypeECSECPrimeRandom,
        keySizeNum,
        kSecAttrTokenIDSecureEnclave,
        privAttrs,
    };
    CFDictionaryRef attrs = CFDictionaryCreate(
        NULL, keys, values, 4,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    SecKeyRef key = SecKeyCreateRandomKey(attrs, &cfErr);

    CFRelease(attrs);
    CFRelease(keySizeNum);
    CFRelease(privAttrs);
    CFRelease(tagData);
    CFRelease(ac);

    if (key == NULL) {
        *err_out = cfErrorToC(cfErr);
        if (cfErr) CFRelease(cfErr);
        return -1;
    }
    CFRelease(key);
    return 0;
}

// ---- Encrypt with the SE key's public key --------------------------------
// On success, *out is a CFDataRef the caller must CFRelease. On failure,
// err_out is set (caller frees).
static int seEncrypt(SecKeyRef priv, const void *plain, int plainLen, CFDataRef *out, char **err_out) {
    *out = NULL;
    *err_out = NULL;

    SecKeyRef pub = SecKeyCopyPublicKey(priv);
    if (pub == NULL) {
        *err_out = strdup("SecKeyCopyPublicKey returned NULL");
        return -1;
    }

    SecKeyAlgorithm alg = kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM;
    if (!SecKeyIsAlgorithmSupported(pub, kSecKeyOperationTypeEncrypt, alg)) {
        CFRelease(pub);
        *err_out = strdup("SE pub key does not support ECIES standard X9.63 SHA256 AES-GCM");
        return -1;
    }

    CFDataRef plainData = makeCFData(plain, plainLen);
    CFErrorRef cfErr = NULL;
    CFDataRef ct = SecKeyCreateEncryptedData(pub, alg, plainData, &cfErr);
    CFRelease(plainData);
    CFRelease(pub);

    if (ct == NULL) {
        *err_out = cfErrorToC(cfErr);
        if (cfErr) CFRelease(cfErr);
        return -1;
    }
    *out = ct;
    return 0;
}

// ---- Decrypt with the SE private key -------------------------------------
static int seDecrypt(SecKeyRef priv, const void *ct, int ctLen, CFDataRef *out, char **err_out) {
    *out = NULL;
    *err_out = NULL;

    SecKeyAlgorithm alg = kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM;
    if (!SecKeyIsAlgorithmSupported(priv, kSecKeyOperationTypeDecrypt, alg)) {
        *err_out = strdup("SE priv key does not support ECIES decrypt");
        return -1;
    }

    CFDataRef ctData = makeCFData(ct, ctLen);
    CFErrorRef cfErr = NULL;
    CFDataRef pt = SecKeyCreateDecryptedData(priv, alg, ctData, &cfErr);
    CFRelease(ctData);

    if (pt == NULL) {
        *err_out = cfErrorToC(cfErr);
        if (cfErr) CFRelease(cfErr);
        return -1;
    }
    *out = pt;
    return 0;
}

// ---- Delete the key from the keychain ------------------------------------
// Returns 0 on success, errSecItemNotFound when not present, -1 + err_out on
// other failures.
static int seDeleteKey(const char *tag, char **err_out) {
    *err_out = NULL;

    CFDataRef tagData = makeTag(tag);
    const void *keys[] = {
        kSecClass,
        kSecAttrApplicationTag,
        kSecAttrKeyType,
    };
    const void *values[] = {
        kSecClassKey,
        tagData,
        kSecAttrKeyTypeECSECPrimeRandom,
    };
    CFDictionaryRef query = CFDictionaryCreate(
        NULL, keys, values, 3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFRelease(tagData);

    OSStatus status = SecItemDelete(query);
    CFRelease(query);

    if (status == errSecSuccess) return 0;
    if (status == errSecItemNotFound) return (int)status;
    char buf[64];
    snprintf(buf, sizeof(buf), "SecItemDelete OSStatus %d", (int)status);
    *err_out = strdup(buf);
    return -1;
}

// Convenience: copy bytes out of a CFDataRef and release it.
static void cfDataCopyAndRelease(CFDataRef d, void *dst, int dstLen) {
    if (d == NULL) return;
    CFIndex have = CFDataGetLength(d);
    CFIndex n = have < (CFIndex)dstLen ? have : (CFIndex)dstLen;
    memcpy(dst, CFDataGetBytePtr(d), n);
    CFRelease(d);
}

static int cfDataLen(CFDataRef d) { return d == NULL ? 0 : (int)CFDataGetLength(d); }

static void releaseKey(SecKeyRef k) { if (k) CFRelease(k); }
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// MacOS is a Secure Enclave-backed Provider for macOS.
//
// The wrapping key is an EC P-256 keypair created in the Secure Enclave
// with kSecAttrTokenIDSecureEnclave. The private key is non-extractable
// and persists in the keychain under kSecAttrApplicationTag = handle.
//
// Wrap uses kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM
// against the SE public key (extracted with SecKeyCopyPublicKey).
// Unwrap calls the same algorithm on the private key, which triggers
// the SE.
//
// Access control: kSecAccessControlPrivateKeyUsage, no biometric.
// Biometric step-up is layered in Slice 1.3 via a separate auth.Unlocker.
type MacOS struct {
	handle string // becomes kSecAttrApplicationTag

	availOnce sync.Once
	avail     bool
}

// NewMacOS returns a Secure Enclave provider for the given handle. The
// handle is used as the keychain item tag; choose a stable
// reverse-DNS-style identifier (e.g. "com.byn.vault.wrappingkey").
func NewMacOS(handle string) *MacOS {
	return &MacOS{handle: handle}
}

// Name implements Provider.
func (m *MacOS) Name() string { return "macos-secure-enclave" }

// Available reports whether a Secure Enclave is usable on this host.
// On error or absent hardware this returns false; CreateOrLoad will
// return ErrProviderUnavailable.
//
// The probe is cheap (no keychain mutation) and is cached after the
// first call.
func (m *MacOS) Available() bool {
	m.availOnce.Do(func() {
		m.avail = probeSecureEnclaveAvailable()
	})
	return m.avail
}

// CreateOrLoad implements Provider. Idempotent.
func (m *MacOS) CreateOrLoad() error {
	if !m.Available() {
		return ErrProviderUnavailable
	}
	exists, err := m.exists()
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	cTag := C.CString(m.handle)
	defer C.free(unsafe.Pointer(cTag))

	var cErr *C.char
	rc := C.seCreateKey(cTag, &cErr)
	if rc != 0 {
		msg := goStringAndFree(cErr)
		return fmt.Errorf("hwkey/macos: SecKeyCreateRandomKey: %s", msg)
	}
	return nil
}

// Wrap implements Provider.
func (m *MacOS) Wrap(plaintext []byte) ([]byte, error) {
	priv, err := m.copyPrivateKey()
	if err != nil {
		return nil, err
	}
	defer C.releaseKey(priv)

	// SecKeyCreateEncryptedData rejects zero-length inputs for ECIES,
	// so guard explicitly.
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("hwkey/macos: Wrap empty plaintext not supported by ECIES")
	}

	var ct C.CFDataRef
	var cErr *C.char
	rc := C.seEncrypt(priv, unsafe.Pointer(&plaintext[0]), C.int(len(plaintext)), &ct, &cErr)
	if rc != 0 {
		msg := goStringAndFree(cErr)
		return nil, fmt.Errorf("hwkey/macos: SecKeyCreateEncryptedData: %s", msg)
	}

	n := int(C.cfDataLen(ct))
	out := make([]byte, n)
	if n > 0 {
		C.cfDataCopyAndRelease(ct, unsafe.Pointer(&out[0]), C.int(n))
	}
	return out, nil
}

// Unwrap implements Provider.
func (m *MacOS) Unwrap(ciphertext []byte) ([]byte, error) {
	priv, err := m.copyPrivateKey()
	if err != nil {
		return nil, err
	}
	defer C.releaseKey(priv)

	if len(ciphertext) == 0 {
		return nil, ErrUnwrap
	}
	var pt C.CFDataRef
	var cErr *C.char
	rc := C.seDecrypt(priv, unsafe.Pointer(&ciphertext[0]), C.int(len(ciphertext)), &pt, &cErr)
	if rc != 0 {
		// SE returns rich error strings; we collapse to ErrUnwrap to
		// avoid leaking which check failed.
		_ = goStringAndFree(cErr)
		return nil, ErrUnwrap
	}
	n := int(C.cfDataLen(pt))
	out := make([]byte, n)
	if n > 0 {
		C.cfDataCopyAndRelease(pt, unsafe.Pointer(&out[0]), C.int(n))
	}
	return out, nil
}

// Erase implements Provider.
func (m *MacOS) Erase() error {
	if !m.Available() {
		return ErrProviderUnavailable
	}
	cTag := C.CString(m.handle)
	defer C.free(unsafe.Pointer(cTag))

	var cErr *C.char
	rc := C.seDeleteKey(cTag, &cErr)
	if rc == 0 {
		return nil
	}
	if rc == C.errSecItemNotFound {
		return ErrKeyNotFound
	}
	msg := goStringAndFree(cErr)
	return fmt.Errorf("hwkey/macos: SecItemDelete: %s", msg)
}

// exists checks whether the SE key with this handle is present.
func (m *MacOS) exists() (bool, error) {
	cTag := C.CString(m.handle)
	defer C.free(unsafe.Pointer(cTag))

	var priv C.SecKeyRef
	var cErr *C.char
	rc := C.seFindPrivateKey(cTag, &priv, &cErr)
	if priv != 0 {
		C.releaseKey(priv)
	}
	switch rc {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		msg := goStringAndFree(cErr)
		return false, fmt.Errorf("hwkey/macos: find key: %s", msg)
	}
}

// copyPrivateKey returns a +1-retained SecKeyRef the caller must
// release.
func (m *MacOS) copyPrivateKey() (C.SecKeyRef, error) {
	cTag := C.CString(m.handle)
	defer C.free(unsafe.Pointer(cTag))

	var priv C.SecKeyRef
	var cErr *C.char
	rc := C.seFindPrivateKey(cTag, &priv, &cErr)
	switch rc {
	case 1:
		return priv, nil
	case 0:
		return 0, ErrKeyNotFound
	default:
		msg := goStringAndFree(cErr)
		return 0, fmt.Errorf("hwkey/macos: find key: %s", msg)
	}
}

func goStringAndFree(c *C.char) string {
	if c == nil {
		return ""
	}
	s := C.GoString(c)
	C.free(unsafe.Pointer(c))
	return s
}

// probeSecureEnclaveAvailable attempts to detect whether an SE-backed
// key can be created. We try a one-off creation with a throwaway tag
// inside a non-persistent context to avoid keychain pollution — but
// SecKeyCreateRandomKey for SE requires kSecAttrIsPermanent=true, so
// the cheapest reliable probe is to query for any key with our tag.
// If that succeeds (success or not-found), we treat the SE API surface
// as available; if it errors with a missing-entitlement OSStatus, we
// treat the provider as unavailable.
//
// In practice the Slice 1.1 daemon will be unsigned during dev — SE
// access may fail with errSecMissingEntitlement on some macOS
// configurations. CreateOrLoad surfaces the underlying error in that
// case.
func probeSecureEnclaveAvailable() bool {
	const probeTag = "com.byn.hwkey.probe"
	cTag := C.CString(probeTag)
	defer C.free(unsafe.Pointer(cTag))

	var priv C.SecKeyRef
	var cErr *C.char
	rc := C.seFindPrivateKey(cTag, &priv, &cErr)
	if priv != 0 {
		C.releaseKey(priv)
	}
	if cErr != nil {
		C.free(unsafe.Pointer(cErr))
	}
	// rc 0 (not found) or 1 (found) both mean the API surface works.
	return rc >= 0
}
