// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package cslsffi

/*
#cgo CFLAGS: -I${SRCDIR}/../../../src
#cgo LDFLAGS: -L${SRCDIR}/../../.. -l:libcausal_slash.a -lcrypto
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "causal_daemon.h"

static int csls_derive_keypair_c(const uint8_t *sk, uint8_t *pk_compressed, uint8_t *pk_uncompressed) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_sk = BN_bin2bn(sk, 32, NULL);
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT *pt = EC_POINT_new(group);
    if (!ctx || !bn_sk || !group || !pt) {
        if (pt) EC_POINT_free(pt);
        if (group) EC_GROUP_free(group);
        if (bn_sk) BN_free(bn_sk);
        if (ctx) BN_CTX_free(ctx);
        return -1;
    }
    int ret = -1;
    if (EC_POINT_mul(group, pt, bn_sk, NULL, NULL, ctx) == 1) {
        size_t c_len = EC_POINT_point2oct(group, pt, POINT_CONVERSION_COMPRESSED, pk_compressed, 33, ctx);
        size_t u_len = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED, pk_uncompressed, 65, ctx);
        if (c_len == 33 && u_len == 65) {
            ret = 0;
        }
    }
    EC_POINT_free(pt);
    EC_GROUP_free(group);
    BN_free(bn_sk);
    BN_CTX_free(ctx);
    return ret;
}

static uint64_t csls_pkt_height(const csls_cheque_pkt_t *p) {
    return p->height;
}
*/
import "C"
import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

var (
	initOnce sync.Once
	initErr  error
)

// EnsureCryptoInit initializes the global OpenSSL/Causal crypto state once.
func EnsureCryptoInit() error {
	initOnce.Do(func() {
		if rc := C.csls_crypto_global_init(); rc != 0 {
			initErr = fmt.Errorf("csls_crypto_global_init failed with code %d", rc)
		}
	})
	return initErr
}

// DeriveKeypair computes the compressed (33 bytes) and uncompressed (65 bytes)
// public keys from a 32-byte secp256k1 secret key.
func DeriveKeypair(sk []byte) (pkComp []byte, pkUncomp []byte, err error) {
	if len(sk) != 32 {
		return nil, nil, errors.New("secret key must be 32 bytes")
	}
	if err := EnsureCryptoInit(); err != nil {
		return nil, nil, err
	}
	comp := make([]byte, 33)
	uncomp := make([]byte, 65)
	rc := C.csls_derive_keypair_c(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&comp[0])),
		(*C.uint8_t)(unsafe.Pointer(&uncomp[0])),
	)
	if rc != 0 {
		return nil, nil, errors.New("secp256k1 key derivation failed")
	}
	return comp, uncomp, nil
}

// Agent wraps the native C11 csls_agent_ctx_t.
type Agent struct {
	ctx *C.csls_agent_ctx_t
	mu  sync.Mutex
}

// NewAgent instantiates a sovereign C11 Agent context for signing cheques.
func NewAgent(sk []byte, walPath string) (*Agent, error) {
	if len(sk) != 32 {
		return nil, errors.New("secret key must be 32 bytes")
	}
	if err := EnsureCryptoInit(); err != nil {
		return nil, err
	}
	var cWal *C.char
	if walPath != "" {
		cWal = C.CString(walPath)
		defer C.free(unsafe.Pointer(cWal))
	}
	ctx := C.csls_agent_new((*C.uint8_t)(unsafe.Pointer(&sk[0])), cWal)
	if ctx == nil {
		return nil, errors.New("csls_agent_new returned NULL")
	}
	return &Agent{ctx: ctx}, nil
}

// Close destroys the underlying C11 agent and cleans up memory.
func (a *Agent) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx != nil {
		C.csls_agent_free(a.ctx)
		a.ctx = nil
	}
}

// SessionBegin initiates a Session MAC handshake with the given vendor public key.
// Returns the 95-byte session_init packet to be POSTed to /v1/session/init.
func (a *Agent) SessionBegin(vendorPK []byte) ([]byte, error) {
	if len(vendorPK) != 33 {
		return nil, errors.New("vendor public key must be 33 bytes compressed")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx == nil {
		return nil, errors.New("agent is closed")
	}

	var initPkt C.csls_session_init_pkt_t
	rc := C.csls_agent_session_begin(
		a.ctx,
		(*C.uint8_t)(unsafe.Pointer(&vendorPK[0])),
		&initPkt,
	)
	if rc != 0 {
		return nil, fmt.Errorf("csls_agent_session_begin failed with code %d", rc)
	}

	out := C.GoBytes(unsafe.Pointer(&initPkt), 95)
	return out, nil
}

// SignChequeMAC signs a 167-byte Session MAC micro-cheque for deltaMicro USDC.
// Returns wire bytes (151-byte cheque + 16-byte SipHash MAC) and the height counter.
func (a *Agent) SignChequeMAC(vendorPK []byte, deltaMicro uint64) ([]byte, uint64, error) {
	if len(vendorPK) != 33 {
		return nil, 0, errors.New("vendor public key must be 33 bytes compressed")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx == nil {
		return nil, 0, errors.New("agent is closed")
	}

	var pkt C.csls_cheque_pkt_t
	var mac [16]C.uint8_t

	rc := C.csls_agent_sign_cheque_mac(
		a.ctx,
		(*C.uint8_t)(unsafe.Pointer(&vendorPK[0])),
		C.uint64_t(deltaMicro),
		&pkt,
		&mac[0],
	)
	if rc != 0 {
		return nil, 0, fmt.Errorf("csls_agent_sign_cheque_mac failed with code %d", rc)
	}

	wire := make([]byte, 167)
	pktBytes := C.GoBytes(unsafe.Pointer(&pkt), C.int(unsafe.Sizeof(pkt)))
	macBytes := C.GoBytes(unsafe.Pointer(&mac[0]), 16)
	copy(wire[:151], pktBytes)
	copy(wire[151:], macBytes)

	height := uint64(C.csls_pkt_height(&pkt))
	return wire, height, nil
}

// GenerateRandomKey generates 32 cryptographically secure random bytes for secp256k1.
func GenerateRandomKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// HexToBytes decodes a hex string (ignoring optional 0x prefix).
func HexToBytes(s string) ([]byte, error) {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	return hex.DecodeString(s)
}

// RunEquivocationTest executes the native C11 Schnorr EOTS equivocation detection and key extraction test.
func RunEquivocationTest() (int, error) {
	if err := EnsureCryptoInit(); err != nil {
		return -1, err
	}
	rc := int(C.csls_run_equivocation_test())
	return rc, nil
}

// RunEquivocationSimulation executes native C11 equivocation test while safely capturing stdout.
func RunEquivocationSimulation() (string, int, error) {
	if err := EnsureCryptoInit(); err != nil {
		return "", -1, err
	}

	r, w, err := os.Pipe()
	if err != nil {
		rc := int(C.csls_run_equivocation_test())
		return "", rc, nil
	}

	stdoutFd := int(os.Stdout.Fd())
	savedStdout, err := syscall.Dup(stdoutFd)
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		rc := int(C.csls_run_equivocation_test())
		return "", rc, nil
	}

	_ = syscall.Dup2(int(w.Fd()), stdoutFd)

	rc := int(C.csls_run_equivocation_test())
	C.fflush(nil)

	_ = w.Close()
	_ = syscall.Dup2(savedStdout, stdoutFd)
	_ = syscall.Close(savedStdout)

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()

	return buf.String(), rc, nil
}

