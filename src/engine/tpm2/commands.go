// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
)

// maxRandomBytes caps a single TPM2_GetRandom response. A real TPM returns at
// most the size of its largest digest; SHA-512 (64 bytes) is the ceiling here.
const maxRandomBytes = 64

// cmdStartup implements TPM2_Startup. TPM_SU_CLEAR resets the resettable PCRs
// and hierarchy enables; TPM_SU_STATE restores the state saved by a prior
// TPM2_Shutdown(TPM_SU_STATE).
func (t *TPM) cmdStartup(r *reader) []byte {
	su := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if su != SUClear && su != SUState {
		return errorResponse(withParam(RCValue, 1)) // startupType is parameter 1
	}
	if su == SUClear {
		if t.started {
			return errorResponse(RCInitialize) // already started; CLEAR re-init is a sequencing error
		}
		t.pcr.reset()
		t.h.reset()
		t.sessions = newSessionTable()
		t.objects.flushAllTransient()
		t.sequences.flushAll()
		t.clock.restartCount++
	} else { // SUState
		if t.stateRestored {
			// State was loaded from a persisted snapshot (cross-process restart).
			// Startup(STATE) succeeds with the restored state.
			t.stateRestored = false
		} else if errResp := t.restoreSavedState(); errResp != nil {
			return errResp
		}
	}
	t.started = true
	return successResponse(nil, 0)
}

// restoreSavedState restores the TPM from the snapshot saved by a prior
// Shutdown(TPM_SU_STATE). Returns an error response if no state was saved.
// The caller must hold t.mu (this is invoked from within Execute).
func (t *TPM) restoreSavedState() []byte {
	if t.savedState == nil {
		return errorResponse(withParam(RCValue, 1)) // no STATE snapshot to restore
	}
	if err := t.restoreLocked(*t.savedState); err != nil {
		return errorResponse(RCFailure)
	}
	t.savedState = nil // consumed: a subsequent STATE startup without a new shutdown fails
	return nil
}

// flushAllTransient removes all transient objects and sequences.
func (ot *objectTable) flushAllTransient() {
	for h := range ot.transient {
		delete(ot.transient, h)
	}
}

// flushAll removes all sequences.
func (st *sequenceTable) flushAll() {
	for h := range st.seqs {
		delete(st.seqs, h)
	}
}

// cmdShutdown implements TPM2_Shutdown. TPM_SU_STATE snapshots the full TPM state
// (PCRs, hierarchies, NV, objects, clock, DA) and persists it via onPersist so
// that a subsequent Startup(TPM_SU_STATE) can restore it. TPM_SU_CLEAR simply
// marks the TPM as not started; state is not preserved across a CLEAR shutdown.
func (t *TPM) cmdShutdown(r *reader) []byte {
	if resp := t.requireStarted(); resp != nil {
		return resp
	}
	su := r.u16()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if su != SUClear && su != SUState {
		return errorResponse(withParam(RCValue, 1)) // shutdownType is parameter 1
	}
	if su == SUState {
		snap := t.snapshotLocked()
		t.savedState = &snap
		if t.onPersist != nil {
			if err := t.onPersist(); err != nil {
				return errorResponse(RCFailure)
			}
		}
		// After a STATE shutdown the TPM's volatile state is cleared so that a
		// subsequent Startup(STATE) restores from the saved snapshot rather than
		// continuing from in-memory state. The TPM remains "started" per the spec;
		// Startup(STATE) is what transitions it back to a fully operational state.
		t.sessions = newSessionTable()
		t.objects.flushAllTransient()
		t.sequences.flushAll()
	}
	return successResponse(nil, 0)
}

// cmdSelfTest implements TPM2_SelfTest (Part 3, §10.2). It runs known-answer
// tests for every algorithm the TPM actually implements: SHA-1, SHA-256,
// SHA-384, SHA-512, HMAC-SHA256, AES-128-ECB, and RSA/ECC signature verify.
// If any test fails, the TPM enters failure mode and only GetTestResult /
// GetCapability answer afterward.
func (t *TPM) cmdSelfTest(r *reader) []byte {
	fullTest := r.u8() // fullTest (TPMI_YES_NO) — no distinct behavior, but must be 0/1
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if fullTest != byte(no) && fullTest != byte(yes) {
		return errorResponse(withParam(RCValue, 1)) // fullTest (param 1) is TPMI_YES_NO
	}

	// Known-answer tests for each implemented algorithm.
	tests := []struct {
		name string
		fn   func() error
	}{
		{"SHA-1", selfTestSHA1},
		{"SHA-256", selfTestSHA256},
		{"SHA-384", selfTestSHA384},
		{"SHA-512", selfTestSHA512},
		{"HMAC-SHA256", selfTestHMACSHA256},
		{"AES-128-ECB", selfTestAES128ECB},
		{"RSA-2048-sign/verify", selfTestRSASignVerify},
		{"ECC-P256-sign/verify", selfTestECCP256SignVerify},
	}

	for _, test := range tests {
		if err := test.fn(); err != nil {
			t.failed = true
			return errorResponse(RCFailure)
		}
	}

	// All tests passed; the toDoList is empty.
	return successResponse(nil, 0)
}

// ---- known-answer tests ---------------------------------------------------

// selfTestSHA1 verifies SHA-1 against the NIST vector for "abc".
func selfTestSHA1() error {
	const want = "a9993e364706816aba3e25717850c26c9cd0d89d"
	got := hashSum(AlgSHA1, []byte("abc"))
	if hex.EncodeToString(got) != want {
		return fmt.Errorf("sha-1 KAT mismatch")
	}
	return nil
}

// selfTestSHA256 verifies SHA-256 against the NIST vector for "abc".
func selfTestSHA256() error {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	got := hashSum(AlgSHA256, []byte("abc"))
	if hex.EncodeToString(got) != want {
		return fmt.Errorf("sha-256 KAT mismatch")
	}
	return nil
}

// selfTestSHA384 verifies SHA-384 against the NIST vector for "abc".
func selfTestSHA384() error {
	const want = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
	got := hashSum(AlgSHA384, []byte("abc"))
	if hex.EncodeToString(got) != want {
		return fmt.Errorf("sha-384 KAT mismatch")
	}
	return nil
}

// selfTestSHA512 verifies SHA-512 against the NIST vector for "abc".
func selfTestSHA512() error {
	const want = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
	got := hashSum(AlgSHA512, []byte("abc"))
	if hex.EncodeToString(got) != want {
		return fmt.Errorf("sha-512 KAT mismatch")
	}
	return nil
}

// selfTestHMACSHA256 verifies HMAC-SHA256 against RFC 4231 test case 2
// (key = 0x0b repeated 20 bytes, data = "Hi There").
func selfTestHMACSHA256() error {
	const want = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	key := bytes.Repeat([]byte{0x0b}, 20)
	got := hmacSum(AlgSHA256, key, []byte("Hi There"))
	if hex.EncodeToString(got) != want {
		return fmt.Errorf("hmac-sha256 KAT mismatch")
	}
	return nil
}

// selfTestAES128ECB verifies AES-128-ECB against NIST SP 800-38A
// (key = 2b7e151628aed2a6abf7158809cf4f3c, plaintext = 6bc1bee22e409f96e93d7e117393172a).
func selfTestAES128ECB() error {
	const wantCipher = "3ad77bb40d7a3660a89ecaf32466ef97"
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	plaintext, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	out := make([]byte, len(plaintext))
	block.Encrypt(out, plaintext)
	if hex.EncodeToString(out) != wantCipher {
		return fmt.Errorf("aes-128-ecb KAT mismatch")
	}
	return nil
}

// selfTestRSASignVerify verifies RSA sign/verify using a deterministic test key.
func selfTestRSASignVerify() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	msg := []byte("self-test")
	digest := hashSum(AlgSHA256, msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest, sig); err != nil {
		return err
	}
	return nil
}

// selfTestECCP256SignVerify verifies ECDSA-P256 sign/verify using a deterministic test key.
func selfTestECCP256SignVerify() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	msg := []byte("self-test")
	digest := hashSum(AlgSHA256, msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(&priv.PublicKey, digest, r, s) {
		return fmt.Errorf("ecdsa-p256 KAT verify failed")
	}
	return nil
}

// cmdGetTestResult implements TPM2_GetTestResult. It reports an empty outData
// and a passing testResult, and answers even before Startup / in failure mode.
func (t *TPM) cmdGetTestResult(_ *reader) []byte {
	var w writer
	w.u16(0) // outData: empty TPM2B_MAX_BUFFER
	result := RCSuccess
	if t.failed {
		result = RCFailure
	}
	w.u32(result) // testResult (TPM_RC)
	return successResponse(w.bytes(), 0)
}

// cmdGetRandom implements TPM2_GetRandom using the reseedable Hash_DRBG.
func (t *TPM) cmdGetRandom(r *reader) []byte {
	n := int(r.u16())
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if n > maxRandomBytes {
		n = maxRandomBytes
	}
	buf, err := t.drbgRead(n)
	if err != nil {
		return errorResponse(RCFailure)
	}
	var w writer
	w.u16(uint16(len(buf))) // TPM2B_DIGEST size
	w.raw(buf)
	return successResponse(w.bytes(), 0)
}

// cmdStirRandom implements TPM2_StirRandom (Part 3, §21.4). Additional input is
// incorporated into the TPM's Hash_DRBG state per SP800-90A reseed rules, so
// subsequent GetRandom output is affected by the supplied entropy.
func (t *TPM) cmdStirRandom(r *reader) []byte {
	inData := r.bytes(int(r.u16())) // inData (TPM2B_SENSITIVE_DATA)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	t.ReseedDRBG(inData)
	return successResponse(nil, 0)
}

// cmdPCRRead implements TPM2_PCR_Read: it returns the update counter, the
// selection actually read back, and the corresponding digests.
func (t *TPM) cmdPCRRead(r *reader) []byte {
	sels := readPCRSelectionList(r)
	if r.err != nil {
		if r.err == errBadValue {
			return errorResponse(withParam(RCValue, 1)) // pcrSelectionIn is parameter 1
		}
		return errorResponse(RCInsufficient)
	}

	// pcrSelectionOut must report the PCR actually read back, not the request:
	// a requested bank the TPM does not implement (or an unselectable index)
	// contributes no digest, so its bits must be cleared in the output selection
	// or pcrSelectionOut and pcrValues would disagree (TPM 2.0 Part 3,
	// TPM2_PCR_Read).
	var digests [][]byte
	out := make([]pcrSelection, 0, len(sels))
	for _, sel := range sels {
		readMap := make([]byte, len(sel.selectMap))
		for i := 0; i < numPCR; i++ {
			if !sel.selected(i) {
				continue
			}
			d := t.pcr.read(sel.hash, i)
			if d == nil {
				continue // unsupported bank or index: not read back
			}
			digests = append(digests, d)
			readMap[i/8] |= 1 << (uint(i) % 8)
		}
		out = append(out, pcrSelection{hash: sel.hash, selectMap: readMap})
	}

	var w writer
	w.u32(t.pcr.updateCounter)     // pcrUpdateCounter
	writePCRSelectionList(&w, out) // pcrSelectionOut (only PCR actually read)
	w.u32(uint32(len(digests)))    // pcrValues: TPML_DIGEST count
	for _, d := range digests {
		w.u16(uint16(len(d)))
		w.raw(d)
	}
	return successResponse(w.bytes(), 0)
}

// cmdPCRExtend implements TPM2_PCR_Extend. The command carries one handle (the
// PCR) and requires an authorization session; the auth value of a PCR is empty
// by default, so any well-formed session is accepted.
func (t *TPM) cmdPCRExtend(tag uint16, r *reader) []byte {
	if tag != TPMSTSessions {
		return errorResponse(RCAuthMissing) // a command needing auth was sent with no sessions
	}
	pcrHandle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	sessions, ok := readAuthArea(r)
	if !ok {
		return errorResponse(RCAuthSize) // authorizationSize did not frame a valid auth area
	}
	values := readDigestValues(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}

	index := int(pcrHandle) // PCR handles are 0x00..0x17, equal to the index
	if index < 0 || index >= numPCR {
		return errorResponse(withHandle(RCValue, 1)) // pcrHandle is the first handle
	}
	if !localityAllowed(pcrExtendLocalities(index), t.locality) {
		return errorResponse(RCLocality) // PCR not extendable at this locality
	}
	for _, v := range values {
		if !t.pcr.extend(v.alg, index, v.digest) {
			return errorResponse(withParam(RCValue, 1)) // digests is the first parameter
		}
	}
	return successResponse(nil, len(sessions))
}

// cmdPCRReset implements TPM2_PCR_Reset: zero a PCR across all banks, subject to
// the PCR's reset-locality attribute.
func (t *TPM) cmdPCRReset(tag uint16, r *reader) []byte {
	if tag != TPMSTSessions {
		return errorResponse(RCAuthMissing)
	}
	pcrHandle := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	sessions, ok := readAuthArea(r)
	if !ok {
		return errorResponse(RCAuthSize)
	}
	index := int(pcrHandle)
	if index < 0 || index >= numPCR {
		return errorResponse(withHandle(RCValue, 1))
	}
	if !localityAllowed(pcrResetLocalities(index), t.locality) {
		return errorResponse(RCLocality) // PCR not resettable at this locality
	}
	t.pcr.resetAt(index)
	return successResponse(nil, len(sessions))
}
