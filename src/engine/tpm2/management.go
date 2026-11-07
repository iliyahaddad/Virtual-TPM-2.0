// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import "fmt"

// This file adds the management/test commands of Phase 8: TPM2_IncrementalSelfTest,
// TPM2_TestParms, TPM2_SetAlgorithmSet and TPM2_PP_Commands.

// cmdIncrementalSelfTest implements TPM2_IncrementalSelfTest (Part 3, §10.3):
// test the requested algorithms. For each algorithm in toTest:
//   - If the algorithm is not a recognized TPM algorithm ID, return RC_VALUE
//     with parameter 1 (the algorithm ID).
//   - If the algorithm can be tested (a KAT exists) and passes, remove it
//     from toDoList.
//   - If the algorithm cannot be tested (no KAT defined), keep it in
//     toDoList.
// The returned toDoList lists algorithms still needing testing.
func (t *TPM) cmdIncrementalSelfTest(r *reader) []byte {
	count := r.u32() // TPML_ALG toTest
	var toDo []uint16
	for i := uint32(0); i < count && r.err == nil; i++ {
		alg := r.u16()
		if r.err != nil {
			return errorResponse(RCInsufficient)
		}
		// An unknown algorithm ID is a parameter error.
		if !isKnownAlgorithm(alg) {
			return errorResponse(withParam(RCValue, 1))
		}
		// Run the KAT if we have one. If we can test it and it passes,
		// omit it from toDo. If we cannot test it (no KAT defined), keep it.
		if err := testAlgorithm(alg); err == nil {
			// Algorithm tested successfully — do not add to toDo.
			continue
		}
		// Cannot test this algorithm — keep it in toDo.
		toDo = append(toDo, alg)
	}
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	var w writer
	w.u32(uint32(len(toDo))) // toDoList count
	for _, a := range toDo {
		w.u16(a)
	}
	return successResponse(w.bytes(), 0)
}

// isKnownAlgorithm reports whether alg is a recognized TPM 2.0 algorithm ID.
func isKnownAlgorithm(alg uint16) bool {
	switch alg {
	case AlgNull, AlgRSA, AlgSHA1, AlgHMAC, AlgAES, AlgMGF1, AlgKeyedHash,
		AlgXOR, AlgSHA256, AlgSHA384, AlgSHA512, AlgRSAPSS, AlgOAEP,
		AlgKDF1SP80056A, AlgKDF1SP800108, AlgKDF2, AlgECC, AlgSymCipher,
		AlgSHA3256, AlgSHA3384, AlgSHA3512, AlgCMAC:
		return true
	}
	return false
}

// testAlgorithm runs the known-answer test for a single TPM algorithm. It
// returns nil if the algorithm is supported and its KAT passes, or an error
// if the algorithm cannot be tested by this emulator.
func testAlgorithm(alg uint16) error {
	switch alg {
	case AlgSHA1:
		return selfTestSHA1()
	case AlgSHA256:
		return selfTestSHA256()
	case AlgSHA384:
		return selfTestSHA384()
	case AlgSHA512:
		return selfTestSHA512()
	case AlgHMAC:
		return selfTestHMACSHA256()
	case AlgAES:
		return selfTestAES128ECB()
	case AlgRSA:
		return selfTestRSASignVerify()
	case AlgECC:
		return selfTestECCP256SignVerify()
	default:
		// No KAT defined for this algorithm.
		return fmt.Errorf("tpm2: no self-test for algorithm 0x%04x", alg)
	}
}

// readPublicParms reads a TPMT_PUBLIC_PARMS (object type + the parameter union).
func readPublicParms(r *reader) public {
	var p public
	p.Type = r.u16()
	switch p.Type {
	case AlgKeyedHash:
		p.Scheme.unmarshal(r)
	case AlgSymCipher:
		p.Sym.unmarshal(r)
	case AlgRSA:
		p.Sym.unmarshal(r)
		p.Scheme.unmarshal(r)
		p.KeyBits = r.u16()
		p.Exp = r.u32()
	case AlgECC:
		p.Sym.unmarshal(r)
		p.Scheme.unmarshal(r)
		p.Curve = r.u16()
		p.KDF.unmarshal(r)
	default:
		if r.err == nil {
			r.err = errBadValue
		}
	}
	return p
}

// cmdTestParms implements TPM2_TestParms (Part 3, §10.4): validate that a set of
// algorithm parameters is supported, without creating an object.
func (t *TPM) cmdTestParms(r *reader) []byte {
	p := readPublicParms(r)
	if r.err != nil {
		return errorResponse(withParam(RCValue, 1))
	}
	switch p.Type {
	case AlgRSA:
		switch p.KeyBits {
		case 1024, 2048, 3072, 4096:
		default:
			return errorResponse(withParam(RCValue, 1))
		}
	case AlgECC:
		if curveFor(p.Curve) == nil {
			return errorResponse(withParam(RCCurve, 1))
		}
	case AlgSymCipher:
		if p.Sym.Alg != AlgNull && p.Sym.Alg != AlgAES {
			return errorResponse(withParam(RCValue, 1))
		}
	case AlgKeyedHash:
		// Any keyed-hash scheme (HMAC/XOR/NULL) is acceptable.
	default:
		return errorResponse(withParam(RCValue, 1))
	}
	return successResponse(nil, 0)
}

// cmdSetAlgorithmSet implements TPM2_SetAlgorithmSet (Part 3, §24.4): record the
// vendor-defined algorithm set. Authorized by the platform hierarchy.
func (t *TPM) cmdSetAlgorithmSet(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCSetAlgorithmSet, 1, r) // @authHandle (platform)
	if errResp != nil {
		return errResp
	}
	algorithmSet := r.u32()
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, RHPlatform); errResp != nil {
		return errResp
	}
	t.algorithmSet = algorithmSet
	return t.authResponse(ac, nil, nil)
}

// cmdPPCommands implements TPM2_PP_Commands (Part 3, §24.3): change the set of
// commands that require physical-presence confirmation. Platform-authorized.
func (t *TPM) cmdPPCommands(tag uint16, r *reader) []byte {
	ac, errResp := parseCommandAuth(tag, CCPPCommands, 1, r) // @auth (platform)
	if errResp != nil {
		return errResp
	}
	setList := readCCList(r)
	clearList := readCCList(r)
	if r.err != nil {
		return errorResponse(RCInsufficient)
	}
	if ac.handles[0] != RHPlatform {
		return errorResponse(withHandle(RCValue, 1))
	}
	if errResp := t.authorizeHierarchy(ac, RHPlatform); errResp != nil {
		return errResp
	}
	if t.ppRequired == nil {
		t.ppRequired = make(map[uint32]bool)
	}
	for _, cc := range setList {
		t.ppRequired[cc] = true
	}
	for _, cc := range clearList {
		delete(t.ppRequired, cc)
	}
	return t.authResponse(ac, nil, nil)
}
