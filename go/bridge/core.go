// Package bridge exposes the threshold-lib TSS primitives over a C ABI so
// that Dart (Flutter FFI), and any other language, can drive the protocols.
//
// core.go holds the pure-Go logic (unit-testable); exports.go holds the thin
// cgo shims.
//
// Conventions:
//   - Every C entry point returns a single heap-allocated C string containing
//     a JSON envelope: {"ok":true,"result":...} or {"ok":false,"error":"..."}.
//     Callers must release it with MpcFreeCString.
//   - Stateless operations (the full ECDSA flow) are one-shot calls.
//   - Interactive protocols (Ed25519 DKG / signing) keep their Go state in a
//     handle registry; Dart passes the handle back on every round and frees
//     it (Free call, or the terminal Step3) when done.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	ecdsasign "github.com/okx/threshold-lib/tss/ecdsa/sign"
	"github.com/okx/threshold-lib/tss/ed25519/sign"
	"github.com/okx/threshold-lib/tss/key/dkg"
	"github.com/okx/threshold-lib/tss/key/reshare"
)

const version = "1.0.0"

// ---------------------------------------------------------------------------
// JSON envelope
// ---------------------------------------------------------------------------

type envelope struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// respond runs fn with panic isolation (threshold-lib may panic on bad input;
// a panic must never cross the C boundary) and serialises the outcome.
func respond(fn func() (any, error)) string {
	result, err := runSafe(fn)
	env := envelope{OK: err == nil}
	if err != nil {
		env.Error = err.Error()
	} else if result != nil {
		b, e := json.Marshal(result)
		if e != nil {
			env = envelope{OK: false, Error: e.Error()}
		} else {
			env.Result = b
		}
	}
	b, err := json.Marshal(env)
	if err != nil { // unreachable: envelope only holds strings/bool
		b = []byte(`{"ok":false,"error":"envelope marshal failed"}`)
	}
	return string(b)
}

func runSafe(fn func() (any, error)) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn()
}

// ---------------------------------------------------------------------------
// Handle registry for stateful (multi-round) protocol sessions
// ---------------------------------------------------------------------------

var (
	handlesMu sync.Mutex
	handleSeq int64
	handles   = map[int64]any{}
)

func putHandle(v any) int64 {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	handleSeq++
	handles[handleSeq] = v
	return handleSeq
}

func takeHandle(h int64) (any, error) {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	v, ok := handles[h]
	if !ok {
		return nil, fmt.Errorf("invalid or closed session handle: %d", h)
	}
	return v, nil
}

func delHandle(h int64) bool {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	if _, ok := handles[h]; !ok {
		return false
	}
	delete(handles, h)
	return true
}

// ---------------------------------------------------------------------------
// Message helpers (tss.Message marshals to {"From":..,"To":..,"Data":".."})
// ---------------------------------------------------------------------------

func messagesOut(m map[int]*tss.Message) []tss.Message {
	out := make([]tss.Message, 0, len(m))
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		out = append(out, *m[k])
	}
	return out
}

func messagesIn(s string) ([]*tss.Message, error) {
	var msgs []tss.Message
	if err := json.Unmarshal([]byte(s), &msgs); err != nil {
		return nil, fmt.Errorf("invalid messages json: %w", err)
	}
	out := make([]*tss.Message, 0, len(msgs))
	for i := range msgs {
		out = append(out, &msgs[i])
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

func coreVersion() string { return version }

// ---------------------------------------------------------------------------
// ECDSA (2-of-n) — one-shot operations, both key shares are available locally
// ---------------------------------------------------------------------------

func coreEcdsaKeygen() (any, error) {
	return keygen.NewEcdsaKeyGen(), nil
}

func coreEcdsaRefresh(share1st, share2nd string) (any, error) {
	return reshare.RefreshEcdsaKeyShares(share1st, share2nd)
}

func coreEcdsaDerivedPubKey(share1st, share2nd string, childIdx uint32) (any, error) {
	return ecdsasign.GetEcdsaDerivedPubKey(share1st, share2nd, childIdx)
}

func coreEcdsaSign(share1st, share2nd string, childIdx uint32, hashHex string) (any, error) {
	hash, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid message hash hex: %w", err)
	}
	r, s, err := ecdsasign.EcdsaSign(share1st, share2nd, childIdx, hash)
	if err != nil {
		return nil, err
	}
	return map[string]string{"r": r, "s": s}, nil
}

// ---------------------------------------------------------------------------
// Ed25519 (2-of-n) DKG — stateful, three rounds
// ---------------------------------------------------------------------------

type dkgSession struct {
	info *dkg.SetupInfo
}

func coreEd25519DkgNew(deviceNumber, total int) (any, error) {
	if deviceNumber <= 0 || total < 2 || deviceNumber > total {
		return nil, fmt.Errorf("invalid dkg params: deviceNumber=%d total=%d", deviceNumber, total)
	}
	s := &dkgSession{info: dkg.NewSetUp(deviceNumber, total, edwards.Edwards())}
	return map[string]int64{"handle": putHandle(s)}, nil
}

func coreEd25519DkgStep1(h int64) (any, error) {
	v, err := takeHandle(h)
	if err != nil {
		return nil, err
	}
	msgs, err := v.(*dkgSession).info.DKGStep1()
	if err != nil {
		return nil, err
	}
	return map[string]any{"messages": messagesOut(msgs)}, nil
}

func coreEd25519DkgStep2(h int64, msgsJson string) (any, error) {
	v, err := takeHandle(h)
	if err != nil {
		return nil, err
	}
	in, err := messagesIn(msgsJson)
	if err != nil {
		return nil, err
	}
	out, err := v.(*dkgSession).info.DKGStep2(in)
	if err != nil {
		return nil, err
	}
	return map[string]any{"messages": messagesOut(out)}, nil
}

func coreEd25519DkgStep3(h int64, msgsJson string) (any, error) {
	v, err := takeHandle(h)
	if err != nil {
		return nil, err
	}
	in, err := messagesIn(msgsJson)
	if err != nil {
		return nil, err
	}
	keyData, err := v.(*dkgSession).info.DKGStep3(in)
	delHandle(h)
	if err != nil {
		return nil, err
	}
	b, err := keyData.MarshalJSON("ed25519")
	if err != nil {
		return nil, err
	}
	return map[string]json.RawMessage{"keyShare": b}, nil
}

func coreEd25519DkgFree(h int64) (any, error) {
	if !delHandle(h) {
		return nil, fmt.Errorf("invalid or closed session handle: %d", h)
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Ed25519 (2-of-n) signing — stateful, three rounds
// ---------------------------------------------------------------------------

type signSession struct {
	s *sign.Ed25519Sign
}

func coreEd25519SignNew(deviceNumber, threshold int, partListJson, shareI, pubKeyJson, msgHex string) (any, error) {
	var partList []int
	if err := json.Unmarshal([]byte(partListJson), &partList); err != nil {
		return nil, fmt.Errorf("invalid partList json: %w", err)
	}
	if _, err := hex.DecodeString(msgHex); err != nil {
		return nil, fmt.Errorf("invalid message hex: %w", err)
	}

	share := new(big.Int)
	if _, ok := share.SetString(shareI, 10); !ok {
		return nil, fmt.Errorf("invalid shareI decimal string")
	}

	var pk tss.PublicKey
	if err := json.Unmarshal([]byte(pubKeyJson), &pk); err != nil {
		return nil, fmt.Errorf("invalid public key json: %w", err)
	}
	point, err := pk.ToECPoint(pk.Curve)
	if err != nil {
		return nil, err
	}
	pubKey := edwards.NewPublicKey(point.X, point.Y)

	s := sign.NewEd25519Sign(deviceNumber, threshold, partList, share, pubKey, msgHex)
	if s == nil {
		return nil, fmt.Errorf("NewEd25519Sign failed: len(partList) must equal threshold")
	}
	return map[string]int64{"handle": putHandle(&signSession{s: s})}, nil
}

func coreEd25519SignStep1(h int64) (any, error) {
	v, err := takeHandle(h)
	if err != nil {
		return nil, err
	}
	msgs, err := v.(*signSession).s.SignStep1()
	if err != nil {
		return nil, err
	}
	return map[string]any{"messages": messagesOut(msgs)}, nil
}

func coreEd25519SignStep2(h int64, msgsJson string) (any, error) {
	v, err := takeHandle(h)
	if err != nil {
		return nil, err
	}
	in, err := messagesIn(msgsJson)
	if err != nil {
		return nil, err
	}
	out, err := v.(*signSession).s.SignStep2(in)
	if err != nil {
		return nil, err
	}
	return map[string]any{"messages": messagesOut(out)}, nil
}

func coreEd25519SignStep3(h int64, msgsJson string) (any, error) {
	v, err := takeHandle(h)
	if err != nil {
		return nil, err
	}
	in, err := messagesIn(msgsJson)
	if err != nil {
		return nil, err
	}
	si, r, err := v.(*signSession).s.SignStep3(in)
	delHandle(h)
	if err != nil {
		return nil, err
	}
	return map[string]string{"si": si.String(), "r": r.String()}, nil
}

func coreEd25519SignFree(h int64) (any, error) {
	if !delHandle(h) {
		return nil, fmt.Errorf("invalid or closed session handle: %d", h)
	}
	return nil, nil
}

// coreEd25519Verify assembles the final signature from the two partial
// signatures (si1+si2, r) and verifies it against the aggregate public key.
func coreEd25519Verify(si1, si2, r, msgHex, pubKeyJson string) (any, error) {
	parse := func(s string) (*big.Int, error) {
		v, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("invalid decimal string: %s", s)
		}
		return v, nil
	}
	si1v, err := parse(si1)
	if err != nil {
		return nil, err
	}
	si2v, err := parse(si2)
	if err != nil {
		return nil, err
	}
	rv, err := parse(r)
	if err != nil {
		return nil, err
	}

	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		return nil, fmt.Errorf("invalid message hex: %w", err)
	}

	var pk tss.PublicKey
	if err := json.Unmarshal([]byte(pubKeyJson), &pk); err != nil {
		return nil, fmt.Errorf("invalid public key json: %w", err)
	}
	point, err := pk.ToECPoint(pk.Curve)
	if err != nil {
		return nil, err
	}
	pubKey := edwards.NewPublicKey(point.X, point.Y)

	s := new(big.Int).Add(si1v, si2v)
	signature := edwards.NewSignature(rv, s)
	valid := signature.Verify(msg, pubKey)

	sig, err := serializeSig(rv, s)
	if err != nil {
		return nil, err
	}
	return map[string]any{"valid": valid, "signature": sig}, nil
}

// serializeSig renders an ed25519 signature in the standard 64-byte wire
// format (r || s, each big-endian 32 bytes).
func serializeSig(r, s *big.Int) (string, error) {
	const width = 32
	rb := r.Bytes()
	sb := s.Bytes()
	if len(rb) > width || len(sb) > width {
		return "", fmt.Errorf("signature component exceeds 32 bytes")
	}
	out := make([]byte, 2*width)
	copy(out[width-len(rb):width], rb)
	copy(out[2*width-len(sb):], sb)
	return hex.EncodeToString(out), nil
}

// coreSha256Hex hashes hex-encoded data and returns the digest hex.
func coreSha256Hex(dataHex string) (any, error) {
	data, err := hex.DecodeString(dataHex)
	if err != nil {
		return nil, fmt.Errorf("invalid data hex: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
