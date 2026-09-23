package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func mustResult(t *testing.T, raw string) json.RawMessage {
	t.Helper()
	var env struct {
		OK     bool            `json:"ok"`
		Error  string          `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("bad envelope json: %v\n%s", err, raw)
	}
	if !env.OK {
		t.Fatalf("call failed: %s", raw)
	}
	return env.Result
}

func mustFail(t *testing.T, raw string) string {
	t.Helper()
	var env struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("bad envelope json: %v\n%s", err, raw)
	}
	if env.OK {
		t.Fatalf("expected failure, got success: %s", raw)
	}
	if env.Error == "" {
		t.Fatalf("expected error message: %s", raw)
	}
	return env.Error
}

func TestVersion(t *testing.T) {
	if string(mustResult(t, respond(func() (any, error) { return coreVersion(), nil }))) != `"1.0.0"` {
		t.Fatal("version mismatch")
	}
}

func TestEcdsaFullFlow(t *testing.T) {
	var shareList []string
	if err := json.Unmarshal(mustResult(t, respond(coreEcdsaKeygen)), &shareList); err != nil || len(shareList) != 3 {
		t.Fatalf("expected 3 key shares, got: %v (%v)", shareList, err)
	}
	share1, share2 := shareList[0], shareList[1]

	// refresh
	var refreshList []string
	if err := json.Unmarshal(mustResult(t, respond(func() (any, error) {
		return coreEcdsaRefresh(share1, share2)
	})), &refreshList); err != nil || len(refreshList) != 3 {
		t.Fatalf("expected 3 refreshed shares, got: %v (%v)", refreshList, err)
	}
	share1, share2 = refreshList[0], refreshList[1]

	// derived public key (format: X || Y, 128 hex chars)
	pubKeyHex := strings.Trim(string(mustResult(t, respond(func() (any, error) {
		return coreEcdsaDerivedPubKey(share1, share2, 100)
	}))), `"`)
	if len(pubKeyHex) != 128 {
		t.Fatalf("unexpected derived pubkey: %s", pubKeyHex)
	}

	// sign
	hash := sha256.Sum256([]byte("hello"))
	var sig struct {
		R string `json:"r"`
		S string `json:"s"`
	}
	if err := json.Unmarshal(mustResult(t, respond(func() (any, error) {
		return coreEcdsaSign(share1, share2, 100, hex.EncodeToString(hash[:]))
	})), &sig); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if sig.R == "" || sig.S == "" {
		t.Fatalf("empty signature: %v", sig)
	}
}

type tssMsg struct {
	From int    `json:"From"`
	To   int    `json:"To"`
	Data string `json:"Data"`
}

func msgsFor(t *testing.T, msgs []tssMsg, to int) string {
	t.Helper()
	var forMe []tssMsg
	for _, m := range msgs {
		if m.To == to {
			forMe = append(forMe, m)
		}
	}
	b, err := json.Marshal(forMe)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func stepOut[T any](t *testing.T, raw string) T {
	t.Helper()
	var res struct {
		Messages T `json:"messages"`
	}
	if err := json.Unmarshal(mustResult(t, raw), &res); err != nil {
		t.Fatalf("bad step result: %v\n%s", err, raw)
	}
	return res.Messages
}

func TestEd25519FullFlow(t *testing.T) {
	type keyShare struct {
		Id        int    `json:"Id"`
		ShareI    string `json:"ShareI"`
		PublicKey struct {
			Curve string `json:"Curve"`
			X     string `json:"X"`
			Y     string `json:"Y"`
		} `json:"PublicKey"`
	}
	type party struct {
		handle   int64
		keyShare keyShare
	}
	parties := map[int]*party{}

	// DKG start
	for dev := 1; dev <= 3; dev++ {
		var res struct {
			Handle int64 `json:"handle"`
		}
		if err := json.Unmarshal(mustResult(t, respond(func() (any, error) {
			return coreEd25519DkgNew(dev, 3)
		})), &res); err != nil {
			t.Fatalf("dkg new: %v", err)
		}
		parties[dev] = &party{handle: res.Handle}
	}

	// round 1 broadcast
	var round1 []tssMsg
	for dev := 1; dev <= 3; dev++ {
		round1 = append(round1, stepOut[[]tssMsg](t, respond(func() (any, error) {
			return coreEd25519DkgStep1(parties[dev].handle)
		}))...)
	}

	// round 2
	var round2 []tssMsg
	for dev := 1; dev <= 3; dev++ {
		in := msgsFor(t, round1, dev)
		round2 = append(round2, stepOut[[]tssMsg](t, respond(func() (any, error) {
			return coreEd25519DkgStep2(parties[dev].handle, in)
		}))...)
	}

	// round 3 -> key shares
	for dev := 1; dev <= 3; dev++ {
		in := msgsFor(t, round2, dev)
		var res struct {
			KeyShare keyShare `json:"keyShare"`
		}
		if err := json.Unmarshal(mustResult(t, respond(func() (any, error) {
			return coreEd25519DkgStep3(parties[dev].handle, in)
		})), &res); err != nil {
			t.Fatalf("dkg step3: %v", err)
		}
		parties[dev].keyShare = res.KeyShare
	}

	// signing between parties 1 and 2
	msg := sha256.Sum256([]byte("hello"))
	msgHex := hex.EncodeToString(msg[:])
	pubKey := map[string]any{
		"Curve": "ed25519",
		"X":     parties[1].keyShare.PublicKey.X,
		"Y":     parties[1].keyShare.PublicKey.Y,
	}
	pubKeyJson, _ := json.Marshal(pubKey)
	partList, _ := json.Marshal([]int{1, 2})

	signNew := func(dev int) int64 {
		var res struct {
			Handle int64 `json:"handle"`
		}
		if err := json.Unmarshal(mustResult(t, respond(func() (any, error) {
			return coreEd25519SignNew(dev, 2, string(partList), parties[dev].keyShare.ShareI,
				string(pubKeyJson), msgHex)
		})), &res); err != nil {
			t.Fatalf("sign new: %v", err)
		}
		return res.Handle
	}
	h1, h2 := signNew(1), signNew(2)

	s1in := msgsFor(t, stepOut[[]tssMsg](t, respond(func() (any, error) {
		return coreEd25519SignStep1(h1)
	})), 2)
	s2in := msgsFor(t, stepOut[[]tssMsg](t, respond(func() (any, error) {
		return coreEd25519SignStep1(h2)
	})), 1)
	s1out2 := stepOut[[]tssMsg](t, respond(func() (any, error) {
		return coreEd25519SignStep2(h1, s2in)
	}))
	s2out2 := stepOut[[]tssMsg](t, respond(func() (any, error) {
		return coreEd25519SignStep2(h2, s1in)
	}))
	s1in2 := msgsFor(t, s2out2, 1) // p1 consumes p2's step2 messages addressed to 1
	s2in2 := msgsFor(t, s1out2, 2) // p2 consumes p1's step2 messages addressed to 2

	var part1, part2 struct {
		Si string `json:"si"`
		R  string `json:"r"`
	}
	if err := json.Unmarshal(mustResult(t, respond(func() (any, error) {
		return coreEd25519SignStep3(h1, s1in2)
	})), &part1); err != nil {
		t.Fatalf("sign step3 p1: %v", err)
	}
	if err := json.Unmarshal(mustResult(t, respond(func() (any, error) {
		return coreEd25519SignStep3(h2, s2in2)
	})), &part2); err != nil {
		t.Fatalf("sign step3 p2: %v", err)
	}

	var ver struct {
		Valid     bool   `json:"valid"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(mustResult(t, respond(func() (any, error) {
		return coreEd25519Verify(part1.Si, part2.Si, part1.R, msgHex, string(pubKeyJson))
	})), &ver); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ver.Valid {
		t.Fatal("signature verification failed")
	}
	if len(ver.Signature) != 128 {
		t.Fatalf("unexpected signature hex length: %d", len(ver.Signature))
	}
}

func TestInvalidInputs(t *testing.T) {
	mustFail(t, respond(func() (any, error) { return coreEd25519DkgStep1(999) }))
	mustFail(t, respond(func() (any, error) { return coreEd25519DkgNew(0, 3) }))
	mustFail(t, respond(func() (any, error) { return coreEcdsaSign("x", "y", 0, "zz") }))
	mustFail(t, respond(func() (any, error) { return coreEd25519SignFree(12345) }))
	mustFail(t, respond(func() (any, error) { return coreEd25519Verify("a", "b", "c", "00", "{}") }))

	// session handle must be consumed after terminal step3
	var res struct {
		Handle int64 `json:"handle"`
	}
	if err := json.Unmarshal(mustResult(t, respond(func() (any, error) { return coreEd25519DkgNew(1, 2) })), &res); err != nil {
		t.Fatal(err)
	}
	// feeding nothing on step3 fails and frees the handle
	mustFail(t, respond(func() (any, error) { return coreEd25519DkgStep3(res.Handle, "[]") }))
	mustFail(t, respond(func() (any, error) { return coreEd25519DkgStep1(res.Handle) }))
}
