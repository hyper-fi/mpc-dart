package sign

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"github.com/okx/threshold-lib/tss/key/bip32"
	"strings"
)

func GetEcdsaDerivedPubKey(share1st string, share2nd string, childIdx uint32) (string, error) {
	data1st := &tss.KeyStep3Data{}
	err := data1st.UnmarshalJSON([]byte(share1st), "ecdsa")
	if err != nil {
		return "", err
	}
	if data1st.Id < 1 || data1st.Id > 3 {
		return "", fmt.Errorf("invalid data1st.Id")
	}

	data2nd := &tss.KeyStep3Data{}
	err = data2nd.UnmarshalJSON([]byte(share2nd), "ecdsa")
	if err != nil {
		return "", err
	}
	if data2nd.Id < 1 || data2nd.Id > 3 {
		return "", fmt.Errorf("invalid data2nd.Id")
	}

	if data1st.Id == data2nd.Id {
		return "", fmt.Errorf("data1st.Id == data2nd.Id")
	}
	if !data1st.PublicKey.Equals(data2nd.PublicKey) {
		return "", fmt.Errorf("data1st.PublicKey != data2nd.PublicKey")
	}

	paiPrivate, _ := keygen.UnMarshalToPaillierKey([]byte(keygen.DefaultPaillierKey))
	p1PreParamsAndProof, _ := keygen.UnMarshalPreParamsWithDlnProof([]byte(keygen.DefaultPreParamsAndProof))

	// this step should be locally done by P2. To save time, we assume both setup are the same.
	p2PreParamsAndProof := &keygen.PreParamsWithDlnProof{
		Params: p1PreParamsAndProof.Params,
		Proof:  p1PreParamsAndProof.Proof,
	}

	p1Dto, _, _ := keygen.P1(data1st.ShareI, paiPrivate, data1st.Id, data2nd.Id, p1PreParamsAndProof, p2PreParamsAndProof.PedersonParameters(), p2PreParamsAndProof.Proof)
	publicKey, _ := curves.NewECPoint(curve, data2nd.PublicKey.X, data2nd.PublicKey.Y)
	p2SaveData, err := keygen.P2(data2nd.ShareI, publicKey, p1Dto, data1st.Id, data2nd.Id, p2PreParamsAndProof.PedersonParameters())
	if err != nil {
		return "", err
	}

	tssKey, err := bip32.NewTssKey(p2SaveData.X2, data2nd.PublicKey, data2nd.ChainCode)
	if err != nil {
		return "", err
	}
	tssKey, err = tssKey.NewChildKey(childIdx)
	if err != nil {
		return "", err
	}

	pubKey := &ecdsa.PublicKey{Curve: curve, X: tssKey.PublicKey().X, Y: tssKey.PublicKey().Y}
	xHex, yHex := hex.EncodeToString(pubKey.X.Bytes()), hex.EncodeToString(pubKey.Y.Bytes())
	xHex = string(bytes.Repeat([]byte{'0'}, 64-len(xHex))) + xHex
	yHex = string(bytes.Repeat([]byte{'0'}, 64-len(yHex))) + yHex
	pubKeyStr := strings.Join([]string{xHex, yHex}, "")

	return pubKeyStr, nil
}

func EcdsaSign(share1st string, share2nd string, childIdx uint32, signMessageHash []byte) (string, string, error) {
	data1st := &tss.KeyStep3Data{}
	err := data1st.UnmarshalJSON([]byte(share1st), "ecdsa")
	if err != nil {
		return "", "", err
	}
	if data1st.Id < 1 || data1st.Id > 3 {
		return "", "", fmt.Errorf("invalid data1st.Id")
	}

	data2nd := &tss.KeyStep3Data{}
	err = data2nd.UnmarshalJSON([]byte(share2nd), "ecdsa")
	if err != nil {
		return "", "", err
	}
	if data2nd.Id < 1 || data2nd.Id > 3 {
		return "", "", fmt.Errorf("invalid data2nd.Id")
	}

	if data1st.Id == data2nd.Id {
		return "", "", fmt.Errorf("data1st.Id == data2nd.Id")
	}
	if !data1st.PublicKey.Equals(data2nd.PublicKey) {
		return "", "", fmt.Errorf("data1st.PublicKey != data2nd.PublicKey")
	}

	paiPrivate, _ := keygen.UnMarshalToPaillierKey([]byte(keygen.DefaultPaillierKey))
	p1PreParamsAndProof, _ := keygen.UnMarshalPreParamsWithDlnProof([]byte(keygen.DefaultPreParamsAndProof))

	// this step should be locally done by P2. To save time, we assume both setup are the same.
	p2PreParamsAndProof := &keygen.PreParamsWithDlnProof{
		Params: p1PreParamsAndProof.Params,
		Proof:  p1PreParamsAndProof.Proof,
	}

	p1Dto, E_x1, _ := keygen.P1(data1st.ShareI, paiPrivate, data1st.Id, data2nd.Id, p1PreParamsAndProof, p2PreParamsAndProof.PedersonParameters(), p2PreParamsAndProof.Proof)
	publicKey, _ := curves.NewECPoint(curve, data2nd.PublicKey.X, data2nd.PublicKey.Y)
	p2SaveData, err := keygen.P2(data2nd.ShareI, publicKey, p1Dto, data1st.Id, data2nd.Id, p2PreParamsAndProof.PedersonParameters())
	if err != nil {
		return "", "", err
	}

	tssKey, err := bip32.NewTssKey(p2SaveData.X2, data2nd.PublicKey, data2nd.ChainCode)
	if err != nil {
		return "", "", err
	}
	tssKey, err = tssKey.NewChildKey(childIdx)
	if err != nil {
		return "", "", err
	}
	x2 := tssKey.ShareI()
	pubKey := &ecdsa.PublicKey{Curve: curve, X: tssKey.PublicKey().X, Y: tssKey.PublicKey().Y}

	p1 := NewP1(pubKey, hex.EncodeToString(signMessageHash), paiPrivate, E_x1, p1PreParamsAndProof.PedersonParameters())
	p2 := NewP2(x2, p2SaveData.E_x1, pubKey, p2SaveData.PaiPubKey, hex.EncodeToString(signMessageHash), p2SaveData.Ped1)

	commit, err := p1.Step1()
	if err != nil {
		return "", "", err
	}
	bobProof, R2, err := p2.Step1(commit)
	if err != nil {
		return "", "", err
	}

	proof, cmtD, err := p1.Step2(bobProof, R2)
	if err != nil {
		return "", "", err
	}
	E_k2_h_xr, affine_proof, err := p2.Step2(cmtD, proof)
	if err != nil {
		return "", "", err
	}

	r, s, err := p1.Step3(E_k2_h_xr, affine_proof)
	if err != nil {
		return "", "", err
	}
	rHex, sHex := hex.EncodeToString(r.Bytes()), hex.EncodeToString(s.Bytes())
	rHex = string(bytes.Repeat([]byte{'0'}, 64-len(rHex))) + rHex
	sHex = string(bytes.Repeat([]byte{'0'}, 64-len(sHex))) + sHex

	return rHex, sHex, nil
}
