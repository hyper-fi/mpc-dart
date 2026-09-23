package sign

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/stretchr/testify/require"

	"testing"

	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"github.com/okx/threshold-lib/tss/key/bip32"
)

func TestEcdsaSign2(t *testing.T) {
	p1Data, p2Data, _ := keygen.KeyGen()

	fmt.Println("=========2/2 keygen==========")
	//paiPrivate, _, _ := paillier.NewKeyPair(8)
	paiPrivate, _ := keygen.UnMarshalToPaillierKey([]byte(keygen.DefaultPaillierKey))

	//p1PreParamsAndProof := keygen.GeneratePreParamsWithDlnProof() // this step should be locally done by P1
	p1PreParamsAndProof, _ := keygen.UnMarshalPreParamsWithDlnProof([]byte(keygen.DefaultPreParamsAndProof))

	// this step should be locally done by P2. To save time, we assume both setup are the same.
	p2PreParamsAndProof := &keygen.PreParamsWithDlnProof{
		Params: p1PreParamsAndProof.Params,
		Proof:  p1PreParamsAndProof.Proof,
	}

	p1Dto, E_x1, _ := keygen.P1(p1Data.ShareI, paiPrivate, p1Data.Id, p2Data.Id, p1PreParamsAndProof, p2PreParamsAndProof.PedersonParameters(), p2PreParamsAndProof.Proof)
	publicKey, _ := curves.NewECPoint(curve, p2Data.PublicKey.X, p2Data.PublicKey.Y)
	p2SaveData, err := keygen.P2(p2Data.ShareI, publicKey, p1Dto, p1Data.Id, p2Data.Id, p2PreParamsAndProof.PedersonParameters())
	require.NoError(t, err)
	fmt.Println(p2SaveData, err)

	fmt.Println("=========bip32==========")
	tssKey, err := bip32.NewTssKey(p2SaveData.X2, p2Data.PublicKey, p2Data.ChainCode)
	tssKey, err = tssKey.NewChildKey(996)
	x2 := tssKey.ShareI()
	pubKey := &ecdsa.PublicKey{Curve: curve, X: tssKey.PublicKey().X, Y: tssKey.PublicKey().Y}

	fmt.Println("=========2/2 sign==========")
	hash := sha256.New()
	hash.Write([]byte("hello"))
	message := hash.Sum(nil)

	p1 := NewP1(pubKey, hex.EncodeToString(message), paiPrivate, E_x1, p1PreParamsAndProof.PedersonParameters())
	p2 := NewP2(x2, p2SaveData.E_x1, pubKey, p2SaveData.PaiPubKey, hex.EncodeToString(message), p2SaveData.Ped1)

	commit, err := p1.Step1()
	require.NoError(t, err)
	bobProof, R2, err := p2.Step1(commit)
	require.NoError(t, err)

	proof, cmtD, _ := p1.Step2(bobProof, R2)
	E_k2_h_xr, affine_proof, err := p2.Step2(cmtD, proof)
	require.NoError(t, err)

	r, s, err := p1.Step3(E_k2_h_xr, affine_proof)
	require.NoError(t, err)
	fmt.Println(r, s)
}
