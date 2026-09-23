package keygen

import (
	"fmt"
	"testing"

	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/tss/key/bip32"
	"github.com/stretchr/testify/require"
)

func TestKeyGen2(t *testing.T) {
	p1SaveData, p2SaveData, p3SaveData := KeyGen()

	fmt.Println("=========2/2 keygen==========")

	// 1-->2   1--->3
	paiPriKey, _, err := paillier.NewKeyPair(8)
	require.NoError(t, err)
	p1PreParamsAndProof := GeneratePreParamsWithDlnProof() // this step should be locally done by P1

	// this step should be locally done by P2. To save time, we assume both setup are the same.
	p2PreParamsAndProof := &PreParamsWithDlnProof{
		Params: p1PreParamsAndProof.Params,
		Proof:  p1PreParamsAndProof.Proof,
	}

	p1Data, _, err := P1(p1SaveData.ShareI, paiPriKey, p1SaveData.Id, p2SaveData.Id, p1PreParamsAndProof, p2PreParamsAndProof.PedersonParameters(), p2PreParamsAndProof.Proof)

	require.NoError(t, err)
	fmt.Println("p1Data", p1Data)
	publicKey, _ := curves.NewECPoint(curve, p2SaveData.PublicKey.X, p2SaveData.PublicKey.Y)
	p2Data, err := P2(p2SaveData.ShareI, publicKey, p1Data, p1SaveData.Id, p2SaveData.Id, p2PreParamsAndProof.PedersonParameters())
	require.NoError(t, err)
	fmt.Println("p2Data", p2Data)

	p1Data, _, err = P1(p1SaveData.ShareI, paiPriKey, p1SaveData.Id, p3SaveData.Id, p1PreParamsAndProof, p2PreParamsAndProof.PedersonParameters(), p2PreParamsAndProof.Proof)
	require.NoError(t, err)
	fmt.Println("p1Data", p1Data)
	p2Data, err = P2(p3SaveData.ShareI, publicKey, p1Data, p1SaveData.Id, p3SaveData.Id, p2PreParamsAndProof.PedersonParameters())
	require.NoError(t, err)
	fmt.Println("p2Data", p2Data)

	fmt.Println("=========bip32==========")
	tssKey, err := bip32.NewTssKey(p1SaveData.ShareI, p1SaveData.PublicKey, p1SaveData.ChainCode)
	require.NoError(t, err)
	tssKey, err = tssKey.NewChildKey(996)
	require.NoError(t, err)
	fmt.Println(tssKey.PublicKey())

	tssKey, err = bip32.NewTssKey(p2SaveData.ShareI, p2SaveData.PublicKey, p2SaveData.ChainCode)
	require.NoError(t, err)
	tssKey, err = tssKey.NewChildKey(996)
	require.NoError(t, err)
	fmt.Println(tssKey.PublicKey())

}
