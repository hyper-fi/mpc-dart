package keygen

import (
	"fmt"
	"github.com/okx/threshold-lib/tss"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewPaillierKey(t *testing.T) {
	pKey, err := NewPaillierKey()
	require.NoError(t, err)
	fmt.Println(pKey)
}

func TestMarshalPaillierKey(t *testing.T) {
	pKey, err := NewPaillierKey()
	require.NoError(t, err)
	bs, err := MarshalPaillierKey(pKey)
	require.NoError(t, err)
	fmt.Println(string(bs))
	pKey2, err := UnMarshalToPaillierKey(bs)
	require.NoError(t, err)
	fmt.Println(pKey2)
}

func TestNewPreParamsWithDlnProof(t *testing.T) {
	proof := NewPreParamsWithDlnProof()
	fmt.Println(proof.Params.NTildei.String())
	fmt.Println(proof.Params.H1i.String())
	fmt.Println(proof.Params.H2i.String())
	fmt.Println(proof.Params.Alpha.String())
	fmt.Println(proof.Params.Beta.String())
	fmt.Println(proof.Params.P.String())
	fmt.Println(proof.Params.Q.String())
}

func TestMarshalPreParamsWithDlnProof(t *testing.T) {
	proof := NewPreParamsWithDlnProof()
	bs, err := MarshalPreParamsWithDlnProof(proof)
	require.NoError(t, err)
	fmt.Println(string(bs))
	proof2, err := UnMarshalPreParamsWithDlnProof(bs)
	require.NoError(t, err)
	fmt.Println(proof2)
}

func TestKeyGen(t *testing.T) {
	p1Data, _, _ := KeyGen()
	bs, err := p1Data.MarshalJSON("ecdsa")
	require.NoError(t, err)
	fmt.Println("p1Data:", p1Data)
	fmt.Println(string(bs))
	p1DataDump := &tss.KeyStep3Data{}
	err = p1DataDump.UnmarshalJSON(bs, "ecdsa")
	require.NoError(t, err)
	fmt.Println("p1DataDump:", p1DataDump)
}

func TestNewEcdsaKeyGen(t *testing.T) {
	saveJsons := NewEcdsaKeyGen()
	for _, j := range saveJsons {
		fmt.Println("=========================")
		fmt.Println(j)
	}
}
