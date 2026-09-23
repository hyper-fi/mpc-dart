package tss

import (
	"encoding/json"
	"fmt"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"math/big"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/vss"
)

type Message struct {
	From int
	To   int
	Data string
}

type KeyStep1Data struct {
	C *commitment.Commitment
}

type KeyStep2Data struct {
	Witness *commitment.Witness
	Share   *vss.Share // secret share
	Proof   *schnorr.Proof
}

type KeyStep3Data struct {
	Id             int
	ShareI         *big.Int                // key share
	PublicKey      *curves.ECPoint         // PublicKey
	ChainCode      string                  // chaincode for derivation, no longer change when update
	SharePubKeyMap map[int]*curves.ECPoint //  ShareI*G map
}

type PublicKey struct {
	Curve string `json:"Curve"`
	X     string `json:"X"`
	Y     string `json:"Y"`
}

type KeyStep3DataMarshal struct {
	Id             int               `json:"Id"`
	ShareI         string            `json:"ShareI"`
	PublicKey      PublicKey         `json:"PublicKey"`
	ChainCode      string            `json:"ChainCode"`
	SharePubKeyMap map[int]PublicKey `json:"SharePubKeyMap"`
}

func (k PublicKey) ToECPoint(curveName string) (*curves.ECPoint, error) {
	p := new(curves.ECPoint)
	if curveName == "ecdsa" {
		p.Curve = secp256k1.S256()
	} else if curveName == "ed25519" {
		p.Curve = edwards.Edwards()
	} else {
		return nil, fmt.Errorf("invalid curveName: %v", curveName)
	}
	p.X = new(big.Int)
	p.X.SetString(k.X, 10)
	p.Y = new(big.Int)
	p.Y.SetString(k.Y, 10)
	return p, nil
}

func (k KeyStep3Data) toMarshalStruct(curveName string) *KeyStep3DataMarshal {
	s := &KeyStep3DataMarshal{
		Id:     k.Id,
		ShareI: k.ShareI.String(),
		PublicKey: PublicKey{
			Curve: curveName,
			X:     k.PublicKey.X.String(),
			Y:     k.PublicKey.Y.String(),
		},
		ChainCode: k.ChainCode,
	}
	s.SharePubKeyMap = make(map[int]PublicKey)
	for m, n := range k.SharePubKeyMap {
		s.SharePubKeyMap[m] = PublicKey{
			Curve: curveName,
			X:     n.X.String(),
			Y:     n.Y.String(),
		}
	}
	return s
}

func (k *KeyStep3Data) fromMarshalStruct(s *KeyStep3DataMarshal, curveName string) error {
	k.Id = s.Id
	k.ChainCode = s.ChainCode

	k.ShareI = new(big.Int)
	k.ShareI.SetString(s.ShareI, 10)

	var err error
	k.PublicKey, err = s.PublicKey.ToECPoint(curveName)
	if err != nil {
		return err
	}

	k.SharePubKeyMap = make(map[int]*curves.ECPoint)
	for m, n := range s.SharePubKeyMap {
		p, err := n.ToECPoint(curveName)
		if err != nil {
			return err
		}
		k.SharePubKeyMap[m] = p
	}

	return nil
}

func (k KeyStep3Data) MarshalJSON(curveName string) ([]byte, error) {
	s := k.toMarshalStruct(curveName)
	return json.Marshal(s)
}

func (k *KeyStep3Data) UnmarshalJSON(b []byte, curveName string) error {
	s := &KeyStep3DataMarshal{}
	s.SharePubKeyMap = make(map[int]PublicKey)

	err := json.Unmarshal(b, s)
	if err != nil {
		return err
	}

	err = k.fromMarshalStruct(s, curveName)
	if err != nil {
		return err
	}
	return nil
}
