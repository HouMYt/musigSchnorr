package main

import (
	"btcd/btcec"
	"errors"
	"github.com/hbakhtiyor/schnorr"
	"math/big"
)

type PrivateKey btcec.PrivateKey
type PublicKey btcec.PublicKey
var Curve = btcec.S256()
func GenPrivatekey() (*PrivateKey, error){
	privKey,err := btcec.NewPrivateKey(Curve)
	if err!=nil {
		return nil,err
	}
	return (*PrivateKey)(privKey),nil

}
func (p *PrivateKey)PubKey()*PublicKey  {
	return (*PublicKey)(&p.PublicKey)
}
func (k *PublicKey)Serialize()[33]byte{
	var result [33]byte
	pk := (*btcec.PublicKey)(k)
	pkbyte := pk.SerializeCompressed()
	copy(result[:],pkbyte)
	return result
}
func AddPubkeys(pks []*PublicKey)([33]byte,error){
	if len(pks)==0 || pks == nil{
		err := errors.New("publicKeys must be an array with one or more elements")
		return *new([33]byte),err
	}
	if len(pks) == 1{
		return pks[0].Serialize(),nil
	}
	var publicKey [33]byte
	var px,py *big.Int
	publicKey = pks[0].Serialize()
	px,py = schnorr.Unmarshal(Curve,publicKey[:])
	for i:=1;i<len(pks);i++{
		publicKey = pks[i].Serialize()
		px1,py1 := schnorr.Unmarshal(Curve,publicKey[:])
		px,py = Curve.Add(px,py,px1,py1)
	}
	copy(publicKey[:],schnorr.Marshal(Curve,px,py))
	return publicKey,nil

}