package main

import (
	"crypto/sha256"
	"errors"
	"github.com/hbakhtiyor/schnorr"
	"math/big"
)

//Sign hash of a larger message.
//If hash is out of bitlength, then truncated the hash.
func Sign(k *PrivateKey,hash []byte) ([]byte, error) {
	var sig []byte
	if k == nil  {
		return sig, errors.New("privateKey must not be nil")
	}
	if hash == nil || len(hash) == 0 {
		return sig,errors.New("hash length must be more than 0 ")
	}
	var m [32]byte
	copy(m[:],hash)
	s,err := schnorr.Sign(k.D,m)
	copy(sig,s[:])
	return sig,err
}

func Verify(k *PublicKey,hash []byte,sig []byte)(bool,error){
	if k == nil {
		return false, errors.New("publicKey must not be nil")
	}
	if hash == nil || len(hash) == 0 {
		return false,errors.New("hash length must be more than 0 ")
	}
	if sig == nil {
		return false,errors.New("signature must not be nil")
	}
	var m [32]byte
	copy(m[:],hash)
	if len(sig)!=64 {
		err := errors.New("signature not in correct format")
		return false,err
	}
	var s [64]byte
	copy(s[:],sig)
	ok,err := schnorr.Verify(k.Serialize(),m,s)
	return ok,err
}
//简单MultiSig方案：签名
func AggregateSignSimple(ks []*PrivateKey,hash []byte)([]byte,error){
	var sig []byte
	if ks == nil || len(ks) == 0 {
		return sig, errors.New("privateKeys must be an array with one or more elements")
	}
	if hash == nil || len(hash) == 0 {
		return sig,errors.New("hash length must be more than 0 ")
	}
	var m [32]byte
	copy(m[:],hash)
	privKs := make([]*big.Int,len(ks))
	for index,k := range ks{
		privKs[index] = k.D
	}
	s,err := schnorr.AggregateSignatures(privKs,m)
	copy(sig,s[:])
	return sig,err
}
//简单MultiSig方案：验证
func AggregateVerifySimple(ks []*PublicKey,hash []byte,sig []byte)(bool,error){
	if hash == nil || len(hash) == 0 {
		return false,errors.New("hash length must be more than 0 ")
	}
	if sig == nil || len(sig) != 64 {
		return false,errors.New("signature must not be nil")
	}
	pubicKey,err := AddPubkeys(ks)
	if err!=nil {
		return false, err
	}
	var m [32]byte
	copy(m[:],hash)
	var s [64]byte
	copy(s[:],sig)
	ok,err := schnorr.Verify(pubicKey,m,s)
	return ok,err
}
//*Simple Schnorr MultiSig with Application to Bitcion*方案
//根据私钥和明文的哈希生成随机数
func genRandomr(d []byte, message [32]byte) (*big.Int, error) {
	h := sha256.Sum256(append(d, message[:]...))
	i := new(big.Int).SetBytes(h[:])
	r := i.Mod(i, Curve.N)
	if r.Sign() == 0 {
		return nil, errors.New("r is zero")
	}

	return r, nil
}
//
//func Hash() []byte {
//
//}
//func HashVerify()bool,err{
//
//}
//func CurveMod()  {
//
//}
//func MultiSign()  {
//
//}
//func AggregateKey()  {
//
//}
//func MultiVerify()  {
//
//}