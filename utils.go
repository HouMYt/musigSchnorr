package main

import (
	"btcd/btcec"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
)

type PrivateKey btcec.PrivateKey
type PublicKey btcec.PublicKey
type CurvePoint struct{
	x *big.Int
	y* big.Int
}
var (
	// Curve is a KoblitzCurve which implements secp256k1.
	Curve = btcec.S256()
	// One holds a big integer of 1
	One = new(big.Int).SetInt64(1)
	// Two holds a big integer of 2
	Two = new(big.Int).SetInt64(2)
	// Three holds a big integer of 3
	Three = new(big.Int).SetInt64(3)
	// Four holds a big integer of 4
	Four = new(big.Int).SetInt64(4)
	// Seven holds a big integer of 7
	Seven = new(big.Int).SetInt64(7)
	// N2 holds a big integer of N-2
	N2 = new(big.Int).Sub(Curve.N, Two)
)
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
func (k *PublicKey)Serialize33()[33]byte{
	var result [33]byte
	pk := (*btcec.PublicKey)(k)
	pkbyte := pk.SerializeCompressed()
	copy(result[:],pkbyte)
	return result
}
func (k *PublicKey)SerializeCompressed()[]byte  {
	pk := (btcec.PublicKey)(*k)
	return pk.SerializeCompressed()
}
func AddPubkeys(pks []*PublicKey)([33]byte,error){
	if len(pks)==0 {
		err := errors.New("publicKeys must be an array with one or more elements")
		return *new([33]byte),err
	}
	if len(pks) == 1{
		return pks[0].Serialize33(),nil
	}
	var publicKey [33]byte
	var px,py *big.Int
	publicKey = pks[0].Serialize33()
	px,py = Unmarshal(Curve,publicKey[:])
	for i:=1;i<len(pks);i++{
		publicKey = pks[i].Serialize33()
		px1,py1 := Unmarshal(Curve,publicKey[:])
		px,py = Curve.Add(px,py,px1,py1)
	}
	copy(publicKey[:],Marshal(Curve,px,py))
	return publicKey,nil

}
func intToByte(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}

func bytetoInt(b []byte)*big.Int  {
	i := new(big.Int).SetBytes(b)
	//返回mod Curve.N不确定是否有问题
	return i.Mod(i, Curve.N)

}

// Marshal converts a point into the form specified in section 2.3.3 of the
// SEC 1 standard.
func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 1+byteLen)
	ret[0] = 2 // compressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	ret[0] += byte(y.Bit(0))
	return ret
}

// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On
// error, x = nil.
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 {
		return
	}
	if len(data) != 1+byteLen {
		return
	}

	x0 := new(big.Int).SetBytes(data[1 : 1+byteLen])
	P := curve.Params().P
	ySq := new(big.Int)
	ySq.Exp(x0, Three, P)
	ySq.Add(ySq, Seven)
	ySq.Mod(ySq, P)
	y0 := new(big.Int)
	P1 := new(big.Int).Add(P, One)
	d := new(big.Int).Mod(P1, Four)
	P1.Sub(P1, d)
	P1.Div(P1, Four)
	y0.Exp(ySq, P1, P)

	if new(big.Int).Exp(y0, Two, P).Cmp(ySq) != 0 {
		return
	}
	if y0.Bit(0) != uint(data[0]&1) {
		y0.Sub(P, y0)
	}
	x, y = x0, y0
	return
}

func hTemp(plaintext []byte) []byte {
	h := sha256.New()
	h.Write(plaintext)
	return h.Sum(nil)
}

func getK(Ry, k0 *big.Int) *big.Int {
	if big.Jacobi(Ry, Curve.P) == 1 {
		return k0
	}
	return k0.Sub(Curve.N, k0)
}