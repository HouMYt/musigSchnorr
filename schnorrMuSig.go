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

func MuSigVerify(k [33]byte,hash []byte,sig []byte)(bool,error){
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
	ok,err := verifytemp(k,m,s)
	return ok,err
}
func Verify(k [33]byte,hash []byte,sig []byte)(bool,error){
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
	ok,err := schnorr.Verify(k,m,s)
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
	//*不明白为什么做下面几步*
	_, Ry := Curve.ScalarBaseMult(intToByte(r))
	if big.Jacobi(Ry, Curve.P) == 1 {
		return r,nil
	}
	return r.Sub(Curve.N, r),nil
}
func getL(pks []*PublicKey)([]byte,error){
	var plaintext []byte
	if len(pks)==0 {
		err := errors.New("publicKeys must be an array with one or more elements")
		return nil,err
	}
	for i:=0;i<len(pks);i++{
		plaintext = append(plaintext, pks[i].SerializeCompressed()...)
	}
	return hTemp(plaintext),nil
}
func Hashagg(pk *PublicKey,l []byte) []byte {
	plaintext := append(l,pk.SerializeCompressed()...)
	return hTemp(plaintext)
}
func genAggPubKey(pks []*PublicKey)([]byte,error){
	l,err:=getL(pks)
	if err!=nil{
		return nil,err
	}
	if len(pks)<2 {
		err := errors.New("publicKeys must be an array with two or more elements")
		return nil,err
	}
	Px,Py :=  Unmarshal(Curve, pks[0].SerializeCompressed())
	if Px == nil || Py == nil || !Curve.IsOnCurve(Px, Py) {
		return nil, errors.New("public key wrong")
	}
	ai := Hashagg(pks[0],l)
	bytetoInt(ai).Mod(bytetoInt(ai),Curve.N)
	Px,Py = Curve.ScalarMult(Px,Py,ai)
	for i:=1;i<len(pks);i++{
		Px0, Py0 := Unmarshal(Curve, pks[i].SerializeCompressed())
		if Px0 == nil || Py0 == nil || !Curve.IsOnCurve(Px0, Py0) {
			return nil, errors.New("public key wrong")
		}
		ai = Hashagg(pks[i],l)
		Px0,Py0 = Curve.ScalarMult(Px0,Py0,ai)
		Px,Py = Curve.Add(Px,Py,Px0,Py0)
	}
	return Marshal(Curve,Px,Py),nil

}
func CurveAdd(ps []CurvePoint)(*CurvePoint,error){
	if len(ps)<2 {
		return nil,errors.New("points must be an array with two or more elements")
	}
	Px := ps[0].x
	Py := ps[0].y
	for i:=1;i<len(ps);i++{
		Px,Py = Curve.Add(Px,Py,ps[i].x,ps[i].y)
	}
	return &CurvePoint{Px,Py},nil
}

func getR(ps []CurvePoint) (*CurvePoint,error) {
	return CurveAdd(ps)
}

func Hashsig(aggKey []byte,rX []byte,m []byte)*big.Int{
	Px,Py := Unmarshal(Curve,aggKey)
	r := append(rX, Marshal(Curve, Px, Py)...)
	r = append(r, m...)
	h := sha256.Sum256(r)
	i := new(big.Int).SetBytes(h[:])
	return i.Mod(i, Curve.N)
}
func signPart(k *PrivateKey ,pks []*PublicKey,Ri []CurvePoint,ri *big.Int,m []byte)([]byte,error){
	l,err:=getL(pks)
	if err!=nil {
		return nil,err
	}
	a:= bytetoInt( Hashagg(k.PubKey(),l))
	aggKey,err:=genAggPubKey(pks)
	if err!=nil {
		return nil,err
	}
	R,err := getR(Ri)
	if err!=nil {
		return nil,err
	}
	c:=Hashsig(aggKey,intToByte(R.x),m)
	c.Mul(c,a)
	c.Mul(c,k.D)
	ri.Add(ri,c)
	ri.Mod(ri,Curve.N)
	return intToByte(ri),nil
}
func addSigPart(si []*big.Int)([]byte,error){
	if len(si) == 0{
		return nil,errors.New("must be one or more signature parts")
	}
	sigAdd := new(big.Int)
	for _,s := range si{
		sigAdd.Add(sigAdd,s)
	}
	return intToByte(sigAdd.Mod(sigAdd,Curve.N)),nil
}
func verifytemp(publicKey [33]byte, message [32]byte, signature [64]byte) (bool, error) {
	Px, Py := Unmarshal(Curve, publicKey[:])

	if Px == nil || Py == nil || !Curve.IsOnCurve(Px, Py) {
		return false, errors.New("signature verification failed 1")
	}
	r := new(big.Int).SetBytes(signature[:32])
	if r.Cmp(Curve.P) >= 0 {
		return false, errors.New("r is larger than or equal to field size")
	}
	s := new(big.Int).SetBytes(signature[32:])
	if s.Cmp(Curve.N) >= 0 {
		return false, errors.New("s is larger than or equal to curve order")
	}
	e := Hashsig(Marshal(Curve,Px,Py),intToByte(r),message[:])
	sGx, sGy := Curve.ScalarBaseMult(intToByte(s))
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(Px, Py, intToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx, Ry := Curve.Add(sGx, sGy, ePx, ePy)
	//不懂为什么要看big.Jacobi(Ry, Curve.P) == 1？
	//if (Rx.Sign() == 0 && Ry.Sign() == 0) || big.Jacobi(Ry, Curve.P) != 1 || Rx.Cmp(r) != 0 {
	if (Rx.Sign() == 0 && Ry.Sign() == 0) ||  Rx.Cmp(r) != 0 {

			return false, errors.New("signature verification failed 2")
	}
	return true, nil
}

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