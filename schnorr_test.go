package main

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/hbakhtiyor/schnorr"
	"math/big"
	"testing"
)

func Test_Schnorr(t *testing.T)  {
	//generate 2 keys
	privKey, err := btcec.NewPrivateKey(btcec.S256())
	if err!=nil {
		t.Fatal(err)
	}
	privKeyInt := privKey.D
	publicKey := privKey.PubKey()
	var pk [33]byte
	copy(pk[:],publicKey.SerializeCompressed())
	privKey2,err := btcec.NewPrivateKey(btcec.S256())
	if err!=nil {
		t.Fatal(err)
	}
	publicKey2 := privKey2.PubKey()
	var pk2   [33]byte
	copy(pk2[:],publicKey2.SerializeCompressed())
	//generate message [32]byte
	var m [32]byte
	msg,err := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	if err != nil && t != nil {
		t.Fatalf("Unexpected error from hex.DecodeString(%s): %v\n", m, err)
	}
	copy(m[:], msg)
	//sign by key1
	sig,err := schnorr.Sign(privKeyInt,m)
	if err != nil && t!=nil{
		t.Fatalf("Unexpected error from Sign: %v\n",err)
	}
	fmt.Printf("%v",sig)
	//verify by key1
	ok1,err:=schnorr.Verify(pk,m,sig)
	if err != nil && t!=nil{
		t.Fatalf("Unexpected error from Verify: %v\n",err)
	}
	fmt.Println(ok1)
	//verify by key 2
	//test result: Unexpected error from Verify: signature verification failed
	ok2,err := schnorr.Verify(pk2,m,sig)
	if err != nil && t!=nil{
		t.Fatalf("Unexpected error from Verify: %v\n",err)
	}
	fmt.Println(ok2)
}

func Test_AggregateSig(t *testing.T) {
	var publicKey [33]byte
	//generate keys
	privKey1, err := btcec.NewPrivateKey(btcec.S256())
	if err!=nil {
		t.Fatal(err)
	}
	privKey2,err := btcec.NewPrivateKey(btcec.S256())
	if err!=nil {
		t.Fatal(err)
	}
	privKeys := []*big.Int{privKey1.D,privKey2.D}
	//generate message [32]byte
	var m [32]byte
	msg,err := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	if err != nil && t != nil {
		t.Fatalf("Unexpected error from hex.DecodeString(%s): %v\n", m, err)
	}
	copy(m[:], msg)
	//Sign AggregateSig
	sig,err:=schnorr.AggregateSignatures(privKeys,m)
	if err != nil && t!=nil{
		t.Fatalf("Unexpected error from Sign: %v\n",err)
	}
	fmt.Printf("%v",sig)
	//Genenrate verifing key by adding the publickeys on the curve
	publicKey1 := privKey1.PubKey().SerializeCompressed()
	publicKey2 := privKey2.PubKey().SerializeCompressed()
	copy(publicKey[:],publicKey1)
	p1x,p1y := schnorr.Unmarshal(btcec.S256(),publicKey[:])
	copy(publicKey[:],publicKey2)
	p2x,p2y:=schnorr.Unmarshal(btcec.S256(),publicKey[:])
	px,py := btcec.S256().Add(p1x,p1y,p2x,p2y)
	copy(publicKey[:],schnorr.Marshal(btcec.S256(),px,py))
	//Verify AggregateSig
	if result, err := schnorr.Verify(publicKey, m, sig); err != nil {
		fmt.Printf("The signature verification failed: %v\n", err)
	} else if result {
		fmt.Println("The signature is valid.")
	}
}
func Test_Utils(t *testing.T){
	priv1,_ := GenPrivatekey()
	priv2,_ := GenPrivatekey()
	priv3,_ := GenPrivatekey()
	privKeys := []*big.Int{priv2.D,priv1.D,priv3.D}
	//generate message [32]byte
	var m [32]byte
	msg,err := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	if err != nil && t != nil {
		t.Fatalf("Unexpected error from hex.DecodeString(%s): %v\n", m, err)
	}
	copy(m[:], msg)
	sig,err := schnorr.AggregateSignatures(privKeys,m)
	pks := []*PublicKey {priv1.PubKey(),priv2.PubKey(),priv3.PubKey()}
	pubkey,err := AddPubkeys(pks)
	if err != nil && t != nil {
		t.Fatalf("Unexpected error from addpubkeys: %v\n", err)
	}
	if result, err := schnorr.Verify(pubkey, m, sig); err != nil {
		fmt.Printf("The signature verification failed: %v\n", err)
	} else if result {
		fmt.Println("The signature is valid.")
	}
}
