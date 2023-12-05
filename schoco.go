// SchoCo package allows to concatenate two Schnorr EdDSA signatures.
// 
// Usage:
// Given an existing signature S_1 over m_1, one can concatenate it with a new one, by doing:
// 1 - Extract the aggregation key and partial signature from S_1:
// 			aggKey, partS1 := S_1.ExtractAggKey()
// 2 - Use the aggKey to sign a new message m_2
// 3 - The concatenated signature is {partS1, S_2}
// 
// The validation requires:
// - The concatenated signature e.g.: {partS1, S_2}
// - The root public key
// - The messages. e.g.: {m_1, m_2}
package schoco

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

// Set parameters
var (
	curve = edwards25519.NewBlakeSHA256Ed25519()
	sha256 = curve.Hash()
	g = curve.Point().Base()
)

type Signature struct {
	R kyber.Point
	S kyber.Scalar
}

// Sign using Schnorr EdDSA
// SchoCo uses the same signature algorithm. 
// Difference is in the key used
// m: Message
// x: Private key
func Sign(m string, z kyber.Scalar) Signature {

	// Pick a random k from allowed set.
	k := curve.Scalar().Pick(curve.RandomStream())

	// r = k * G (a.k.a the same operation as r = g^k)
	r := curve.Point().Mul(k, g)

	// h := Hash(r.String() + m + publicKey)
	publicKey := curve.Point().Mul(z, g)
	h := Hash(r.String() + m + publicKey.String())

	// s = k - e * x
	s := curve.Scalar().Sub(k, curve.Scalar().Mul(h, z))

	return Signature{R: r, S: s}
}

// given a new message m and an existing signature,
// return an schoco signature Sig_2 = {partSig1, Sig2}
func Aggregate(m string, sig Signature) (kyber.Point, Signature) {

	// Pick a random k from allowed set.
	k := curve.Scalar().Pick(curve.RandomStream())

	// r = k * G (a.k.a the same operation as r = g^k)
	r := curve.Point().Mul(k, g)

	// Extract aggKey
	aggKey, partSig := sig.ExtractAggKey()

	// h := Hash(r.String() + m + publicKey)
	publicKey := curve.Point().Mul(aggKey, g)
	h := Hash(r.String() + m + publicKey.String())

	// s = k - e * x
	s := curve.Scalar().Sub(k, curve.Scalar().Mul(h, aggKey))

	return partSig, Signature{R: r, S: s}
}

// Verify concatenated EdDSA signatures using SchoCo scheme
// origpubkey: first public key
// setSigR: array with all Sig.R
// setM: array with all messages
// lastsigS: last signature.S
func Verify(origpubkey kyber.Point, setSigR []kyber.Point, setM []string, lastsigS kyber.Scalar) bool {

	// Important to note that as new assertions are added in the beginning of the token, the content of arrays is in reverse order.
	// e.g. setSigR[0] = last appended signature.
	if (len(setSigR)) != len(setM) {
		fmt.Println("Incorrect parameters!")
		return false
	}

	var i = len(setSigR) - 1
	var y kyber.Point
	var h kyber.Scalar

	if len(setSigR) == 1 {
		y = origpubkey
		// check if g ^ lastsig.S = lastsig.R - y ^ lastHash
		leftside := curve.Point().Mul(lastsigS, g)
		h = Hash(setSigR[i].String() + setM[i] + y.String())
		rightside := curve.Point().Sub(setSigR[i], curve.Point().Mul(h, y))
		return leftside.Equal(rightside)
	}

	// calculate all y's from first to last-1 parts
	for i > 0 {
		if i == len(setSigR)-1 {
			y = origpubkey
		} else {
			h = Hash(setSigR[i+1].String() + setM[i+1] + y.String())
			y = curve.Point().Sub(setSigR[i+1], curve.Point().Mul(h, y))
		}
		i--
	}

	// calculate last y
	h = Hash(setSigR[i+1].String() + setM[i+1] + y.String())
	y = curve.Point().Sub(setSigR[i+1], curve.Point().Mul(h, y))

	// check if g ^ lastsig.S = lastsig.R - y ^ lastHash
	leftside := curve.Point().Mul(lastsigS, g)
	h = Hash(setSigR[i].String() + setM[i] + y.String())
	rightside := curve.Point().Sub(setSigR[i], curve.Point().Mul(h, y))

	return leftside.Equal(rightside)
}

// StdVerify is the STD validation of a Schnorr EdDSA signature
// TODO: Keeping for debugging purposes. Remove it later.
// m: Message
// s: Signature
// y: Public key
func StdVerify(m string, S Signature, y kyber.Point) bool {

	h := Hash(S.R.String() + m + y.String())

	// Attempt to reconstruct 's * G' with a provided signature; s * G = r - h * y
	sGv := curve.Point().Sub(S.R, curve.Point().Mul(h, y))

	// Construct the actual 's * G'
	sG := curve.Point().Mul(S.S, g)

	// Equality check; ensure signature and public key outputs to s * G.
	return sG.Equal(sGv)
}

// Given ID, return a keypair
func IDKeyPair(id string) (kyber.Scalar, kyber.Point) {

	privateKey := Hash(id)
	publicKey := curve.Point().Mul(privateKey, curve.Point().Base())

	return privateKey, publicKey
}

// Return a new random key pair
func RandomKeyPair() (kyber.Scalar, kyber.Point) {

	privateKey := curve.Scalar().Pick(curve.RandomStream())
	publicKey := curve.Point().Mul(privateKey, curve.Point().Base())

	return privateKey, publicKey
}

// Given string, return hash Scalar
func Hash(s string) kyber.Scalar {
	sha256.Reset()
	sha256.Write([]byte(s))

	return curve.Scalar().SetBytes(sha256.Sum(nil))
}

func (S Signature) String() string {
	return fmt.Sprintf("(r=%s, s=%s)", S.R, S.S)
}

// Return the aggregation key and partial signature
func (S Signature) ExtractAggKey() (aggKey kyber.Scalar, partSig kyber.Point) {
	return S.S, S.R
}