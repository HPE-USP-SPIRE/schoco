// SchoCo package allows to concatenate Schnorr EdDSA signatures.
// 
// Usage:
// Given an existing signature S_1 over m_1, one can concatenate it with a new one, by doing:
// 1 - Extract the aggregation key and partial signature from S_1:
// 			aggKey, partS1 := S_1.ExtractAggKey()
// 2 - Use the aggKey to sign a new message m_2
// 3 - The concatenated signature is {partS1, S_2}
// 
// The validation requires: (IMPORTANT: All messages and partial signatures must be in reverse order )
// - The set of partial signatures (partsig_n, ..., partsig_1)
// - The last signature (sig_n+1)
// - The root public key 
// - The set of signed messages (message_n, ..., message_1)

package schoco

import (
	"fmt"
	"errors"

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

// given a new message m and an existing signature sig_1,
// return an schoco signature sig_2 = {partSig1, sig2}
// If sig_1 is already a concatenated signature, aggregation uses only the last complete signature (partSig_n, aggkey_n).
// The resulting concatenated signature is composed of all previous partial signatures (partsig_1, ..., partsig_n) and the new signature sig_n+1.
func Aggregate(m string, sig1 Signature) (kyber.Point, Signature) {

	// Pick a random k from allowed set.
	k := curve.Scalar().Pick(curve.RandomStream())

	// r = k * G (a.k.a the same operation as r = g^k)
	r := curve.Point().Mul(k, g)

	// Extract aggKey and partial signature
	aggKey, partSig1 := sig1.ExtractAggKey()

	// h := Hash(r.String() + m + publicKey)
	publicKey := curve.Point().Mul(aggKey, g)
	h := Hash(r.String() + m + publicKey.String())

	// s = k - e * x
	s := curve.Scalar().Sub(k, curve.Scalar().Mul(h, aggKey))

	// Return the partial signature and the new full signature
	return partSig1, Signature{R: r, S: s}
}

// Verification with support to both STD and concatenated schnorr signatures. If validating a std signature, setPartSig must be []kyber.Point{}.
// origpubkey: first public key
// setPartSig: array with all partial signatures
// setMessages: array with all messages
// lastsig: last signature (complete)
func Verify(origpubkey kyber.Point, setMessages []string, setPartSig []kyber.Point, lastsig Signature) bool {

	// Important to note that as new assertions are added in the beginning of the token, the content of arrays is in reverse order.
	// e.g. setPartSig[0] = last appended signature.
	if (len(setPartSig)) != len(setMessages)-1 {
		fmt.Println("Incorrect parameters!")
		return false
	}

	var y kyber.Point
	var leftside, rightside kyber.Point

	if len(setPartSig) == 0 {
		y = origpubkey

		// check if g ^ lastsig.S = lastsig.R - y ^ lastHash
		leftside = curve.Point().Mul(lastsig.S, g)
		h := Hash(lastsig.R.String() + setMessages[0] + y.String())
		rightside = curve.Point().Sub(lastsig.R, curve.Point().Mul(h, y))
	} else {
		var i = len(setPartSig) - 1

		// calculate all y's from first to last-1 parts
		for i >= 0 {
			if i == len(setPartSig)-1 {
				y = origpubkey
			} else {
				h := Hash(setPartSig[i+1].String() + setMessages[i+2] + y.String())
				y = curve.Point().Sub(setPartSig[i+1], curve.Point().Mul(h, y))
			}
			i--
		}

		// calculate last y
		h := Hash(setPartSig[i+1].String() + setMessages[i+2] + y.String())
		y = curve.Point().Sub(setPartSig[i+1], curve.Point().Mul(h, y))

		// check if g ^ lastsig.S = lastsig.R - y ^ lastHash
		h = Hash(lastsig.R.String() + setMessages[i+1] + y.String())
		leftside = curve.Point().Mul(lastsig.S, g)
		rightside = curve.Point().Sub(lastsig.R, curve.Point().Mul(h, y))
	}

	return leftside.Equal(rightside)
}

// Sign using Schnorr EdDSA
// m: Message
// x: Private key
func StdSign(m string, z kyber.Scalar) Signature {

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

// If given ID, return the corresponding keypair. Otherwise, create a new random key pair
func KeyPair(id ...string) (kyber.Scalar, kyber.Point) {

	var privateKey kyber.Scalar
	var publicKey kyber.Point
	if len(id) == 0 {
		privateKey = curve.Scalar().Pick(curve.RandomStream())
	} else {
		privateKey = Hash(id[0])
	}
	publicKey = curve.Point().Mul(privateKey, curve.Point().Base())

	return privateKey, publicKey
}

// Return Signature in a string format
func (S Signature) String() string {
	return fmt.Sprintf("(r=%s, s=%s)", S.R, S.S)
}

// Return the aggregation key and partial signature
func (S Signature) ExtractAggKey() (aggKey kyber.Scalar, partSig kyber.Point) {
	return S.S, S.R
}

// ToByte encodes a Signature struct to []byte
func (sig Signature) ToByte() ([]byte, error) {

    rBytes, err := sig.R.MarshalBinary()
    if err != nil {
        return nil, err
    }

    sBytes, err := sig.S.MarshalBinary()
    if err != nil {
        return nil, err
    }

    return append(rBytes, sBytes...), nil
}

// Given string, return hash Scalar
func Hash(s string) kyber.Scalar {
	sha256.Reset()
	sha256.Write([]byte(s))

	return curve.Scalar().SetBytes(sha256.Sum(nil))
}

// Convert []byte to a Signature struct
func ByteToSignature(data []byte) (Signature, error) {

	// Initialize signature
    sig := Signature{
        R: curve.Point().Null(), 
        S: curve.Scalar().Zero(), 
    }

    rLen := len(data) / 2
    if rLen*2 != len(data) {
        return sig, errors.New("invalid signature length")
    }

    if err := sig.R.UnmarshalBinary(data[:rLen]); err != nil {
        return sig, err
    }

	sig.S = curve.Scalar().SetBytes(data[rLen:])

    if sig.S == nil {
        return sig, errors.New("invalid scalar value")
    }
    return sig, nil
}

// Convert a []byte to a kyber point
func ByteToPoint(pointBytes []byte) (kyber.Point, error) {
    point := curve.Point().Null()
    if err := point.UnmarshalBinary(pointBytes); err != nil {
        return nil, err
    }
    return point, nil
}

// Convert a kyber point to []byte
func PointToByte(point kyber.Point) ([]byte, error) {
    pointBytes, err := point.MarshalBinary()
    if err != nil {
        return nil, err
    }
    return pointBytes, nil
}


//  Draft ///////////////////////////////////////


//  The functions below can or not be part of the package. Must evaluate the need and convenience
// Verification function using []byte instead specific kyber and Signature struct
func TestByteVerify(rootPubKeyBytes []byte, setMessages []string, setPartSig [][]byte, lastSigBytes []byte) bool {

	// Important to note that as new assertions are added in the beginning of the token, the content of arrays is in reverse order.
	// e.g. setPartSig[0] = last appended signature.
	if (len(setPartSig)) != len(setMessages)-1 {
		fmt.Println("Incorrect parameters!")
		return false
	}

	// Convert all
	// 
	// Decode origpubkey from []byte
	rootPK, err := ByteToPoint(rootPubKeyBytes)
	if err != nil {
		// Handle error
	}

	var y kyber.Point
	var leftside, rightside kyber.Point

	if len(setPartSig) == 0 {
		y = rootPK

		// check if g ^ lastsig.S = lastsig.R - y ^ lastHash
		lastSig, _ := ByteToSignature(lastSigBytes)
		leftside = curve.Point().Mul(lastSig.S, g)
		h := Hash(lastSig.R.String() + setMessages[0] + y.String())
		rightside = curve.Point().Sub(lastSig.R, curve.Point().Mul(h, y))
	} else {
		var i = len(setPartSig) - 1

		// calculate all y's from first to last-1 parts
		for i >= 0 {
			if i == len(setPartSig)-1 {
				y = rootPK
			} else {
				// Decode partialsig from []byte
				partSig, err := ByteToPoint(setPartSig[i+1])
				if err != nil {
					// Handle error
				}
				h := Hash(partSig.String() + setMessages[i+2] + y.String())
				y = curve.Point().Sub(partSig, curve.Point().Mul(h, y))
			}
			i--
		}

		// calculate last y
		partSig, err := ByteToPoint(setPartSig[i+1])
		if err != nil {
			// Handle error
		}
		h := Hash(partSig.String() + setMessages[i+2] + y.String())
		y = curve.Point().Sub(partSig, curve.Point().Mul(h, y))

		// check if g ^ lastsig.S = lastsig.R - y ^ lastHash
		lastSig, err := ByteToSignature(lastSigBytes)
		if err != nil {
			// Handle error
		}
		h = Hash(lastSig.R.String() + setMessages[i+1] + y.String())
		leftside = curve.Point().Mul(lastSig.S, g)
		rightside = curve.Point().Sub(lastSig.R, curve.Point().Mul(h, y))
	}

	return leftside.Equal(rightside)
}


// Same aggregation function, but using signatures and partial signatures in []byte format for compatibility purposes.
func TestByteAgg(m string, prevSig []byte) ([]byte, []byte) {

	// Pick a random k from allowed set.
	k := curve.Scalar().Pick(curve.RandomStream())

	// r = k * G (a.k.a the same operation as r = g^k)
	r := curve.Point().Mul(k, g)

	// Convert sig from []byte to Signature
	// TODO: Error handling
	sig, _ := ByteToSignature(prevSig)

	// Extract aggKey and partial signature
	aggKey, prevPartial := sig.ExtractAggKey()

	// h := Hash(r.String() + m + publicKey)
	publicKey := curve.Point().Mul(aggKey, g)
	h := Hash(r.String() + m + publicKey.String())

	// s = k - e * x
	s := curve.Scalar().Sub(k, curve.Scalar().Mul(h, aggKey))

	// Convert signature to byte
	// TODO: Error handling
	fullSig, _ := Signature{R: r, S: s}.ToByte()
	prevPartialBytes, _ :=  prevPartial.MarshalBinary()

	// Return the partial signature and the new full signature
	return prevPartialBytes, fullSig
}