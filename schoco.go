package schoco

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"filippo.io/edwards25519"
)

/* ============================================================
   Types
============================================================ */

type Signature struct {
	R *edwards25519.Point
	S *edwards25519.Scalar
}

/* ============================================================
   Hash utilities
============================================================ */

func hashToScalar(parts ...[]byte) *edwards25519.Scalar {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	digest := h.Sum(nil) // 32 bytes SHA-256

	s := new(edwards25519.Scalar)
	s.SetBytesWithClamping(digest) // OK com 32 bytes
	return s
}

/* ============================================================
   Key generation
============================================================ */

func KeyPair() (*edwards25519.Scalar, *edwards25519.Point, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}

	sk := new(edwards25519.Scalar)
	sk.SetBytesWithClamping(seed[:])
	pk := new(edwards25519.Point).ScalarBaseMult(sk)
	return sk, pk, nil
}

/* ============================================================
   Standard Schnorr signature
============================================================ */

func StdSign(msg []byte, sk *edwards25519.Scalar) (*Signature, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	k := new(edwards25519.Scalar)
	k.SetBytesWithClamping(nonce[:])

	R := new(edwards25519.Point).ScalarBaseMult(k)
	pk := new(edwards25519.Point).ScalarBaseMult(sk)

	Rb := R.Bytes()
	PKb := pk.Bytes()

	h := hashToScalar(Rb[:], msg, PKb[:])

	S := new(edwards25519.Scalar)
	S.Multiply(h, sk)
	S.Negate(S)
	S.Add(S, k)

	return &Signature{R, S}, nil
}

/* ============================================================
   Standard Schnorr signature verification
============================================================ */

func StdVerify(msg []byte, sig *Signature, pk *edwards25519.Point) bool {
	if sig == nil || sig.R == nil || sig.S == nil || pk == nil {
		return false
	}

	// h = H(R || msg || pk)
	h := hashToScalar(sig.R.Bytes(), msg, pk.Bytes())

	// left = S*B
	left := new(edwards25519.Point).ScalarBaseMult(sig.S)

	// right = R - h*pk => R - h*pk = R + (-h*pk)
	hpk := new(edwards25519.Point).ScalarMult(h, pk)
	right := new(edwards25519.Point).Subtract(sig.R, hpk)

	return left.Equal(right) == 1
}

/* ============================================================
   SchoCo aggregation
============================================================ */

func Aggregate(
	msg []byte,
	prev *Signature,
) (*edwards25519.Point, *Signature, error) {

	var nonce [64]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}

	k, err := new(edwards25519.Scalar).SetUniformBytes(nonce[:])
	if err != nil {
		return nil, nil, err
	}

	R := new(edwards25519.Point).ScalarBaseMult(k)

	aggKey := prev.S
	partSig := prev.R

	pk := new(edwards25519.Point).ScalarBaseMult(aggKey)

	Rb := R.Bytes()
	PKb := pk.Bytes()

	h := hashToScalar(Rb[:], msg, PKb[:])

	S := new(edwards25519.Scalar)
	S.Multiply(h, aggKey)
	S.Negate(S)
	S.Add(S, k)

	return partSig, &Signature{R, S}, nil
}

/* ============================================================
   Verification
============================================================ */

func Verify(
	rootPK *edwards25519.Point,
	messages [][]byte,
	partSigs []*edwards25519.Point,
	lastSig *Signature,
) bool {

	if len(partSigs) != len(messages)-1 {
		return false
	}

	y := new(edwards25519.Point).Set(rootPK)

	for i := len(partSigs) - 1; i >= 0; i-- {
		Rb := partSigs[i].Bytes()
		Yb := y.Bytes()

		h := hashToScalar(Rb[:], messages[i+1], Yb[:])

		hy := new(edwards25519.Point).ScalarMult(h, y)
		y.Subtract(partSigs[i], hy)
	}

	Rb := lastSig.R.Bytes()
	Yb := y.Bytes()

	h := hashToScalar(Rb[:], messages[0], Yb[:])

	left := new(edwards25519.Point).ScalarBaseMult(lastSig.S)
	right := new(edwards25519.Point).ScalarMult(h, y)
	right.Subtract(lastSig.R, right)

	return left.Equal(right) == 1
}

/* ============================================================
   Serialization
============================================================ */

func (s *Signature) MarshalBinary() ([]byte, error) {
	if s == nil || s.R == nil || s.S == nil {
		return nil, errors.New("nil signature")
	}

	out := make([]byte, 64)
	copy(out[:32], s.R.Bytes()[:])
	copy(out[32:], s.S.Bytes()[:])
	return out, nil
}

func UnmarshalSignature(data []byte) (*Signature, error) {
	if len(data) != 64 {
		return nil, errors.New("invalid signature length")
	}

	R, err := new(edwards25519.Point).SetBytes(data[:32])
	if err != nil {
		return nil, err
	}

	S := new(edwards25519.Scalar)
	if _, err := S.SetCanonicalBytes(data[32:]); err != nil {
		return nil, err
	}

	return &Signature{R, S}, nil
}
