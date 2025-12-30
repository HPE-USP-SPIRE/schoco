package schoco_test

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/hpe-usp-spire/schoco"
)

var (
	message1 = []byte("first message")
	message2 = []byte("second message")
	message3 = []byte("third message")
)

func TestBasic(t *testing.T) {
	t.Run("Std Schnorr Signature creation and Validation using random key pair", func(t *testing.T) {
		rootSecretKey, rootPublicKey, err := schoco.KeyPair()
		if err != nil {
			t.Fatalf("KeyPair error: %v", err)
		}

		signature, err := schoco.StdSign(message1, rootSecretKey)
		if err != nil {
			t.Fatalf("StdSign error: %v", err)
		}

		// ✅ Verificação usando StdVerify
		if !schoco.StdVerify(message1, signature, rootPublicKey) {
			t.Error("StdVerify failed for individual signature")
		}

		// Verificação usando Verify (como antes)
		if !schoco.Verify(rootPublicKey, [][]byte{message1}, []*edwards25519.Point{}, signature) {
			t.Error("Verify failed for individual signature")
		}

		// Marshal/unmarshal roundtrip
		b, err := signature.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary error: %v", err)
		}
		rec, err := schoco.UnmarshalSignature(b)
		if err != nil {
			t.Fatalf("UnmarshalSignature error: %v", err)
		}

		if !schoco.StdVerify(message1, rec, rootPublicKey) {
			t.Error("StdVerify failed after unmarshalling")
		}
	})

	t.Run("Aggregate signatures and validate", func(t *testing.T) {
		rootSecretKey, rootPublicKey, err := schoco.KeyPair()
		if err != nil {
			t.Fatalf("KeyPair error: %v", err)
		}

		sig1, err := schoco.StdSign(message1, rootSecretKey)
		if err != nil {
			t.Fatalf("StdSign error: %v", err)
		}

		partSig1, sig2, err := schoco.Aggregate(message2, sig1)
		if err != nil {
			t.Fatalf("Aggregate error: %v", err)
		}

		// Validar agregação com Verify
		if !schoco.Verify(rootPublicKey, [][]byte{message2, message1}, []*edwards25519.Point{partSig1}, sig2) {
			t.Error("Aggregate verification failed")
		}

		// Validar std individual de sig1
		if !schoco.StdVerify(message1, sig1, rootPublicKey) {
			t.Error("StdVerify failed for original signature")
		}
	})
}


func TestVerify(t *testing.T) {
	// Create root key pair
	rootSecretKey, rootPublicKey, err := schoco.KeyPair()
	if err != nil {
		t.Fatalf("KeyPair error: %v", err)
	}

	// generate signature1
	signature1, err := schoco.StdSign(message1, rootSecretKey)
	if err != nil {
		t.Fatalf("StdSign error: %v", err)
	}

	// Extract aggregation key (S) and partial signature (R) directly from the struct
	aggKey := signature1.S    // *edwards25519.Scalar
	partSig := signature1.R   // *edwards25519.Point

	// Use aggregation key to sign a new message (signature2)
	signature2, err := schoco.StdSign(message2, aggKey)
	if err != nil {
		t.Fatalf("StdSign (aggKey) error: %v", err)
	}

	// Use schoco.Aggregate to aggregate a new signature (signature3)
	partSig2, signature3, err := schoco.Aggregate(message3, signature2)
	if err != nil {
		t.Fatalf("Aggregate error: %v", err)
	}

	t.Run("Validate Std signature (signature1) with schoco.Verify", func(t *testing.T) {
		setSigR := []*edwards25519.Point{}
		setMsg := [][]byte{message1}

		if !schoco.Verify(rootPublicKey, setMsg, setSigR, signature1) {
			t.Error("Validate Std signature with schoco.Verify failed!")
		}
	})

	t.Run("Validate SchoCo signature with schoco.Verify (single partial)", func(t *testing.T) {
		setSigR := []*edwards25519.Point{partSig}
		setMsg := [][]byte{message2, message1}

		if !schoco.Verify(rootPublicKey, setMsg, setSigR, signature2) {
			t.Error("Validate SchoCo signature with schoco.Verify failed!")
		}
	})

	t.Run("Validate signature2 with schoco.Verify using agg public key", func(t *testing.T) {
		// aggPK = aggKey * G
		aggPK := new(edwards25519.Point).ScalarBaseMult(aggKey)

		if !schoco.Verify(aggPK, [][]byte{message2}, []*edwards25519.Point{}, signature2) {
			t.Error("Signature2 verification with agg public key failed")
		}
	})

	t.Run("Validate signature3 (two partials) with schoco.Verify", func(t *testing.T) {
		setSigR := []*edwards25519.Point{partSig2, partSig}
		setMsg := [][]byte{message3, message2, message1}

		if !schoco.Verify(rootPublicKey, setMsg, setSigR, signature3) {
			t.Error("Validate SchoCo signature (3 messages) with schoco.Verify failed!")
		}
	})
}
