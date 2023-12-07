package schoco_test

import (
	"testing"

	"github.com/hpe-usp-spire/schoco"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3"
)

var (
	curve = edwards25519.NewBlakeSHA256Ed25519()
	rootSecretKey = curve.Scalar().Pick(curve.RandomStream())
	rootPublicKey = curve.Point().Mul(rootSecretKey, curve.Point().Base())
	message1 = "first message"
	message2 = "second message"
	message3 = "third message"
)

func TestBasic(t *testing.T) {
	t.Run("Std Schnorr Signature creation and Validation", func(t *testing.T) {

		// generate signature
		signature := schoco.StdSign(message1, rootSecretKey)

		// Validate the signature using the public key
		if !schoco.StdVerify(message1, signature, rootPublicKey) {
			t.Error("Signature is not valid for the provided message and public key")
		}
	})

	t.Run("Test schoco.Aggregate: ", func(t *testing.T) { 

		// generate signature
		signature1 := schoco.StdSign(message1, rootSecretKey)

		// convert signature to bytes
		sig1Bytes, err := signature1.ToByte()
		if err != nil {
			t.Error("Error converting sig to bytes")
		}

		// Aggregate signature1 with a new signature over message2
		partsig1, signature2 := schoco.Aggregate(message2, signature1)
		partsig1Bytes, signature2Bytes := schoco.NewAgg(message2, sig1Bytes)


		// validate concatenated signature
		setSigR := []kyber.Point{partsig1}
		setMsg := []string{message2, message1}
		if !schoco.Verify(rootPublicKey, setMsg, setSigR, signature2)	{
			t.Error("Validate schoco.Aggregate with schoco.Verify failed!")
		}

		// validate using bytes
		// Encode rootPublicKey to []byte
		rootPublicKeyBytes, err := schoco.PointToByte(rootPublicKey)
		if err != nil {
			// Handle error
		}
		setPartSigBytes := [][]byte{partsig1Bytes}


		if !schoco.NewVerify(rootPublicKeyBytes, setMsg, setPartSigBytes, signature2Bytes)	{
			t.Error("Validate schoco.Aggregate with schoco.Verify failed!")
		}
	})
}

func TestVerify(t *testing.T) {

	// generate signature
	signature1 := schoco.StdSign(message1, rootSecretKey)

	// Extract aggregation key and partial signature
	aggKey, partSig := signature1.ExtractAggKey()

	// Use aggregation key to sign a new message
	signature2 := schoco.StdSign(message2, aggKey)

	// Use schoCo.Aggregate to aggregate a new signature
	partsig2, signature3 := schoco.Aggregate(message3, signature2)

	t.Run("Validate Std signature (signature1) with schoco.Verify: ", func(t *testing.T) { 
		setSigR := []kyber.Point{}
		setMsg := []string{message1}

		if !schoco.Verify(rootPublicKey, setMsg, setSigR, signature1)	{
			t.Error("Validate Std signature with schoco.Verify failed!")
		}
	})

	t.Run("Validate SchoCo signature with schoco.Verify: ", func(t *testing.T) { 
		setSigR := []kyber.Point{partSig}
		setMsg := []string{message2, message1}

		if !schoco.Verify(rootPublicKey, setMsg, setSigR, signature2)	{
			t.Error("Validate SchoCo signature with schoco.Verify failed!")
		}
	})

	t.Run("Validate signature2 with schoco.StdVerify: ", func(t *testing.T) { 

		// Validate the signature using the agg public key
		aggPK := curve.Point().Mul(aggKey, curve.Point().Base())
		if !schoco.StdVerify(message2, signature2, aggPK) {
			t.Error("Signature is not valid for the provided message and public key")
		}
	})

	t.Run("Validate signature3 with schoco.Verify: ", func(t *testing.T) { 
		setSigR := []kyber.Point{partsig2, partSig}
		setMsg := []string{message3, message2, message1}

		if !schoco.Verify(rootPublicKey, setMsg, setSigR, signature3)	{
			t.Error("Validate SchoCo signature with schoco.Verify failed!")
		}
	})
}