package schoco_test

import (
	"fmt"
	"testing"

	"github.com/hpe-usp-spire/schoco"
	"go.dedis.ch/kyber/v3"
)


func BenchmarkKeyCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = schoco.KeyPair() // Only measure the key creation
	}
}


func BenchmarkSignatureAggregation(b *testing.B) {
	for numMsgs := 1; numMsgs <= 40; numMsgs += 5 {
		b.Run(fmt.Sprintf("SignAgg_%d_msgs", numMsgs), func(b *testing.B) {
			// Setup: key pair
			sk, _ := schoco.KeyPair()

			// First signature
			baseMsg := fmt.Sprintf("msg%d", 1)
			sig := schoco.StdSign(baseMsg, sk)
			setSigR := []kyber.Point{}
			setMsg := []string{baseMsg}

			// Aggregate remaining signatures
			for i := 2; i <= numMsgs; i++ {
				msg := fmt.Sprintf("msg%d", i)
				partSig, nextSig := schoco.Aggregate(msg, sig)
				sig = nextSig
				setSigR = append([]kyber.Point{partSig}, setSigR...) // prepend
				setMsg = append([]string{msg}, setMsg...)           // prepend
			}

			// Measure aggregation time
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Recreate the signatures for aggregation test
				for i := 2; i <= numMsgs; i++ {
					msg := fmt.Sprintf("msg%d", i)
					partSig, nextSig := schoco.Aggregate(msg, sig)
					sig = nextSig
					setSigR = append([]kyber.Point{partSig}, setSigR...) // prepend
					setMsg = append([]string{msg}, setMsg...)           // prepend
				}
			}
		})
	}
}


func BenchmarkValidation(b *testing.B) {
	for numMsgs := 1; numMsgs <= 40; numMsgs += 5 {
		b.Run(fmt.Sprintf("Verify_%d_msgs", numMsgs), func(b *testing.B) {
			// Setup: key pair
			sk, pk := schoco.KeyPair()

			// First signature
			baseMsg := fmt.Sprintf("msg%d", 1)
			sig := schoco.StdSign(baseMsg, sk)
			setSigR := []kyber.Point{}
			setMsg := []string{baseMsg}

			// Aggregate remaining signatures
			for i := 2; i <= numMsgs; i++ {
				msg := fmt.Sprintf("msg%d", i)
				partSig, nextSig := schoco.Aggregate(msg, sig)
				sig = nextSig
				setSigR = append([]kyber.Point{partSig}, setSigR...) // prepend
				setMsg = append([]string{msg}, setMsg...)           // prepend
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !schoco.Verify(pk, setMsg, setSigR, sig) {
					b.Fatal("Verification failed")
				}
			}
		})
	}
}
