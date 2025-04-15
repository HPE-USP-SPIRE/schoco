package schoco_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"go.dedis.ch/kyber/v3"
	"github.com/hpe-usp-spire/schoco"
)

type BenchmarkResult struct {
	Hops               int64 `json:"hops"`
	SignIndividualNS   int64 `json:"sign_individual_ns"`
	SignAggregateNS    int64 `json:"sign_aggregate_ns"`
	VerifyIndividualNS int64 `json:"verify_individual_ns"`
	VerifyAggregateNS  int64 `json:"verify_aggregate_ns"`
}

func TestCompareAggregation(t *testing.T) {
	var results []BenchmarkResult

	for hops := int64(1); hops <= 40; hops += 5 {
		var (
			sk, pk      = schoco.KeyPair()
			msgs        []string
			sigs        []schoco.Signature
			// partSigs    []kyber.Point
			aggSig      schoco.Signature
			aggMsgs     []string
			aggPartSigs []kyber.Point
		)

		// --- Generate Messages ---
		for i := int64(0); i < hops; i++ {
			msgs = append(msgs, fmt.Sprintf("msg-%d", i))
		}

		// --- Sign Individually ---
		start := time.Now()
		for _, m := range msgs {
			sigs = append(sigs, schoco.StdSign(m, sk))
		}
		signIndividualNS := time.Since(start).Nanoseconds()

		// --- Sign Aggregated ---
		start = time.Now()
		baseMsg := msgs[0]
		aggSig = schoco.StdSign(baseMsg, sk)
		aggMsgs = []string{baseMsg}
		for i := 1; i < len(msgs); i++ {
			partSig, newSig := schoco.Aggregate(msgs[i], aggSig)
			aggSig = newSig
			aggPartSigs = append([]kyber.Point{partSig}, aggPartSigs...) // prepend
			aggMsgs = append([]string{msgs[i]}, aggMsgs...)              // prepend
		}
		signAggregateNS := time.Since(start).Nanoseconds()

		// --- Verify Individually ---
		start = time.Now()
		for i, m := range msgs {
			if !schoco.StdVerify(m, sigs[i], pk) {
				t.Fatal("std verify failed")
			}
		}
		verifyIndividualNS := time.Since(start).Nanoseconds()

		// --- Verify Aggregated ---
		start = time.Now()
		if !schoco.Verify(pk, aggMsgs, aggPartSigs, aggSig) {
			t.Fatal("agg verify failed")
		}
		verifyAggregateNS := time.Since(start).Nanoseconds()

		// Append result
		results = append(results, BenchmarkResult{
			Hops:               hops,
			SignIndividualNS:   signIndividualNS,
			SignAggregateNS:    signAggregateNS,
			VerifyIndividualNS: verifyIndividualNS,
			VerifyAggregateNS:  verifyAggregateNS,
		})
	}

	// --- Print JSON ---
	jsonOut, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(jsonOut))
}
