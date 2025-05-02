package main

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/pkg/profile"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

func main() {
	// first we generate our witness
	var w circuit
	w.X = 1
	w.Y = 1
	witness, err := frontend.NewWitness(&w, fr.Modulus())

	if err != nil {
		panic(fmt.Errorf("generate witness: %w", err))
	}

	var c circuit
	ccs, err := frontend.Compile(fr.Modulus(), scs.NewBuilder, &c)

	// now we compile our circuit
	// note that we can also test with r1cs.NewBuilder (groth16)
	if err != nil {
		panic(fmt.Errorf("compile circuit: %w", err))
	}

	// now we solve the circuit using the solver;
	// (can use TraceProfile or CPUProfile as needed )
	// then run go tool trace trace.out
	p := profile.Start(profile.TraceProfile, profile.ProfilePath("."), profile.NoShutdownHook)

	start := time.Now()
	_ = ccs.IsSolved(witness)
	took := time.Since(start)

	p.Stop()
	if err != nil {
		panic(fmt.Errorf("solve circuit: %w", err))
	}

	fmt.Printf("solved in %s\n", took)

}

const n = 4

type circuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *circuit) Define(api frontend.API) error {
	for i := 0; i < n; i++ {
		circuit.X = api.Mul(circuit.X, circuit.X)
	}
	api.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}
