package main

import (
	"encoding/hex"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Circuit definition
type AddMulCircuit struct {
	X1     frontend.Variable `gnark:",public"`
	X2, X3 frontend.Variable
}

// Define declares the circuit's constraints
// x1 = (x2 * x3) + 2*x2 + 3 * x3
func (circuit *AddMulCircuit) Define(api frontend.API) error {
	tmp := api.Mul(circuit.X2, circuit.X3)

	res := api.Add(tmp, api.Mul(2, circuit.X2), api.Mul(3, circuit.X3))

	// assert that the statement x1 = (x2 * x3) + 2*x2 + 3 * x3 is true.
	api.AssertIsEqual(circuit.X1, res)
	return nil
}

func main() {

	// 1. Define the circuit
	var circuit AddMulCircuit

	// 2. Compile the circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		log.Println("circuit compilation error")
	}

	// 3. Setup KZG SRS (trusted setup)
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	// 4. Witness instantiation.
	w := AddMulCircuit{X1: 6, X2: 1, X3: 1}

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatal(err)
	}

	// 5. Generate proving & verification keys
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		log.Fatal(err)
	}

	// 6. Create and export Solidity verifier
	file, err := os.Create("Verifier.sol")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	err = vk.ExportSolidity(file)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Solidity verifier generated: Verifier.sol")

	// 7. Generate proof
	proof, err := plonk.Prove(ccs, pk, witnessFull)
	if err != nil {
		log.Fatal(err)
	}

	// 8. Verify proof
	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal(err)
	}

	// 9. Serialize proof for Solidity Using MarshalSolidity
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity()")
	}

	proofStr := hex.EncodeToString(_proof.MarshalSolidity())
	log.Println("Serialized Proof (Hex):", proofStr)

}
