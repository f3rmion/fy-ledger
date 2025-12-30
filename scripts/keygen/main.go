// FROST Key Generation and Signing Helper
// Generates FROST key shares and can perform software participant operations
// for testing with the Ledger app.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/frost"
)

type KeyShareOutput struct {
	Participant int    `json:"participant"`
	GroupKey    string `json:"group_key"`    // 32 bytes compressed
	ID          string `json:"id"`           // 32 bytes (id in first 2 bytes, rest zero)
	SecretShare string `json:"secret_share"` // 32 bytes
	PublicShare string `json:"public_share"` // 32 bytes compressed (for verification)
}

type KeyGenOutput struct {
	Threshold int              `json:"threshold"`
	Total     int              `json:"total"`
	Shares    []KeyShareOutput `json:"shares"`
}

type CommitmentOutput struct {
	Participant   int    `json:"participant"`
	HidingNonce   string `json:"hiding_nonce"`   // 32 bytes (secret)
	BindingNonce  string `json:"binding_nonce"`  // 32 bytes (secret)
	HidingCommit  string `json:"hiding_commit"`  // 32 bytes
	BindingCommit string `json:"binding_commit"` // 32 bytes
}

type SignInput struct {
	MessageHash  string             `json:"message_hash"` // 32 bytes
	GroupKey     string             `json:"group_key"`    // 32 bytes
	Participants []ParticipantInput `json:"participants"` // All signing participants
	SignerIndex  int                `json:"signer_index"` // Index of this signer in participants
}

type ParticipantInput struct {
	ID            int    `json:"id"`
	SecretShare   string `json:"secret_share,omitempty"`   // Only for local signer
	HidingNonce   string `json:"hiding_nonce,omitempty"`   // Only for local signer
	BindingNonce  string `json:"binding_nonce,omitempty"`  // Only for local signer
	HidingCommit  string `json:"hiding_commit"`
	BindingCommit string `json:"binding_commit"`
}

type SignOutput struct {
	PartialSig string `json:"partial_sig"` // 32 bytes
}

type AggregateInput struct {
	GroupKey     string             `json:"group_key"`
	MessageHash  string             `json:"message_hash"`
	Participants []ParticipantInput `json:"participants"`
	PartialSigs  []PartialSigInput  `json:"partial_sigs"`
}

type PartialSigInput struct {
	ID         int    `json:"id"`
	PartialSig string `json:"partial_sig"`
}

type AggregateOutput struct {
	R     string `json:"R"`     // 32 bytes (group commitment)
	Z     string `json:"z"`     // 32 bytes (aggregated signature)
	Valid bool   `json:"valid"` // Verification result
}

func main() {
	// Subcommands
	keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
	threshold := keygenCmd.Int("t", 2, "Threshold (minimum signers)")
	total := keygenCmd.Int("n", 3, "Total participants")

	commitCmd := flag.NewFlagSet("commit", flag.ExitOnError)
	participantID := commitCmd.Int("id", 1, "Participant ID")

	signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
	aggregateCmd := flag.NewFlagSet("aggregate", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Println("Usage: keygen <command> [options]")
		fmt.Println("Commands: keygen, commit, sign, aggregate")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		keygenCmd.Parse(os.Args[2:])
		runKeygen(*threshold, *total)
	case "commit":
		commitCmd.Parse(os.Args[2:])
		runCommit(*participantID)
	case "sign":
		signCmd.Parse(os.Args[2:])
		runSign()
	case "aggregate":
		aggregateCmd.Parse(os.Args[2:])
		runAggregate()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func runKeygen(threshold, total int) {
	if threshold > total {
		fmt.Fprintf(os.Stderr, "Error: threshold must be <= total\n")
		os.Exit(1)
	}

	g := &bjj.BJJ{}
	hasher := frost.NewBlake2bHasher()
	f, err := frost.NewWithHasher(g, threshold, total, hasher)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating FROST: %v\n", err)
		os.Exit(1)
	}

	participants := make([]*frost.Participant, total)
	round1Broadcasts := make([]*frost.Round1Data, total)
	round1PrivateData := make([][]*frost.Round1PrivateData, total)

	for i := 0; i < total; i++ {
		participants[i], err = f.NewParticipant(rand.Reader, i+1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating participant %d: %v\n", i+1, err)
			os.Exit(1)
		}
		round1Broadcasts[i] = participants[i].Round1Broadcast()
		round1PrivateData[i] = make([]*frost.Round1PrivateData, total)
		for j := 0; j < total; j++ {
			if i != j {
				round1PrivateData[i][j] = f.Round1PrivateSend(participants[i], j+1)
			}
		}
	}

	for i := 0; i < total; i++ {
		for j := 0; j < total; j++ {
			if i != j {
				err := f.Round2ReceiveShare(participants[i], round1PrivateData[j][i], round1Broadcasts[j].Commitments)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error in round 2: %v\n", err)
					os.Exit(1)
				}
			}
		}
	}

	output := KeyGenOutput{
		Threshold: threshold,
		Total:     total,
		Shares:    make([]KeyShareOutput, total),
	}

	for i := 0; i < total; i++ {
		keyShare, err := f.Finalize(participants[i], round1Broadcasts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finalizing: %v\n", err)
			os.Exit(1)
		}

		groupKeyBytes := keyShare.GroupKey.Bytes()
		idBytes := keyShare.ID.Bytes() // Use fy's scalar representation directly
		secretBytes := keyShare.SecretKey.Bytes()
		publicBytes := keyShare.PublicKey.Bytes()

		output.Shares[i] = KeyShareOutput{
			Participant: i + 1,
			GroupKey:    hex.EncodeToString(groupKeyBytes),
			ID:          hex.EncodeToString(idBytes),
			SecretShare: hex.EncodeToString(secretBytes),
			PublicShare: hex.EncodeToString(publicBytes),
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}

func runCommit(participantID int) {
	g := &bjj.BJJ{}

	// Generate random nonces
	hidingNonce, _ := g.RandomScalar(rand.Reader)
	bindingNonce, _ := g.RandomScalar(rand.Reader)

	// Compute commitments
	hidingCommit := g.NewPoint().ScalarMult(hidingNonce, g.Generator())
	bindingCommit := g.NewPoint().ScalarMult(bindingNonce, g.Generator())

	output := CommitmentOutput{
		Participant:   participantID,
		HidingNonce:   hex.EncodeToString(hidingNonce.Bytes()),
		BindingNonce:  hex.EncodeToString(bindingNonce.Bytes()),
		HidingCommit:  hex.EncodeToString(hidingCommit.Bytes()),
		BindingCommit: hex.EncodeToString(bindingCommit.Bytes()),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}

func runSign() {
	var input SignInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	g := &bjj.BJJ{}
	hasher := frost.NewBlake2bHasher()
	f, _ := frost.NewWithHasher(g, 2, 3, hasher) // threshold doesn't matter for signing

	// Parse inputs
	messageHash, _ := hex.DecodeString(input.MessageHash)
	groupKeyBytes, _ := hex.DecodeString(input.GroupKey)
	groupKey := g.NewPoint()
	groupKey.SetBytes(groupKeyBytes)

	// Get signer's data
	signer := input.Participants[input.SignerIndex]
	secretBytes, _ := hex.DecodeString(signer.SecretShare)
	hidingNonceBytes, _ := hex.DecodeString(signer.HidingNonce)
	bindingNonceBytes, _ := hex.DecodeString(signer.BindingNonce)

	secretKey := g.NewScalar()
	secretKey.SetBytes(secretBytes)
	hidingNonce := g.NewScalar()
	hidingNonce.SetBytes(hidingNonceBytes)
	bindingNonce := g.NewScalar()
	bindingNonce.SetBytes(bindingNonceBytes)

	// Build signer ID
	signerIDScalar := g.NewScalar()
	signerIDBytes := make([]byte, 32)
	signerIDBytes[31] = byte(signer.ID)
	signerIDScalar.SetBytes(signerIDBytes)

	// Build key share and nonce
	keyShare := &frost.KeyShare{
		ID:        signerIDScalar,
		SecretKey: secretKey,
		GroupKey:  groupKey,
	}

	nonce := &frost.SigningNonce{
		ID: signerIDScalar,
		D:  hidingNonce,
		E:  bindingNonce,
	}

	// Build commitment list
	var commitments []*frost.SigningCommitment
	for _, p := range input.Participants {
		hidingBytes, _ := hex.DecodeString(p.HidingCommit)
		bindingBytes, _ := hex.DecodeString(p.BindingCommit)
		hiding := g.NewPoint()
		hiding.SetBytes(hidingBytes)
		binding := g.NewPoint()
		binding.SetBytes(bindingBytes)

		idScalar := g.NewScalar()
		idBytes := make([]byte, 32)
		idBytes[31] = byte(p.ID)
		idScalar.SetBytes(idBytes)

		commitments = append(commitments, &frost.SigningCommitment{
			ID:           idScalar,
			HidingPoint:  hiding,
			BindingPoint: binding,
		})
	}

	// Compute partial signature using the FROST library
	sigShare, err := f.SignRound2(keyShare, nonce, messageHash, commitments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error computing partial sig: %v\n", err)
		os.Exit(1)
	}

	output := SignOutput{
		PartialSig: hex.EncodeToString(sigShare.Z.Bytes()),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}

func runAggregate() {
	var input AggregateInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	g := &bjj.BJJ{}
	hasher := frost.NewBlake2bHasher()
	f, _ := frost.NewWithHasher(g, 2, 3, hasher)

	// Parse group key
	groupKeyBytes, _ := hex.DecodeString(input.GroupKey)
	groupKey := g.NewPoint()
	groupKey.SetBytes(groupKeyBytes)

	// Parse message
	messageHash, _ := hex.DecodeString(input.MessageHash)

	// Build commitment list
	var commitments []*frost.SigningCommitment
	for _, p := range input.Participants {
		hidingBytes, _ := hex.DecodeString(p.HidingCommit)
		bindingBytes, _ := hex.DecodeString(p.BindingCommit)
		hiding := g.NewPoint()
		hiding.SetBytes(hidingBytes)
		binding := g.NewPoint()
		binding.SetBytes(bindingBytes)

		idScalar := g.NewScalar()
		idBytes := make([]byte, 32)
		idBytes[31] = byte(p.ID)
		idScalar.SetBytes(idBytes)

		commitments = append(commitments, &frost.SigningCommitment{
			ID:           idScalar,
			HidingPoint:  hiding,
			BindingPoint: binding,
		})
	}

	// Parse partial signatures
	var sigShares []*frost.SignatureShare
	for _, ps := range input.PartialSigs {
		sigBytes, _ := hex.DecodeString(ps.PartialSig)
		sig := g.NewScalar()
		sig.SetBytes(sigBytes)

		idScalar := g.NewScalar()
		idBytes := make([]byte, 32)
		idBytes[31] = byte(ps.ID)
		idScalar.SetBytes(idBytes)

		sigShares = append(sigShares, &frost.SignatureShare{
			ID: idScalar,
			Z:  sig,
		})
	}

	// Aggregate signatures
	signature, err := f.Aggregate(messageHash, commitments, sigShares)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error aggregating: %v\n", err)
		os.Exit(1)
	}

	// Verify signature
	valid := f.Verify(messageHash, signature, groupKey)

	output := AggregateOutput{
		R:     hex.EncodeToString(signature.R.Bytes()),
		Z:     hex.EncodeToString(signature.Z.Bytes()),
		Valid: valid,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}
