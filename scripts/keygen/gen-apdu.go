package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/frost"
)

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func main() {
	g := &bjj.BJJ{}
	hasher := frost.NewBlake2bHasher()
	f, err := frost.NewWithHasher(g, 2, 3, hasher)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Run DKG
	participants := make([]*frost.Participant, 3)
	round1Broadcasts := make([]*frost.Round1Data, 3)
	round1PrivateData := make([][]*frost.Round1PrivateData, 3)

	for i := 0; i < 3; i++ {
		participants[i], _ = f.NewParticipant(rand.Reader, i+1)
		round1Broadcasts[i] = participants[i].Round1Broadcast()
		round1PrivateData[i] = make([]*frost.Round1PrivateData, 3)
		for j := 0; j < 3; j++ {
			if i != j {
				round1PrivateData[i][j] = f.Round1PrivateSend(participants[i], j+1)
			}
		}
	}

	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			if i != j {
				f.Round2ReceiveShare(participants[i], round1PrivateData[j][i], round1Broadcasts[j].Commitments)
			}
		}
	}

	// Finalize key shares
	keyShares := make([]*frost.KeyShare, 3)
	for i := 0; i < 3; i++ {
		keyShares[i], _ = f.Finalize(participants[i], round1Broadcasts)
	}

	groupKey := padTo32(keyShares[0].GroupKey.Bytes())
	id1 := padTo32(keyShares[0].ID.Bytes())
	secret1 := padTo32(keyShares[0].SecretKey.Bytes())
	id2 := padTo32(keyShares[1].ID.Bytes())
	secret2 := padTo32(keyShares[1].SecretKey.Bytes())

	// Generate software participant commitments
	hidingNonce2, _ := g.RandomScalar(rand.Reader)
	bindingNonce2, _ := g.RandomScalar(rand.Reader)
	hidingCommit2 := padTo32(g.NewPoint().ScalarMult(hidingNonce2, g.Generator()).Bytes())
	bindingCommit2 := padTo32(g.NewPoint().ScalarMult(bindingNonce2, g.Generator()).Bytes())

	// Message
	message := make([]byte, 32)
	for i := 0; i < 32; i += 4 {
		message[i] = 0xde
		message[i+1] = 0xad
		message[i+2] = 0xbe
		message[i+3] = 0xef
	}

	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              FROST 2-of-3 Manual Test APDUs                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Paste these into Speculos GUI. Click RIGHT to approve prompts.")
	fmt.Println()

	// Step 1
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ STEP 1: Inject Keys (click RIGHT to approve)                   │")
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")
	injectData := append(groupKey, id1...)
	injectData = append(injectData, secret1...)
	fmt.Printf("E019000060%s\n", hex.EncodeToString(injectData))
	fmt.Println()

	// Step 2
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ STEP 2: Generate Commitments                                   │")
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")
	fmt.Println("E01A000000")
	fmt.Println()
	fmt.Println("→ Copy response (128 hex chars before '9000')")
	fmt.Println("  Format: <hiding_32bytes><binding_32bytes>")
	fmt.Println()

	// Step 3
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ STEP 3: Inject Message                                         │")
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")
	fmt.Printf("E01B000020%s\n", hex.EncodeToString(message))
	fmt.Println()

	// Step 4
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ STEP 4: Inject Commitments                                     │")
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("Replace XXXX...XXXX with Ledger's response from Step 2:")
	fmt.Println()
	fmt.Printf("E01C0200C0%s", hex.EncodeToString(id1))
	fmt.Print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	fmt.Printf("%s%s%s\n",
		hex.EncodeToString(id2),
		hex.EncodeToString(hidingCommit2),
		hex.EncodeToString(bindingCommit2))
	fmt.Println()
	fmt.Println("Participant 2's commitments (already filled in above):")
	fmt.Printf("  Hiding:  %s\n", hex.EncodeToString(hidingCommit2))
	fmt.Printf("  Binding: %s\n", hex.EncodeToString(bindingCommit2))
	fmt.Println()

	// Step 5
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ STEP 5: Partial Sign (click RIGHT to approve)                  │")
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")
	fmt.Println("E01E000000")
	fmt.Println()
	fmt.Println("→ Response is Ledger's 32-byte partial signature")
	fmt.Println()

	// Reference data
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Reference Data (for verification)                   ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("Group public key:     %s\n", hex.EncodeToString(groupKey))
	fmt.Printf("Message hash:         %s\n", hex.EncodeToString(message))
	fmt.Printf("Participant 2 ID:     %s\n", hex.EncodeToString(id2))
	fmt.Printf("Participant 2 secret: %s\n", hex.EncodeToString(secret2))
	fmt.Printf("Hiding nonce 2:       %s\n", hex.EncodeToString(padTo32(hidingNonce2.Bytes())))
	fmt.Printf("Binding nonce 2:      %s\n", hex.EncodeToString(padTo32(bindingNonce2.Bytes())))
}
