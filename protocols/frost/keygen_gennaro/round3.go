package keygen_gennaro

import (
	"fmt"

	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/math/polynomial"
	"github.com/sa8/multi-party-sig/pkg/party"
)

//This broadcast message are the VSS shares for each participant to verify other participants.
type broadcast3 struct {
	round.ReliableBroadcastContent
	// Phi_i is the commitment to the polynomial that this participant generated.
	Phi_i *polynomial.Exponent
}

//This round combines a verification of the secret shares and the computation of the final public key.
type round3 struct {
	*round2

	// Phi contains the polynomial commitment for each participant, ourselves included.
	//
	Phi map[party.ID]*polynomial.Exponent
}

// StoreMessage implements round.Round.
func (r *round3) StoreMessage(round.Message) error { return nil }

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// "Each Pᵢ verifies their shares by calculating
	//
	//   fₗ(i) * G =? ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕₗₖ
	//
	expected := r.shareFrom[from].ActOnBase()
	actual := body.Phi_i.Evaluate(r.SelfID().Scalar(r.Group()))
	if !expected.Equal(actual) {
		return fmt.Errorf("VSS failed to validate")
	}
	r.Phi[from] = body.Phi_i

	return nil
}

// VerifyMessage implements round.Round.
func (r *round3) VerifyMessage(msg round.Message) error {
	return nil
}

// Finalize implements round.Round.
// In this round, we finalize the DKG by computing the long-lived private share and the threshold public key.
func (r *round3) Finalize(chan<- *round.Message) (round.Session, error) {

	// 3. "Each P_i calculates their long-lived private signing share by computing
	// sᵢ = ∑ₗ₌₁ⁿ fₗ(i), stores s_i securely, and deletes each fₗ(i)"
	for l, f_li := range r.shareFrom {
		r.privateShare.Add(f_li)
		delete(r.shareFrom, l)
	}

	// 4. "Each Pᵢ calculates their public verification share Yᵢ = sᵢ • G,
	// and the group's public key Y = ∑ⱼ₌₁ⁿ ϕⱼ₀. Any participant
	// can compute the verification share of any other participant by calculating
	//
	// Yᵢ = ∑ⱼ₌₁ⁿ ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕⱼₖ."

	for _, phi_j := range r.Phi {
		r.publicKey = r.publicKey.Add(phi_j.Constant())
	}
	// This accomplishes the same sum as in the paper, by first summing
	// together the exponent coefficients, and then evaluating.
	exponents := make([]*polynomial.Exponent, 0, r.PartyIDs().Len())
	for _, phi_j := range r.Phi {
		exponents = append(exponents, phi_j)
	}
	verificationExponent, err := polynomial.Sum(exponents)
	if err != nil {
		panic(err)
	}
	for k, v := range r.verificationShares {
		r.verificationShares[k] = v.Add(verificationExponent.Evaluate(k.Scalar(r.Group())))
	}
	if r.taproot {
		// BIP-340 adjustment: If our public key is odd, then the underlying secret
		// needs to be negated. Since this secret is ∑ᵢ aᵢ₀, we can negated each
		// of these. Had we generated the polynomials -fᵢ instead, we would have
		// ended up with the correct sharing of the secret. So, this means that
		// we can correct by simply negating our share.
		//
		// We assume that everyone else does the same, so we negate all the verification
		// shares.
		YSecp := r.publicKey.(*curve.Secp256k1Point)
		if !YSecp.HasEvenY() {
			r.privateShare.Negate()
			for i, y_i := range r.verificationShares {
				r.verificationShares[i] = y_i.Negate()
			}
		}
		secpVerificationShares := make(map[party.ID]*curve.Secp256k1Point)
		for k, v := range r.verificationShares {
			secpVerificationShares[k] = v.(*curve.Secp256k1Point)
		}
		return r.ResultRound(&TaprootConfig{
			ID:                 r.SelfID(),
			Threshold:          r.threshold,
			PrivateShare:       r.privateShare.(*curve.Secp256k1Scalar),
			PublicKey:          YSecp.XBytes()[:],
			VerificationShares: secpVerificationShares,
		}), nil
	}

	return r.ResultRound(&Config{
		ID:                 r.SelfID(),
		Threshold:          r.threshold,
		PrivateShare:       r.privateShare,
		PublicKey:          r.publicKey,
		VerificationShares: party.NewPointMap(r.verificationShares),
	}), nil
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		Phi_i: polynomial.EmptyExponent(r.Group()),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
