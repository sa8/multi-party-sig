package keygen_gennaro

import (
	"fmt"
	"time"

	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/math/polynomial"
	"github.com/sa8/multi-party-sig/pkg/party"
)
// step 5 of Figure 3 of the DKG in the Pikachu paper
// remove participants who have not replied to complaints

type broadcast5 struct {
	round.ReliableBroadcastContent
	// Phi_i is the commitment to the polynomial that this participant generated.
	proofs []proof
	//Complaints map[party.ID]*curve.Scalar
	//Complaints []party.ID
}

type round5 struct {
	*round4
	//Complaints map[party.ID]*curve.Scalar
	ShareFrom map[party.ID]curve.Scalar
	startTime time.Time
}

// StoreMessage implements round.Round.
func (r *round5) StoreMessage(round.Message) error { return nil }

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round5) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	//fmt.Println("round 5 body",body)
	// r.Complaints = make(map[party.ID]*curve.Scalar)
	// for key, value := range body.Complaints {
 //  		r.Complaints[key] = value
	// 	}
    for _, c := range body.proofs {
        if c.id == r.SelfID() && r.Complaints[from] != ""{
            expected := c.value.ActOnBase()
            actual := r.Phi[from].Evaluate(r.SelfID().Scalar(r.Group()))
            if expected.Equal(actual) {
                r.ShareFrom[from] = c.value
                r.Complaints[from] = ""
            }else {
                fmt.Println("still wrong!!")
            }
        }
    }

	return nil
}

// VerifyMessage implements round.Round.
func (r *round5) VerifyMessage(msg round.Message) error {
	return nil
}

// Finalize implements round.Round.
func (r *round5) Finalize(chan<- *round.Message) (round.Session, error) {
	r.startTime = time.Now()
	// 3. "Each P_i calculates their long-lived private signing share by computing
	// sᵢ = ∑ₗ₌₁ⁿ fₗ(i), stores s_i securely, and deletes each fₗ(i)"
	fmt.Println("round 5 sharefrom", r.ShareFrom)
	fmt.Println("round 5 complaints", r.Complaints)
	for l, f_li := range r.ShareFrom {
	    if r.Complaints[l] == "" {
		    r.privateShare.Add(f_li)
		    // TODO: Maybe actually clear this in a better way
		    delete(r.ShareFrom, l)
		}
	}

	// 4. "Each Pᵢ calculates their public verification share Yᵢ = sᵢ • G,
	// and the group's public key Y = ∑ⱼ₌₁ⁿ ϕⱼ₀. Any participant
	// can compute the verification share of any other participant by calculating
	//
	// Yᵢ = ∑ⱼ₌₁ⁿ ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕⱼₖ."
	//fmt.Println("round 5 phi", r.Phi)
	for l, phi_j := range r.Phi {
	    if r.Complaints[l] == "" {
	    	fmt.Println("Including ",l)
		    r.publicKey = r.publicKey.Add(phi_j.Constant())
		}
	}
	//fmt.Println("Complaints from round 5: ", r.Complaints)
	// This accomplishes the same sum as in the paper, by first summing
	// together the exponent coefficients, and then evaluating.
	exponents := make([]*polynomial.Exponent, 0, r.PartyIDs().Len())
	for l, phi_j := range r.Phi {
		if r.Complaints[l] == "" {exponents = append(exponents, phi_j)}
	}
	verificationExponent, err := polynomial.Sum(exponents)
	if err != nil {
		panic(err)
	}
	for k, v := range r.verificationShares {
		if r.Complaints[k] == ""{
			r.verificationShares[k] = v.Add(verificationExponent.Evaluate(k.Scalar(r.Group())))
		}
	}
	fmt.Println("PrivateShare: ",r.SelfID(),r.privateShare)
	fmt.Println("Keygen result: ", r.publicKey.(*curve.Secp256k1Point).XBytes()[:])

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
func (broadcast5) RoundNumber() round.Number { return 5 }

// BroadcastContent implements round.BroadcastRound.
func (r *round5) BroadcastContent() round.BroadcastContent {
    return &broadcast5{
    		proofs: make([]proof,1),
    }
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }

func (r *round5) StartTime() time.Time {return r.startTime}
