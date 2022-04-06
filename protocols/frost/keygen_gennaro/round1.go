package keygen_gennaro

import (
	"crypto/rand"
	"time"
	"fmt"

	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/math/polynomial"
	"github.com/sa8/multi-party-sig/pkg/math/sample"
	"github.com/sa8/multi-party-sig/pkg/party"
)

// This round corresponds with the steps 1-4 of Round 1, Figure 1 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
type round1 struct {
	*round.Helper
	// taproot indicates whether or not to make taproot compatible keys.
	//
	// This means taking the necessary steps to ensure that the shared secret generates
	// a public key with even y coordinate.
	//
	// We also end up returning a different result, to accomodate this fact.
	taproot bool
	// threshold is the integer t which defines the maximum number of corruptions tolerated for this session.
	//
	// Alternatively, the degree of the polynomial used to share the secret.
	//
	// Alternatively, t + 1 participants are needed to make a signature.
	threshold int
	// refresh indicates whether or not we're doing a refresh instead of a key-generation.
	refresh bool
	// These fields are set to accomodate both key-generation, in which case they'll
	// take on identity values, and refresh, in which case their values are meaningful.
	// These values should be modifiable.

	// privateShare is our previous private share when refreshing, and 0 otherwise.
	privateShare curve.Scalar
	// verificationShares should hold the previous verification shares when refreshing, and identity points otherwise.
	verificationShares map[party.ID]curve.Point
	// publicKey should be the previous public key when refreshing, and 0 otherwise.
	publicKey curve.Point

	//timer
	//timer NewTimer *time.Timer
	startTime time.Time
}

// VerifyMessage implements round.Round.
//
// Since this is the start of the protocol, we aren't expecting to have received
// any messages yet, so we do nothing.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
//
// The overall goal of this round is to generate a secret value, create a polynomial
// sharing of that value, and then send commitments to these values.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	//r.timer := time.NewTimer(time.Second * 10)
	fmt.Println("Starting round 1", r.SelfID())
	
	group := r.Group()
	// These steps come from Figure 3, step 1 of the Pikachu paper.

	// 1. "Every participant P_i samples t + 1 random values (aᵢ₀, ..., aᵢₜ)) <-$ Z/(q)
	// and uses these values as coefficients to define a degree t polynomial
	// fᵢ(x) = ∑ⱼ₌₀ᵗ⁻¹ aᵢⱼ xʲ"
	//

	// Refresh: Instead of creating a new secret, instead use 0, so that our result doesn't change.
	a_i0 := group.NewScalar()
	if !r.refresh {
		a_i0 = sample.Scalar(rand.Reader, r.Group())
	}
	F_i := polynomial.NewPolynomial(r.Group(), r.threshold, a_i0)

	// 2. "Every P_i computes s_{i,j} = f_i(j)"
	//consider the cheating case for testing purpose:
	if r.SelfID() == "12D3KooWSpyoi7KghH98SWDfDFMyAwuvtP8MWWGDcC1e1uHWzjSm"{
		fmt.Println("There is a cheater")
		for _, l := range r.OtherPartyIDs() {
			lprime := party.ID("cheater")
			//fmt.Println("cheater value",F_i.Evaluate(lprime.Scalar(r.Group())))
	        if err := r.SendMessage(out, &message2{
	            F_li: F_i.Evaluate(lprime.Scalar(r.Group())),
	        }, l); err != nil {
	            return r, err
	        }
	    }
	} else if r.SelfID() != "12D3KooWSpyoi7KghH98SWDfDFMyAwuvtP8MWWGDcC1e1uHWzjSm" && r.SelfID() != "abort" {
	    for _, l := range r.OtherPartyIDs() {
	        if err := r.SendMessage(out, &message2{
	            F_li: F_i.Evaluate(l.Scalar(r.Group())),
	        }, l); err != nil {
	        	fmt.Println("here")
	            return r, err
	        }
	    }

	}

    selfShare := F_i.Evaluate(r.SelfID().Scalar(r.Group()))
    //3. Every participant computes ph_i == <f_ij G>
	startTime := time.Now()

	return &round2{
		round1:               r,
		F_i:                  F_i,
	    ShareFrom: map[party.ID]curve.Scalar{r.SelfID(): selfShare},
	    startTime:            startTime,
	}, nil
}

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }

func (r *round1) StartTime() time.Time {return r.startTime}
