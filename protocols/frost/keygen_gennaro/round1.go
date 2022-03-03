package keygen_gennaro

import (
	"crypto/rand"

	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/math/polynomial"
	"github.com/sa8/multi-party-sig/pkg/math/sample"
	"github.com/sa8/multi-party-sig/pkg/party"
)

//This round corresponds to round1 of Gennaro's DKG algorithm.
//All participants are expected to share their Shamir-shares in private to all other participants.
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
	group := r.Group()
	// These steps come from Figure 1, Round 1 of the Frost paper.

	// 1. "Every participant P_i samples t + 1 random values (aᵢ₀, ..., aᵢₜ)) <-$ Z/(q)
	// and uses these values as coefficients to define a degree t polynomial
	// fᵢ(x) = ∑ⱼ₌₀ᵗ⁻¹ aᵢⱼ xʲ"
	//

	// Refresh: Instead of creating a new secret, instead use 0, so that our result doesn't change.
	// In practice, we refresh at every new DKG.
	a_i0 := group.NewScalar()
	if !r.refresh {
		a_i0 = sample.Scalar(rand.Reader, r.Group())
	}
	f_i := polynomial.NewPolynomial(r.Group(), r.threshold, a_i0)

	// 2. "Every P_i computes s_{i,j} = f_i(j)"
	// Every participant shares this in private to all other participants.
	for _, l := range r.OtherPartyIDs() {
		if err := r.SendMessage(out, &message2{
			F_li: f_i.Evaluate(l.Scalar(r.Group())),
		}, l); err != nil {
			return r, err
		}
	}
	selfShare := f_i.Evaluate(r.SelfID().Scalar(r.Group()))
	//We go to round2 after this, where we collect all privately shared pieces of the other participants.
	return &round2{
		round1:    r,
		f_i:       f_i,
		shareFrom: map[party.ID]curve.Scalar{r.SelfID(): selfShare},
	}, nil
}

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
