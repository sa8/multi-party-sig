package keygen_gennaro

import (
	"time"
	"fmt"

	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/math/polynomial"
	"github.com/sa8/multi-party-sig/pkg/party"
)


type message2 struct {
	// F_li is the secret share sent from party l to this party.
	F_li curve.Scalar
}
// this step corresponds to step 2 in the DKG figure of the pikachu paper (broadcast commitments)
type round2 struct {
	*round1
	// f_i is the polynomial this participant uses to share their contribution to
	// the secret
	F_i *polynomial.Polynomial
    // shareFrom is the secret share sent to us by a given party, including ourselves.
    //
    // shareFrom[l] corresponds to fₗ(i) in the Frost paper, with i our own ID.
    ShareFrom map[party.ID]curve.Scalar

    startTime time.Time
}

func (round2) Number() round.Number { return 2 }

func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	//This is step 2 in the Pikachu paper
	fmt.Println("Starting round 2", r.SelfID())
    Phi_i := polynomial.NewPolynomialExponent(r.F_i)

	// 4. "Every Pᵢ broadcasts phi_i
	err := r.BroadcastMessage(out, &broadcast3{
		Phi_i:      Phi_i,
	})
	if err != nil {
		return r, err
	}

	var Cmp []Complaint


	return &round3{
		round2:    r,
		Phi:  map[party.ID]*polynomial.Exponent{r.SelfID(): Phi_i},
		Mps: Cmp,
		F_i: r.F_i,
		ShareFrom: r.ShareFrom,
		startTime: time.Now(),
	}, nil
}

// RoundNumber implements round.Content.
func (message2) RoundNumber() round.Number { return 2 }

// VerifyMessage implements round.Round.
func (r *round2) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	// check nil
	if body.F_li == nil {
		return round.ErrNilFields
	}

	return nil
}

// StoreMessage implements round.Round.
//
func (r *round2) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message2)

	r.ShareFrom[from] = body.F_li
	return nil
}

// MessageContent implements round.Round.
func (r *round2) MessageContent() round.Content {
	return &message2{
		F_li: r.Group().NewScalar(),
	}
}

func (r *round2) StartTime() time.Time {return r.startTime}