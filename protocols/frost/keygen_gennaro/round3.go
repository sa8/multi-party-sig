package keygen_gennaro

import (
	"fmt"
    "time"

	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/math/polynomial"
	"github.com/sa8/multi-party-sig/pkg/party"
)
// this rounds corresponds to the complaints (if any)
type complaint struct {
    id party.ID
    value curve.Scalar
}

type broadcast3 struct {
	round.ReliableBroadcastContent
	// Phi_i is the commitment to the polynomial that this participant generated.
	Phi_i *polynomial.Exponent
}


type round3 struct {
	*round2

    //
    mps []complaint
	// Phi contains the polynomial commitment for each participant, ourselves included.
	//
	Phi map[party.ID]*polynomial.Exponent

    startTime time.Time
}

// StoreMessage implements round.Round.
func (r *round3) StoreMessage(round.Message) error { return nil }

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From

	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		r.mps = append(r.mps,complaint{id: from, value: r.shareFrom[from]})
		return nil
	}

    // "Each Pᵢ verifies their shares by calculating
    //
    //   fₗ(i) * G =? ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕₗₖ
    //
    expected := r.shareFrom[from].ActOnBase()
    actual := body.Phi_i.Evaluate(r.SelfID().Scalar(r.Group()))
    if !expected.Equal(actual) {
        fmt.Println("VSS failed to validate")
        r.mps = append(r.mps,complaint{id: from, value: r.shareFrom[from]})
    }

    r.Phi[from] = body.Phi_i

	return nil
}

// VerifyMessage implements round.Round.
func (r *round3) VerifyMessage(msg round.Message) error {
	return nil
}

// Finalize implements round.Round.
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
    r.startTime = time.Now()

    // 4. "Every Pᵢ broadcasts its complaints
    err := r.BroadcastMessage(out, &broadcast4{
        complaints: r.mps,
    })
    if err != nil {
        return r, err
    }

    var proofs []proof

    return &round4{
        round3:    r,
        complaints: map[party.ID]*curve.Scalar{r.SelfID(): nil},
        proofs: proofs,
    }, nil
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
    return &broadcast3{
    		Phi_i:   polynomial.EmptyExponent(r.Group()),
    }
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }

func (r *round3) StartTime() time.Time {return r.startTime}
