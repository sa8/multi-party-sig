package keygen_gennaro

import (
    "time"
    "fmt"

	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/party"
)

type proof struct {
    id party.ID
    value curve.Scalar
}


type broadcast4 struct {
	round.ReliableBroadcastContent
	complaints []complaint
}


type round4 struct {
	*round3
	complaints map[party.ID]*curve.Scalar
	proofs []proof
    startTime time.Time
}

// StoreMessage implements round.Round.
func (r *round4) StoreMessage(round.Message) error { return nil }

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round4) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast4)
	if !ok || body == nil {
	    //fixme??
		return round.ErrInvalidContent
	}

    fmt.Println("Conplaints: ", body.complaints )
    for _, c := range body.complaints {
        if c.id == r.SelfID(){
            r.proofs = append(r.proofs,proof{id: from, value: r.f_i.Evaluate(from.Scalar(r.Group()))})
        }else{
            r.complaints[c.id] = &c.value
        }
    }
	return nil
}

// VerifyMessage implements round.Round.
func (r *round4) VerifyMessage(msg round.Message) error {
	return nil
}

// Finalize implements round.Round.
func (r *round4) Finalize(out chan<- *round.Message) (round.Session, error) {
    r.startTime = time.Now()
    // 4. "Every Pᵢ broadcasts phi_i
    err := r.BroadcastMessage(out, &broadcast5{
        proofs: r.proofs,
    })
    if err != nil {
        return r, err
    }
    return &round5{
        round4:    r,
    }, nil

}

// RoundNumber implements round.Content.
func (broadcast4) RoundNumber() round.Number { return 4 }

// BroadcastContent implements round.BroadcastRound.
//{id: party.ID(0), value: r.Group().NewScalar()}
func (r *round4) BroadcastContent() round.BroadcastContent {
    return &broadcast4{
    		complaints: make([]complaint,1),
    }
}

// Number implements round.Round.
func (round4) Number() round.Number { return 4 }

func (r *round4) StartTime() time.Time {return r.startTime}
