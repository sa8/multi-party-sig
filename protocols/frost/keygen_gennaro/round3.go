 package keygen_gennaro

import (
	"fmt"
    "time"

	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/math/polynomial"
	"github.com/sa8/multi-party-sig/pkg/party"
)
// this rounds corresponds to the complaints (if any). -> step 3 from figure 3 in DKG figure
type Complaint struct {
    Id party.ID
    Value curve.Scalar
}

type broadcast3 struct {
	round.ReliableBroadcastContent
	// Phi_i is the commitment to the polynomial that this participant generated.
	Phi_i *polynomial.Exponent
}


type round3 struct {
	*round2

    //
    Mps []Complaint
	// Phi contains the polynomial commitment for each participant, ourselves included.
	Phi map[party.ID]*polynomial.Exponent
    F_i *polynomial.Polynomial
    ShareFrom map[party.ID]curve.Scalar
    startTime time.Time
}

// StoreMessage implements round.Round.
func (r *round3) StoreMessage(round.Message) error { return nil }

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		r.Mps = append(r.Mps,Complaint{Id: from, Value: r.ShareFrom[from]})
		return nil
	}
   
    // "Each Pᵢ verifies their shares by calculating
    //
    //   fₗ(i) * G =? ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕₗₖ
    //
    // expected := r.ShareFrom[from].ActOnBase()
    // actual := body.Phi_i.Evaluate(r.SelfID().Scalar(r.Group()))
    // if !expected.Equal(actual) {
    //     fmt.Println("VSS failed to validate from ", from)
    //     r.Mps = append(r.Mps,Complaint{Id: from, Value: r.ShareFrom[from]})
    // }
    if _, ok := r.ShareFrom[from]; ok {
        expected := r.ShareFrom[from].ActOnBase()
        actual := body.Phi_i.Evaluate(r.SelfID().Scalar(r.Group()))
        if !expected.Equal(actual) {
            fmt.Println("VSS failed to validate from ", from)
            r.Mps = append(r.Mps,Complaint{Id: from, Value: r.ShareFrom[from]})
        }
    } else{
        //r.Mps = append(r.Mps,Complaint{Id: from, Value: r.ShareFrom[from]})
        r.Mps = append(r.Mps,Complaint{Id: from, Value: r.Group().NewScalar()})  
    }

    r.Phi[from] = body.Phi_i

	return nil
}

// VerifyMessage implements round.Round.
func (r *round3) VerifyMessage(msg round.Message) error {
	return nil
}
func  isIncluded(party party.ID, mps []Complaint) bool {
    for _, check := range mps{
        if check.Id == party { 
            return true
        }
    }
    return false

}
// Finalize implements round.Round.
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
    //r.startTime = time.Now()
    fmt.Println("Starting round 3", r.SelfID())
    // 4. "Every Pᵢ broadcasts its complaints
    
    //check for missing shares here (i.e. players that aborted)
    for _,party := range(r.PartyIDs()){
        if _, ok := r.ShareFrom[party]; !ok {
            if !isIncluded(party, r.Mps){r.Mps = append(r.Mps,Complaint{Id: party, Value: r.Group().NewScalar()}) }        
        }
    }

    fmt.Println("Complaints, round 3:", r.Mps)
    complaintsRound4 := make([]string,0)
    if len(r.Mps) >0 {
        for i,_ := range r.Mps{
            complaintsRound4 = append(complaintsRound4,string(r.Mps[i].Id))
        }
        //complaintsRound4 = []string{string(r.Mps[0].Id)}
    } 

    err := r.BroadcastMessage(out, &broadcast4{ComplaintsRound4: complaintsRound4})
    if err != nil {
        //fmt.Println("error in broadcast4")
        return r, err
    }

    var proofs []proof
    return &round4{
        round3:    r,
        //Complaints: map[party.ID]*curve.Scalar{r.SelfID(): nil},
        Complaints: map[party.ID]string{r.SelfID(): ""},
        //complaints: r.mps,
        Proofs: proofs,
        F_i: r.F_i,
        ShareFrom: r.ShareFrom,
        startTime: time.Now(),
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


// MessageContent implements round.Round.
func (round3) MessageContent() round.Content { return nil }
