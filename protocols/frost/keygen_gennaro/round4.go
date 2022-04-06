package keygen_gennaro

import (
    "time"
    //"fmt"
  //  "reflect"

    "github.com/sa8/multi-party-sig/pkg/math/polynomial"
	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/party"
)
// this rounds implements the replies to complaint -> step 4 of figure 3 in the Pikachu paper
// if somjeone sent a complaint against us, we reply
type proof struct {
    id party.ID
    value curve.Scalar
}


type broadcast4 struct {
	round.ReliableBroadcastContent
    //ComplaintsRound4 map[party.ID]*curve.Scalar
    ComplaintsRound4 []string
}


type round4 struct {
	*round3
	//Complaints map[party.ID]*curve.Scalar
   // complaints []complaint
    Complaints map[party.ID]string
	Proofs []proof
    F_i *polynomial.Polynomial
    ShareFrom map[party.ID]curve.Scalar
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

    // fmt.Println("Body complaints, round 4: ", body.ComplaintsRound4, "from", from, "myself", r.SelfID())
    // fmt.Println("Complaints map: ", r.Complaints)

    for _, c := range body.ComplaintsRound4{
        if c == string(r.SelfID()) && r.SelfID() != "12D3KooWSpyoi7KghH98SWDfDFMyAwuvtP8MWWGDcC1e1uHWzjSm"{
            r.Proofs = append(r.Proofs,proof{id: from, value: r.F_i.Evaluate(from.Scalar(r.Group()))})
        } else {
            //r.Complaints = append(r.Complaints, party.ID(c))
            if len(c)>0 { r.Complaints[party.ID(c)] = "cheater"}
        }
    }

    // check if someone sent a complaint about us
        // for key, v := range body.ComplaintsRound4 {
        // //for c := range body.complaints {
        //     //if c[Id] == r.SelfID(){
        //     if key == r.SelfID(){
        //         fmt.Println("Round 4 proof ", key)
        //         r.Proofs = append(r.Proofs,proof{id: from, value: r.F_i.Evaluate(from.Scalar(r.Group()))})
        //     }else{
        //         //r.Complaints[c.Id] = &c.Value
        //         r.Complaints[key] = v
        //     }
        // }
   // fmt.Println("here", r.Complaints)
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
    //fmt.Println("Starting round 4", r.SelfID(), "complaints", r.Complaints)
    
    if r.SelfID()!= "12D3KooWSpyoi7KghH98SWDfDFMyAwuvtP8MWWGDcC1e1uHWzjSm" && r.SelfID()!= "abort"{
        err := r.BroadcastMessage(out, &broadcast5{
            proofs: r.Proofs,
            //Complaints: r.Complaints,
        })
        if err != nil {
            return r, err
        }
    }
    return &round5{
        round4:    r,
        ShareFrom: r.ShareFrom,
        startTime: time.Now(),
    }, nil

}

// RoundNumber implements round.Content.
func (broadcast4) RoundNumber() round.Number { return 4 }

// BroadcastContent implements round.BroadcastRound.
//{id: party.ID(0), value: r.Group().NewScalar()}
func (r *round4) BroadcastContent() round.BroadcastContent {
    return &broadcast4{
    		//ComplaintsRound4: make([]Complaint,0),
            //ComplaintsRound4: make(map[party.ID]*curve.Scalar),
            ComplaintsRound4: make([]string,0),
    }
}

// Number implements round.Round.
func (round4) Number() round.Number { return 4 }

func (r *round4) StartTime() time.Time {return r.startTime}
