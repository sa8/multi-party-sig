package sign_with_tweak

import (
	"fmt"

	"github.com/sa8/multi-party-sig/internal/round"
	"github.com/sa8/multi-party-sig/pkg/party"
	"github.com/sa8/multi-party-sig/pkg/protocol"
	"github.com/sa8/multi-party-sig/protocols/frost/keygen_gennaro"
)

const (
	// Frost Sign with Threshold.
	protocolID        = "frost/sign-threshold"
	protocolIDTaproot = "frost/sign-threshold-taproot"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

func StartSignCommonTweak(taproot bool, result *keygen_gennaro.Config, signers []party.ID, messageHash []byte, tweak []byte) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			FinalRoundNumber: protocolRounds,
			SelfID:           result.ID,
			PartyIDs:         signers,
			Threshold:        result.Threshold,
			Group:            result.PublicKey.Curve(),
		}
		if taproot {
			info.ProtocolID = protocolIDTaproot
		} else {
			info.ProtocolID = protocolID
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}

		return &round1{
			Helper:  helper,
			taproot: taproot,
			M:       messageHash,
			Y:       result.PublicKey,
			YShares: result.VerificationShares.Points,
			s_i:     result.PrivateShare,
			T:  tweak,
		}, nil
	}
}
