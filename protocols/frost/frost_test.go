package frost

import (
	//"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sa8/multi-party-sig/internal/test"
	"github.com/sa8/multi-party-sig/pkg/math/curve"
	"github.com/sa8/multi-party-sig/pkg/party"
	"github.com/sa8/multi-party-sig/pkg/protocol"
	"github.com/sa8/multi-party-sig/pkg/taproot"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()
	// h, err := protocol.NewMultiHandler(Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	// require.NoError(t, err)
	// test.HandlerLoop(id, h, n)
	// r, err := h.Result()
	// require.NoError(t, err)
	// require.IsType(t, &Config{}, r)
	// c0 := r.(*Config)

	// h, err = protocol.NewMultiHandler(Refresh(c0, ids), nil)
	// require.NoError(t, err)
	// test.HandlerLoop(id, h, n)
	// r, err = h.Result()
	// require.NoError(t, err)
	// require.IsType(t, &Config{}, r)
	//c := r.(*Config)
	// require.True(t, c0.PublicKey.Equal(c.PublicKey))

	h, err := protocol.NewMultiHandler(KeygenTaprootGennaro(id, ids, threshold), nil)
	require.NoError(t, err)
	//fmt.Println(r)
	//c := r.(*TaprootConfig)
	test.HandlerLoopKeyGen(id, h, n)

	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	c0Taproot := r.(*TaprootConfig)
	fmt.Println("config", c0Taproot)
	// h, err = protocol.NewMultiHandler(RefreshTaproot(c0Taproot, ids), nil)
	// require.NoError(t, err)
	// test.HandlerLoop(c.ID, h, n)

	// r, err = h.Result()
	// require.NoError(t, err)
	// require.IsType(t, &TaprootConfig{}, r)

	//cTaproot := r.(*TaprootConfig)
	// require.True(t, bytes.Equal(c0Taproot.PublicKey, cTaproot.PublicKey))

	// h, err = protocol.NewMultiHandler(Sign(c, ids, message), nil)
	// require.NoError(t, err)
	// test.HandlerLoop(c.ID, h, n)

	// signResult, err := h.Result()
	// require.NoError(t, err)
	// require.IsType(t, Signature{}, signResult)
	// signature := signResult.(Signature)
	// assert.True(t, signature.Verify(c.PublicKey, message))
	signers := party.IDSlice{"a", "b", "c", "d", "e"}
	if signers.Contains(id) {
		tweak := []byte{0,1}
		h, err = protocol.NewMultiHandler(SignTaprootWithTweak(c0Taproot, signers, message, tweak), nil)
		//h, err = protocol.NewMultiHandler(SignTaproot(c0Taproot, signers, message), nil)
		require.NoError(t, err)

		test.HandlerLoop(id, h, n)

		signResult, err := h.Result()
		fmt.Println("signing result:", signResult)
		require.NoError(t, err)
		require.IsType(t, taproot.Signature{}, signResult)
		taprootSignature := signResult.(taproot.Signature)

		// for tweak case, we update the public key with the tweak key instead
		//assert.True(t, c0Taproot.PublicKey.Verify(taprootSignature, message))
	 	public := []byte(c0Taproot.PublicKey)
	 	tweakedKey := taproot.PublicKey(apply_tweak_to_publicKeyTaproot(t, public, tweak))
	 	assert.True(t, tweakedKey.Verify(taprootSignature, message))
	 //    public := []byte(c0Taproot.PublicKey)
	 //    group := curve.Secp256k1{}
	 //    s_tweak := group.NewScalar().SetNat(new(safenum.Nat).SetBytes(tweak))
	 //    p_tweak := s_tweak.ActOnBase()

	 //    P, err := curve.Secp256k1{}.LiftX(public)
	 //    require.NoError(t, err, "failed to process public key")

	 //    Y_tweak := P.Add(p_tweak)
	 //    YSecp := Y_tweak.(*curve.Secp256k1Point)
	 //    if !YSecp.HasEvenY() {
	 //        s_tweak.Negate()
	 //        p_tweak := s_tweak.ActOnBase()
	 //        Y_tweak = P.Negate().Add(p_tweak)
	 //        YSecp = Y_tweak.(*curve.Secp256k1Point)
	 //    }
	 //    PBytes := taproot.PublicKey(YSecp.XBytes())
		// assert.True(t, PBytes.Verify(taprootSignature, message))
	} else {n.Quit(id)}

}
func apply_tweak_to_publicKeyTaproot(t *testing.T, public []byte, tweak []byte) []byte{
    group := curve.Secp256k1{}
    s_tweak := group.NewScalar().SetNat(new(safenum.Nat).SetBytes(tweak))
    p_tweak := s_tweak.ActOnBase()

    P, err := curve.Secp256k1{}.LiftX(public)
    require.NoError(t, err, "failed to process public key")

    Y_tweak := P.Add(p_tweak)
    YSecp := Y_tweak.(*curve.Secp256k1Point)
    if !YSecp.HasEvenY() {
        s_tweak.Negate()
        p_tweak := s_tweak.ActOnBase()
        Y_tweak = P.Negate().Add(p_tweak)
        YSecp = Y_tweak.(*curve.Secp256k1Point)
    }
    PBytes := YSecp.XBytes()
    return PBytes
}
func TestFrost(t *testing.T) {
	N := 6
	T := N - 2
	message := []byte("hello")

	// partyIDs := test.PartyIDs(N)
	// fmt.Println(partyIDs)

	partyIDs := party.IDSlice{"a", "b", "c", "d", "e", "12D3KooWSpyoi7KghH98SWDfDFMyAwuvtP8MWWGDcC1e1uHWzjSm"}
	fmt.Println(partyIDs)
	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)
	for _, id := range partyIDs {
		go do(t, id, partyIDs, T, message, n, &wg)
	}
	wg.Wait()
}
