package filpay

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const railOneTimePaymentProcessedABI = `[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"railId","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"netPayeeAmount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"operatorCommission","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"networkFee","type":"uint256"}],"name":"RailOneTimePaymentProcessed","type":"event"}]`

var (
	railOneTimePaymentProcessedTopic = crypto.Keccak256Hash([]byte("RailOneTimePaymentProcessed(uint256,uint256,uint256,uint256)"))
	railOneTimePaymentProcessedEvent abi.Event
)

func init() {
	parsed, err := abi.JSON(strings.NewReader(railOneTimePaymentProcessedABI))
	if err != nil {
		panic(fmt.Sprintf("filpay: parse RailOneTimePaymentProcessed abi: %v", err))
	}
	ev, ok := parsed.Events["RailOneTimePaymentProcessed"]
	if !ok {
		panic("filpay: RailOneTimePaymentProcessed event missing from abi")
	}
	railOneTimePaymentProcessedEvent = ev
}

// sumRailOneTimePaymentCredit sums the creditable one-time charge per rail from
// RailOneTimePaymentProcessed logs: netPayeeAmount + networkFee.
//
// operatorCommission is deliberately EXCLUDED. In this design the client is the rail
// operator (createRail is sent by the payer), so a malicious client can set an arbitrary
// operator commission routed back to itself as serviceFeeRecipient. Crediting the pool at
// the full gross (net + commission + networkFee) would let such a client fund the pool at
// gross while the SP only ever receives netPayeeAmount — paying the SP a fraction of the
// retrieved value. We therefore credit only what the SP can actually receive (net) plus the
// protocol-set, non-redirectable networkFee, which the SP continues to absorb (matching the
// honest commission==0 flow exactly, where credit == net + networkFee == oneTimePayment).
func sumRailOneTimePaymentCredit(receipt *types.Receipt, paymentsAddr common.Address) (map[string]*big.Int, error) {
	if receipt == nil {
		return nil, fmt.Errorf("filpay: nil receipt")
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("filpay: payment tx failed")
	}
	ev := railOneTimePaymentProcessedEvent

	byRail := map[string]*big.Int{}
	for _, lg := range receipt.Logs {
		if lg == nil || len(lg.Topics) == 0 || lg.Address != paymentsAddr {
			continue
		}
		if lg.Topics[0] != railOneTimePaymentProcessedTopic || len(lg.Topics) < 2 {
			continue
		}
		railID := new(big.Int).SetBytes(lg.Topics[1].Bytes())
		vals, err := ev.Inputs.NonIndexed().Unpack(lg.Data)
		if err != nil {
			return nil, fmt.Errorf("filpay: unpack RailOneTimePaymentProcessed: %w", err)
		}
		if len(vals) < 3 {
			return nil, fmt.Errorf("filpay: RailOneTimePaymentProcessed missing payment amounts")
		}
		net, ok := vals[0].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("filpay: RailOneTimePaymentProcessed netPayeeAmount type %T", vals[0])
		}
		// operatorCommission (vals[1]) is intentionally not used: it is attacker-controllable
		// and would otherwise inflate the pool credit without the SP receiving those funds.
		networkFee, ok := vals[2].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("filpay: RailOneTimePaymentProcessed networkFee type %T", vals[2])
		}
		credit := new(big.Int).Add(net, networkFee)
		key := railID.String()
		cur := byRail[key]
		if cur == nil {
			cur = big.NewInt(0)
		}
		byRail[key] = new(big.Int).Add(cur, credit)
	}
	return byRail, nil
}
