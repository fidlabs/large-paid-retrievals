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

// sumRailOneTimePaymentGross sums the gross one-time charge per rail from
// RailOneTimePaymentProcessed logs: netPayeeAmount + operatorCommission + networkFee.
// That gross is what the payer's modifyRailPayment oneTimePayment debited from lockup.
// Only netPayeeAmount lands in the payee's Filecoin Pay account; commission and network
// fees are absorbed by the SP when the settlement pool is credited at gross.
func sumRailOneTimePaymentGross(receipt *types.Receipt, paymentsAddr common.Address) (map[string]*big.Int, error) {
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
		commission, ok := vals[1].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("filpay: RailOneTimePaymentProcessed operatorCommission type %T", vals[1])
		}
		networkFee, ok := vals[2].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("filpay: RailOneTimePaymentProcessed networkFee type %T", vals[2])
		}
		gross := new(big.Int).Add(net, commission)
		gross.Add(gross, networkFee)
		key := railID.String()
		cur := byRail[key]
		if cur == nil {
			cur = big.NewInt(0)
		}
		byRail[key] = new(big.Int).Add(cur, gross)
	}
	return byRail, nil
}
