// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/log"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	cmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var emptyCodeHash = crypto.Keccak256Hash(nil)

var (
	errInsufficientBalanceForGas             = errors.New("insufficient balance to pay for gas")
	errIncorrectGasDelegationContractAddress = errors.New("incorrect gas delegation contract address was given")
	errGasDelegationWhitelistCheckFailed     = errors.New("gas delegation whitelist check failed")
	errGasDelegationWhitelistDenied          = errors.New("gas delegation whitelist denied")
)

var ABITrue = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001")

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	consensusConfig *common.ConsensusConfig
	splitGasPaid    bool
	gp              *GasPool
	msg             Message
	gas             uint64
	gasPrice        *big.Int
	gasFeeCap       *big.Int
	gasTipCap       *big.Int
	initialGas      uint64
	value           *big.Int
	data            []byte
	state           vm.StateDB
	evm             *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	To() *common.Address

	GasPrice() *big.Int
	GasFeeCap() *big.Int
	GasTipCap() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	IsFake() bool
	Data() []byte
	AccessList() types.AccessList

	// contextual information
	ChainConfig() *params.ChainConfig
	GasDelegator() *common.Address
}

// ExecutionResult includes all output after executing given evm
// message no matter the execution itself is successful or not.
type ExecutionResult struct {
	UsedGas    uint64 // Total used gas but include the refunded gas
	Err        error  // Any error encountered during the execution(listed in core/vm/errors.go)
	ReturnData []byte // Returned data from evm(function result or data supplied with revert opcode)
}

// Unwrap returns the internal evm error which allows us for further
// analysis outside.
func (result *ExecutionResult) Unwrap() error {
	return result.Err
}

// Failed returns the indicator whether the execution is successful or not
func (result *ExecutionResult) Failed() bool { return result.Err != nil }

// Return is a helper function to help caller distinguish between revert reason
// and function return. Return returns the data after execution if no error occurs.
func (result *ExecutionResult) Return() []byte {
	if result.Err != nil {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// Revert returns the concrete revert reason if the execution is aborted by `REVERT`
// opcode. Note the reason can be nil if no data supplied with revert opcode.
func (result *ExecutionResult) Revert() []byte {
	if result.Err != vm.ErrExecutionReverted {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, accessList types.AccessList, isContractCreation bool, isHomestead, isEIP2028 bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	if isContractCreation && isHomestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		nonZeroGas := params.TxDataNonZeroGasFrontier
		if isEIP2028 {
			nonZeroGas = params.TxDataNonZeroGasEIP2028
		}
		if (math.MaxUint64-gas)/nonZeroGas < nz {
			return 0, ErrGasUintOverflow
		}
		gas += nz * nonZeroGas

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, ErrGasUintOverflow
		}
		gas += z * params.TxDataZeroGas
	}
	if accessList != nil {
		gas += uint64(len(accessList)) * params.TxAccessListAddressGas
		gas += uint64(accessList.StorageKeys()) * params.TxAccessListStorageKeyGas
	}
	return gas, nil
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(consensusConfig *common.ConsensusConfig, evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		consensusConfig: consensusConfig,
		splitGasPaid:    false,
		gp:              gp,
		evm:             evm,
		msg:             msg,
		gasPrice:        msg.GasPrice(),
		gasFeeCap:       msg.GasFeeCap(),
		gasTipCap:       msg.GasTipCap(),
		value:           msg.Value(),
		data:            msg.Data(),
		state:           evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(consensusConfig *common.ConsensusConfig, evm *vm.EVM, msg Message, gp *GasPool) (*ExecutionResult, error) {
	return NewStateTransition(consensusConfig, evm, msg, gp).TransitionDb()
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) buyGas() error {
	state := st.state
	sender := st.msg.From()
	mgval := new(big.Int).SetUint64(st.msg.Gas())
	mgval = mgval.Mul(mgval, st.gasPrice)
	balanceCheck := mgval
	if st.gasFeeCap != nil {
		balanceCheck = new(big.Int).SetUint64(st.msg.Gas())
		balanceCheck = balanceCheck.Mul(balanceCheck, st.gasFeeCap)
		balanceCheck.Add(balanceCheck, st.value)
	}
	totalGas := st.msg.Gas()

	if st.msg.ChainConfig().GasFree != nil {
		sender = st.msg.ChainConfig().GasFree.Payer
	} else if st.msg.GasDelegator() != nil {
		gasDelegationContractAddr := st.msg.GasDelegator()
		///////////////////////////////////////////////////////////////////////////////////////////
		checkerGasUsed, err := checkWhitelist(st.consensusConfig, *gasDelegationContractAddr, sender, mgval, state, st.evm)
		if err != nil {
			return err
		}
		if st.msg.ChainConfig().GlobalDC != nil && st.msg.ChainConfig().IsTheBalanceGlobalDCBlock(st.evm.Context.BlockNumber) {
			// Account gas consumed by checkWhitelist()
			totalGas += checkerGasUsed

			// Charge gas consumed by checkWhitelist() to the delegator
			delegatorExpense := new(big.Int).SetUint64(checkerGasUsed)
			delegatorExpense.Mul(delegatorExpense, st.gasPrice)
			balanceCheck.Add(balanceCheck, delegatorExpense)
			mgval.Add(mgval, delegatorExpense)

			// Do not account for msg.value of original sender
			balanceCheck.Sub(balanceCheck, st.value)
		} ///////////////////////////////////////////////////////////////////////////////////////////
		sender = *gasDelegationContractAddr
	} else if st.msg.ChainConfig().GlobalDC != nil && st.msg.ChainConfig().IsTheBalanceGlobalDCBlock(st.evm.Context.BlockNumber) {
		balance := state.GetBalance(sender)
		if balance.Cmp(mgval) < 0 {
			// try split gas payment
			gasDelegationContractAddr := st.msg.ChainConfig().GlobalDC.GasDelegationContractAddress
			insufficientMgval := big.NewInt(0).Sub(mgval, balance)
			if state.GetBalance(gasDelegationContractAddr).Cmp(insufficientMgval) < 0 {
				return errInsufficientBalanceForGas
			}
			if err := st.gp.SubGas(totalGas); err != nil {
				return err
			}
			///////////////////////////////////////////////////////////////////////////////////////////
			_, err := useGasPoint(st.consensusConfig, gasDelegationContractAddr, sender, insufficientMgval, state, st.evm)
			if err != nil {
				return err
			}
			// Account gas consumed by useGasPoint()
			//totalGas += checkerGasUsed

			// Charge gas consumed by useGasPoint() to the delegator
			//delegatorExpense := new(big.Int).SetUint64(checkerGasUsed)
			//delegatorExpense.Mul(delegatorExpense, st.gasPrice)
			//balanceCheck.Add(balanceCheck, delegatorExpense)
			//mgval.Add(mgval, delegatorExpense)

			// Do not account for msg.value of original sender
			//balanceCheck.Sub(balanceCheck, st.value)
			///////////////////////////////////////////////////////////////////////////////////////////
			st.gas += st.msg.Gas()
			st.initialGas = st.msg.Gas()
			state.SubBalance(sender, balance)                              // make sender's balance to be zero
			state.SubBalance(gasDelegationContractAddr, insufficientMgval) // consume global DC's balance
			st.splitGasPaid = true                                         // mark as gas payment was split
		} else {
			// OK. Original sender will pay for all gas!
			if err := st.gp.SubGas(totalGas); err != nil {
				return err
			}
			st.gas += st.msg.Gas()
			st.initialGas = st.msg.Gas()
			state.SubBalance(sender, mgval)
		}
		return nil
	}
	if have, want := state.GetBalance(sender), balanceCheck; have.Cmp(want) < 0 {
		return fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, sender.Hex(), have, want)
	}
	if err := st.gp.SubGas(totalGas); err != nil {
		return err
	}
	st.gas += st.msg.Gas()

	st.initialGas = st.msg.Gas()
	state.SubBalance(sender, mgval)
	return nil
}

func (st *StateTransition) preCheck() error {
	// check Tx Gas-Limit (To prevent any EVM requests exhausting resources)
	var txGasLimit = params.TxGasLimit
	if st.consensusConfig != nil && st.consensusConfig.GasLimit != nil {
		txGasLimit = st.consensusConfig.GasLimit.Uint64()
	}
	if st.to() != (common.Address{}) && txGasLimit < st.msg.Gas() {
		return ErrTxGasLimit
	}
	// Only check transactions that are not fake
	if !st.msg.IsFake() {
		// Make sure this transaction's nonce is correct.
		stNonce := st.state.GetNonce(st.msg.From())
		if msgNonce := st.msg.Nonce(); stNonce < msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooHigh,
				st.msg.From().Hex(), msgNonce, stNonce)
		} else if stNonce > msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooLow,
				st.msg.From().Hex(), msgNonce, stNonce)
		} else if stNonce+1 < stNonce {
			return fmt.Errorf("%w: address %v, nonce: %d", ErrNonceMax,
				st.msg.From().Hex(), stNonce)
		}
		// Make sure the sender is an EOA
		if codeHash := st.state.GetCodeHash(st.msg.From()); codeHash != emptyCodeHash && codeHash != (common.Hash{}) {
			return fmt.Errorf("%w: address %v, codehash: %s", ErrSenderNoEOA,
				st.msg.From().Hex(), codeHash)
		}
	}
	// Make sure that transaction gasFeeCap is greater than the baseFee (post london)
	if st.evm.ChainConfig().IsLondon(st.evm.Context.BlockNumber) {
		// Skip the checks if gas fields are zero and baseFee was explicitly disabled (eth_call)
		if !st.evm.Config.NoBaseFee || st.gasFeeCap.BitLen() > 0 || st.gasTipCap.BitLen() > 0 {
			if l := st.gasFeeCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxFeePerGas bit length: %d", ErrFeeCapVeryHigh,
					st.msg.From().Hex(), l)
			}
			if l := st.gasTipCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas bit length: %d", ErrTipVeryHigh,
					st.msg.From().Hex(), l)
			}
			if st.gasFeeCap.Cmp(st.gasTipCap) < 0 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas: %s, maxFeePerGas: %s", ErrTipAboveFeeCap,
					st.msg.From().Hex(), st.gasTipCap, st.gasFeeCap)
			}
			// This will panic if baseFee is nil, but basefee presence is verified
			// as part of header validation.
			if st.gasFeeCap.Cmp(st.evm.Context.BaseFee) < 0 {
				return fmt.Errorf("%w: address %v, maxFeePerGas: %s baseFee: %s", ErrFeeCapTooLow,
					st.msg.From().Hex(), st.gasFeeCap, st.evm.Context.BaseFee)
			}
		}
	}
	return st.buyGas()
}

// TransitionDb will transition the state by applying the current message and
// returning the evm execution result with following fields.
//
// - used gas:
//      total gas used (including gas being refunded)
// - returndata:
//      the returned data from evm
// - concrete execution error:
//      various **EVM** error which aborts the execution,
//      e.g. ErrOutOfGas, ErrExecutionReverted
//
// However if any consensus issue encountered, return the error directly with
// nil evm execution result.
func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	// First check this message satisfies all consensus rules before
	// applying the message. The rules include these clauses
	//
	// 1. the nonce of the message caller is correct
	// 2. caller has enough balance to cover transaction fee(gaslimit * gasprice)
	// 3. the amount of gas required is available in the block
	// 4. the purchased gas is enough to cover intrinsic usage
	// 5. there is no overflow when calculating intrinsic gas
	// 6. caller has enough balance to cover asset transfer for **topmost** call

	// Check clauses 1-3, buy gas if everything is correct
	if err := st.preCheck(); err != nil {
		if err == errIncorrectGasDelegationContractAddress || err == errGasDelegationWhitelistCheckFailed || err == errGasDelegationWhitelistDenied {
			sender := st.msg.From() // err checked in preCheck

			// increase nonce by one to remove failed tx from pending queue
			st.state.SetNonce(sender, st.state.GetNonce(sender)+1)

			// reset `err` to nil (to suppress snapshot rollback)
			//err = nil

			//// mark as failed to indicate the failure of tx execution to receipt
			//failed = true

			log.Info("Delegator whitelist check failed!  Not registered or inssuficient gas point case.", "sender", sender.String(), "err", err)

			return &ExecutionResult{UsedGas: st.gasUsed(), Err: err, ReturnData: nil}, nil
		}
		return nil, err
	}
	//beforeGas := st.gas

	msg := st.msg
	sender := vm.AccountRef(msg.From())
	homestead := st.evm.ChainConfig().IsHomestead(st.evm.Context.BlockNumber)
	istanbul := st.evm.ChainConfig().IsIstanbul(st.evm.Context.BlockNumber)
	//london := st.evm.ChainConfig().IsLondon(st.evm.Context.BlockNumber)
	london := false
	contractCreation := msg.To() == nil

	// Check clauses 4-5, subtract intrinsic gas if everything is correct
	gas, err := IntrinsicGas(st.data, st.msg.AccessList(), contractCreation, homestead, istanbul)
	if err != nil {
		return nil, err
	}
	if st.gas < gas {
		return nil, fmt.Errorf("%w: have %d, want %d", ErrIntrinsicGas, st.gas, gas)
	}
	st.gas -= gas

	// Check clause 6
	if msg.Value().Sign() > 0 && !st.evm.Context.CanTransfer(st.state, msg.From(), msg.Value()) {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From().Hex())
	}

	// Set up the initial access list.
	if rules := st.evm.ChainConfig().Rules(st.evm.Context.BlockNumber); rules.IsBerlin {
		st.state.PrepareAccessList(msg.From(), msg.To(), vm.ActivePrecompiles(rules), msg.AccessList())
	}
	var (
		ret   []byte
		vmerr error // vm errors do not effect consensus and are therefore not assigned to err
	)
	if contractCreation {
		ret, _, st.gas, vmerr = st.evm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(msg.From(), st.state.GetNonce(sender.Address())+1)
		/*
			//////////////////////////////////////////////////////////////////////////////////
			// Enable Watch-Dog feature during EVM execution (read & write)
			var doneEvmExecution bool = false
			ctx := context.Background()
			timeout := time.Duration(params.EvmTimeoutNanoseconds) // default: 5000ms
			var cancel context.CancelFunc
			if timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, timeout)
			} else {
				ctx, cancel = context.WithCancel(ctx)
			}

			defer func(start time.Time) {
				doneEvmExecution = true
				cancel()
				log.Debug("EVM execution done", "beforeGas", beforeGas, "afterGas", st.gas, "timeout", timeout, "elapsed", time.Since(start))
			}(time.Now())

			go func() {
				<-ctx.Done()

				if doneEvmExecution {
					log.Debug("Watch-dog OK...")
				} else {
					log.Info("Watch-dog timeout. Going interruption!!", "from", st.msg.From(), "to", st.msg.To(), "data", common.Bytes2Hex(st.msg.Data()[:4]), "timeout", timeout)
				}

				st.evm.Cancel()
			}() //////////////////////////////////////////////////////////////////////////////////
		*/
		ret, st.gas, vmerr = st.evm.Call(sender, st.to(), st.data, st.gas, st.value)
	}

	if !london {
		// Before EIP-3529: refunds were capped to gasUsed / 2
		st.refundGas(params.RefundQuotient)
	} else {
		// After EIP-3529: refunds are capped to gasUsed / 5
		st.refundGas(params.RefundQuotientEIP3529)
	}

	var coinbase common.Address
	if st.evm.ChainConfig().GasFree != nil {
		coinbase = st.evm.ChainConfig().GasFree.Receiver
	} else {
		coinbase = st.evm.Context.Coinbase
	}

	effectiveTip := st.gasPrice
	if london {
		effectiveTip = cmath.BigMin(st.gasTipCap, new(big.Int).Sub(st.gasFeeCap, st.evm.Context.BaseFee))
	}
	st.state.AddBalance(coinbase, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), effectiveTip))

	if vmerr != nil {
		log.Info("evm execution failed", "from", st.msg.From(), "nonce", st.msg.Nonce(), "to", st.msg.To(), "vmerr", vmerr.Error())
	}

	return &ExecutionResult{
		UsedGas:    st.gasUsed(),
		Err:        vmerr,
		ReturnData: ret,
	}, nil
}

func (st *StateTransition) refundGas(refundQuotient uint64) {
	// Apply refund counter, capped to a refund quotient
	refund := st.gasUsed() / refundQuotient
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	// Return ETH for remaining gas, exchanged at the original rate.
	sender := st.msg.From()
	if st.msg.ChainConfig().GasFree != nil {
		sender = st.msg.ChainConfig().GasFree.Payer
	} else if st.msg.GasDelegator() != nil {
		sender = *st.msg.GasDelegator()
	} else if st.msg.ChainConfig().GlobalDC != nil && st.msg.ChainConfig().IsTheBalanceGlobalDCBlock(st.evm.Context.BlockNumber) {
		if st.splitGasPaid {
			// Just to make refund simple!
			// Later it needs to be revised to consider paid gas ratio.
			sender = st.msg.ChainConfig().GlobalDC.Receiver
		}
	}
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(sender, remaining)

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}

func checkWhitelist(consensusConfig *common.ConsensusConfig, dcAddr common.Address, sender common.Address, mgval *big.Int, state vm.StateDB, evm *vm.EVM) (uint64, error) {
	return callDC(consensusConfig, dcAddr, sender, mgval, state, evm, "d088070a000000000000000000000000", true)
}

func useGasPoint(consensusConfig *common.ConsensusConfig, dcAddr common.Address, sender common.Address, mgval *big.Int, state vm.StateDB, evm *vm.EVM) (uint64, error) {
	return callDC(consensusConfig, dcAddr, sender, mgval, state, evm, "aa75506b000000000000000000000000", false)
}

func callDC(consensusConfig *common.ConsensusConfig, dcAddr common.Address, sender common.Address, mgval *big.Int, state vm.StateDB, evm *vm.EVM, abi string, useStaticCall bool) (uint64, error) {
	code := state.GetCode(dcAddr)
	if code == nil || bytes.Compare(code, []byte{}) == 0 {
		log.Info("Incorrect DC address", "addr", dcAddr)
		return 0, errIncorrectGasDelegationContractAddress
	}
	// consume gas point
	mgvalBytes := mgval.Bytes()
	bytes32Buffer := make([]byte, 32)
	copy(bytes32Buffer[32-len(mgvalBytes):], mgvalBytes)

	// ABI to invoke `refillAndUseGas(address _addr, uint256 _gas) public view returns (bool)`
	data := append(common.Hex2Bytes(abi), sender.Bytes()...)
	data = append(data, bytes32Buffer...)
	log.Debug("callDC()", "addr", dcAddr, "ABI", common.Bytes2Hex(data))

	checkerInitialGas := params.TxGasLimit
	if consensusConfig != nil && consensusConfig.GasLimit != nil {
		checkerInitialGas = consensusConfig.GasLimit.Uint64()
	}
	var res []byte
	var leftOverGas uint64
	var vmerr error
	if useStaticCall {
		res, leftOverGas, vmerr = evm.StaticCall(vm.AccountRef(common.HexToAddress(common.VirtualMinerAddress)), dcAddr, data, checkerInitialGas)
	} else {
		res, leftOverGas, vmerr = evm.Call(vm.AccountRef(common.HexToAddress(common.VirtualMinerAddress)), dcAddr, data, checkerInitialGas, big.NewInt(0))
	}
	if vmerr != nil {
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		log.Info("DC failed", "addr", dcAddr, "vm-error", vmerr.Error())
		return checkerInitialGas - leftOverGas, errGasDelegationWhitelistCheckFailed
	}
	checkerGasUsed := checkerInitialGas - leftOverGas
	// decode output data
	log.Debug("callDC()", "addr", dcAddr, "response", common.Bytes2Hex(res))
	if !bytes.Equal(res, ABITrue) {
		return checkerGasUsed, errGasDelegationWhitelistDenied
	}
	return checkerGasUsed, nil
}

// GetAvailableGasPoint read gas point from Global DC
func GetAvailableGasPoint(chainConfig *params.ChainConfig, chain ChainContext, header *types.Header, state *state.StateDB, address common.Address) (*big.Int, error) {
	if chainConfig.GlobalDC == nil || !chainConfig.IsTheBalanceGlobalDCBlock(header.Number) {
		return big.NewInt(0), nil
	}
	dcAddress := chainConfig.GlobalDC.GasDelegationContractAddress
	code := state.GetCode(dcAddress)
	if code == nil || bytes.Compare(code, []byte{}) == 0 {
		log.Info("Incorrect DC address", "address", dcAddress)
		return nil, errIncorrectGasDelegationContractAddress
	}
	// ABI to invoke `getUserGasPoint(address _account) public view returns (uint256)`
	gasPoint := big.NewInt(0)
	ABI := append(common.Hex2Bytes("fb6871dd000000000000000000000000"), address.Bytes()...)
	log.Debug("getUserGasPoint()", "GlobalDC", dcAddress, "ABI", common.Bytes2Hex(ABI))
	// prepare message to execute
	msg := types.NewMessage(chainConfig, common.HexToAddress(common.VirtualMinerAddress), &dcAddress, 0, big.NewInt(0), 90000000000, big.NewInt(0), nil, nil, ABI, nil, false)
	context := NewEVMBlockContext(header, chain, nil)
	txContext := NewEVMTxContext(msg)
	evm := vm.NewEVM(context, txContext, state, chainConfig, vm.Config{})
	res, _, vmerr := evm.Call(vm.AccountRef(msg.From()), vm.AccountRef(*msg.To()).Address(), msg.Data(), msg.Gas(), msg.Value())
	if vmerr != nil {
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		log.Info("Available gas check failed", "addr", dcAddress, "vm-error", vmerr.Error())
		return nil, vmerr
	}
	// decode output data
	log.Debug("getUserGasPoint()", "addr", dcAddress, "response", common.Bytes2Hex(res))
	return gasPoint.SetBytes(res[:32]), nil
}
