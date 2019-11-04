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
	"context"
	"errors"
	"math"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

var (
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")

	errIncorrectGasDelegationWhitelistContractAddress = errors.New("incorrect gas delegation whitelist contract address was given")

	errGasDelegationWhitelistCheckFailed = errors.New("gas delegation whitelist check failed")

	errGasDelegationWhitelistDenied = errors.New("gas delegation whitelist denied")
)

var ABITrue = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001")

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all all the necessary work to work out a valid new state root.

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
	gp         *GasPool
	msg        Message
	gas        uint64
	gasPrice   *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	//FromFrontier() (common.Address, error)
	To() *common.Address

	GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	CheckNonce() bool
	Data() []byte

	// contextual information
	ChainConfig() *params.ChainConfig
	GasDelegator() *common.Address
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, contractCreation, homestead bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	if contractCreation && homestead {
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
		if (math.MaxUint64-gas)/params.TxDataNonZeroGas < nz {
			return 0, vm.ErrOutOfGas
		}
		gas += nz * params.TxDataNonZeroGas

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, vm.ErrOutOfGas
		}
		gas += z * params.TxDataZeroGas
	}
	return gas, nil
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(consensusConfig *common.ConsensusConfig, evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		consensusConfig: consensusConfig,
		gp:       gp,
		evm:      evm,
		msg:      msg,
		gasPrice: msg.GasPrice(),
		value:    msg.Value(),
		data:     msg.Data(),
		state:    evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(consensusConfig *common.ConsensusConfig, evm *vm.EVM, msg Message, gp *GasPool) ([]byte, uint64, bool, error) {
	return NewStateTransition(consensusConfig, evm, msg, gp).TransitionDb()
}

func (st *StateTransition) from() vm.AccountRef {
	f := st.msg.From()
	if !st.state.Exist(f) {
		st.state.CreateAccount(f)
	}
	return vm.AccountRef(f)
}

func (st *StateTransition) to() vm.AccountRef {
	if st.msg == nil {
		return vm.AccountRef{}
	}
	to := st.msg.To()
	if to == nil {
		return vm.AccountRef{} // contract creation
	}

	reference := vm.AccountRef(*to)
	if !st.state.Exist(*to) {
		st.state.CreateAccount(*to)
	}
	return reference
}

func (st *StateTransition) useGas(amount uint64) error {
	if st.gas < amount {
		return vm.ErrOutOfGas
	}
	st.gas -= amount

	return nil
}

func (st *StateTransition) buyGas() error {
	var (
		state  = st.state
		sender = st.from()
	)

	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasPrice)

	if st.msg.ChainConfig().GasFree != nil {
		sender = vm.AccountRef(st.msg.ChainConfig().GasFree.Payer)
	} else if st.msg.GasDelegator() != nil {
		gasDelegationWhitelistContractAddr := st.msg.GasDelegator()
		code := state.GetCode(*gasDelegationWhitelistContractAddr)
		if code == nil || bytes.Compare(code, []byte {}) == 0 {
			log.Info("Incorrect Gas-Delegation-Whitelist contract address", "addr", gasDelegationWhitelistContractAddr)
			return errIncorrectGasDelegationWhitelistContractAddress
		}

		// check Gas-Delegation Whitelist
		mgvalBytes := mgval.Bytes()
		bytes32Buffer := make([]byte, 32)
		copy(bytes32Buffer[32 - len(mgvalBytes):], mgvalBytes)

		// ABI to invoke `checkWhitelist(address _addr, uint256 _gas) public view returns (bool)`
		data := append(common.Hex2Bytes("d088070a000000000000000000000000"), sender.Address().Bytes()...)
		data = append(data, bytes32Buffer...)

		log.Debug("checkWhitelist()", "addr", gasDelegationWhitelistContractAddr, "ABI", common.ToHex(data))

		res, _, vmerr := st.evm.Call(vm.AccountRef(common.HexToAddress(common.VirtualMinerAddress)), *gasDelegationWhitelistContractAddr, data, 90000000000, big.NewInt(0))
		if vmerr != nil {
			// The only possible consensus-error would be if there wasn't
			// sufficient balance to make the transfer happen. The first
			// balance transfer may never fail.
			log.Info("Gas-Delegation-Whitelist check failed", "addr", gasDelegationWhitelistContractAddr, "vm-error", vmerr.Error())
			return errGasDelegationWhitelistCheckFailed
		}

		// decode output data
		log.Debug("checkWhitelist()", "addr", gasDelegationWhitelistContractAddr, "response", common.ToHex(res))

		if !bytes.Equal(res, ABITrue) {
			return errGasDelegationWhitelistDenied
		}

		sender = vm.AccountRef(*st.msg.GasDelegator())
	}

	if state.GetBalance(sender.Address()).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.gas += st.msg.Gas()

	st.initialGas = st.msg.Gas()
	state.SubBalance(sender.Address(), mgval)
	return nil
}

func (st *StateTransition) preCheck() error {
	msg := st.msg

	// check Tx Gas-Limit (To prevent any EVM requests exhausting resources)
	var txGasLimit = params.TxGasLimit
	if st.consensusConfig != nil && st.consensusConfig.GasLimit != nil {
		txGasLimit = st.consensusConfig.GasLimit.Uint64()
	}
	if st.to() != vm.AccountRef(common.Address{}) && txGasLimit < msg.Gas() {
		return ErrTxGasLimit
	}

	sender := st.from()

	// Make sure this transaction's nonce is correct
	if msg.CheckNonce() {
		nonce := st.state.GetNonce(sender.Address())
		if nonce < msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return st.buyGas()
}

// TransitionDb will transition the state by applying the current message and
// returning the result including the the used gas. It returns an error if it
// failed. An error indicates a consensus issue.
func (st *StateTransition) TransitionDb() (ret []byte, usedGas uint64, failed bool, err error) {
	if err = st.preCheck(); err != nil {
        if err == errIncorrectGasDelegationWhitelistContractAddress || err == errGasDelegationWhitelistCheckFailed || err == errGasDelegationWhitelistDenied {
        	sender := st.from() // err checked in preCheck

            // increase nonce by one to remove failed tx from pending queue
            st.state.SetNonce(sender.Address(), st.state.GetNonce(sender.Address())+1)

            // reset `err` to nil (to suppress snapshot rollback)
            err = nil

            // mark as failed to indicate the failure of tx execution to receipt
            failed = true

			log.Info("Delegator whitelist check failed!", "sender", sender, "err", err)
        }
		return
	}
	beforeGas := st.gas

	msg := st.msg
	sender := st.from() // err checked in preCheck

	homestead := st.evm.ChainConfig().IsHomestead(st.evm.BlockNumber)
	contractCreation := msg.To() == nil

	// Pay intrinsic gas
	gas, err := IntrinsicGas(st.data, contractCreation, homestead)
	if err != nil {
		return nil, 0, false, err
	}
	if err = st.useGas(gas); err != nil {
		return nil, 0, false, err
	}

	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)
	if contractCreation {
		ret, _, st.gas, vmerr = evm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(sender.Address(), st.state.GetNonce(sender.Address())+1)

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

			evm.Cancel()
		}()//////////////////////////////////////////////////////////////////////////////////

		ret, st.gas, vmerr = evm.Call(sender, st.to().Address(), st.data, st.gas, st.value)
	}
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == vm.ErrInsufficientBalance {
			return nil, 0, false, vmerr
		}
	}
	st.refundGas()

	var coinbase = common.Address{}
	if st.evm.ChainConfig().GasFree != nil {
		coinbase = st.evm.ChainConfig().GasFree.Receiver
	} else {
		coinbase = st.evm.Coinbase
	}
	st.state.AddBalance(coinbase, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), st.gasPrice))

	if vmerr != nil {
		log.Info("evm execution failed", "from", st.msg.From(), "nonce", st.msg.Nonce(), "to", st.msg.To(), "vmerr", vmerr.Error())
	}

	return ret, st.gasUsed(), vmerr != nil, err
}

func (st *StateTransition) refundGas() {
	// Apply refund counter, capped to half of the used gas.
	refund := st.gasUsed() / 2
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	// Return ETH for remaining gas, exchanged at the original rate.
	sender := st.from()

	if st.msg.ChainConfig().GasFree != nil {
		sender = vm.AccountRef(st.msg.ChainConfig().GasFree.Payer)
	} else if st.msg.GasDelegator() != nil {
		sender = vm.AccountRef(*st.msg.GasDelegator())
	}

	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(sender.Address(), remaining)

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
