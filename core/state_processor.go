// Copyright 2015 The go-ethereum Authors
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
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor)Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit())
	)

	// read consensus configuration from system contract
	var consensusConfig *common.ConsensusConfig = nil
	if p.config != nil && p.config.Clique != nil && p.config.Clique.HasConsensusConfiguration() {
		parentHeader := p.bc.GetHeader(block.ParentHash(), block.NumberU64() - 1)
		if parentHeader == nil {
			return nil, nil, 0, consensus.ErrUnknownAncestor
		}
		consensusConfig = RetrieveConsensusConfigurations(p.bc, parentHeader, statedb, p.config)
	}

	// Mutate the the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, _, err := ApplyTransaction(consensusConfig, p.config, p.bc, nil, gp, statedb, header, tx, usedGas, cfg)
		if err != nil {
			return nil, nil, 0, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(consensusConfig, p.bc, header, statedb, block.Transactions(), block.Uncles(), receipts)

	return receipts, allLogs, *usedGas, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(consensusConfig *common.ConsensusConfig, config *params.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, uint64, error) {
	msg, err := tx.AsMessage(config, types.MakeSigner(config, header.Number))
	if err != nil {
		return nil, 0, err
	}
	// Create a new context to be used in the EVM environment
	context := NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)
	_, gas, failed, err := ApplyMessage(consensusConfig, vmenv, msg, gp)
	if err != nil {
		return nil, 0, err
	}
	// Update the state with pending changes
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += gas

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = gas
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	return receipt, gas, err
}

func RetrieveConsensusConfigurations(bc *BlockChain, header *types.Header, statedb *state.StateDB, chainConfig *params.ChainConfig) *common.ConsensusConfig {
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Read consensus configurations from system contract.
	// It is intended to be used only for `Mainnet Core`.
	// That is, DO NOT enable any consensus configurations in side-chains. (i.e., shared side-chain and dedicated side-chain).

	// prepare message to execute
	fromAddr := common.HexToAddress(common.VirtualMinerAddress) /* pre-defined address used to execute contract call */
	toAddr := common.HexToAddress(common.ConsensusContractAddress)
	data := common.Hex2Bytes(common.GetConsensusConfig)

	msg := types.NewMessage(chainConfig, fromAddr, &toAddr, 0, big.NewInt(0), 90000000000, big.NewInt(0), data, false)
	//log.Trace("*****", "vmAccountRef", vm.AccountRef(msg.From()).Address())

	// For `importChain` case, DO NOT execute on canonical block! (In this case, we have to consider any possible side-forks)
	context := NewEVMContext(msg, header, bc, nil)
	evm := vm.NewEVM(context, statedb, chainConfig, vm.Config{})
	res, _, vmerr := evm.Call(vm.AccountRef(msg.From()), vm.AccountRef(*msg.To()).Address(), msg.Data(), msg.Gas(), msg.Value())
	if vmerr != nil {
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		panic(fmt.Sprintf("VM returned with error: %s", vmerr.Error()))
	}

	// decode output data
	responseDataLengthLoc := new(big.Int)
	responseDataLengthLoc.SetBytes(res[:32])

	responseDataStartLoc := responseDataLengthLoc.Uint64() + 32
	responseDataLength := new(big.Int)
	responseDataLength.SetBytes(res[responseDataLengthLoc.Uint64():responseDataStartLoc])

	responseData := res[responseDataStartLoc : responseDataStartLoc+responseDataLength.Uint64()]
	//log.Debug("Consensus configurations", "hex", hexutil.Encode(responseData))
	//log.Debug("Consensus configurations", "json", string(responseData))

	consensusConfig := new(common.ConsensusConfig)
	if err := json.Unmarshal(responseData[:], consensusConfig); err != nil {
		panic(fmt.Sprintf("Failed to parse ConsensusConfig response: %+v", err))
	}
	log.Debug(fmt.Sprintf("ConsensusConfig info (json): %+v", consensusConfig))
	////////////////////////////////////////////////////////////////////////////////////////////////////////////

	return consensusConfig
}