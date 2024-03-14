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
	"github.com/ethereum/go-ethereum/log"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
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
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)
	// read consensus configuration from system contract
	var consensusConfig *common.ConsensusConfig = nil
	if p.config != nil && p.config.Clique != nil && p.config.Clique.HasConsensusConfiguration() {
		parentHeader := p.bc.GetHeader(block.ParentHash(), block.NumberU64()-1)
		if parentHeader == nil {
			return nil, nil, 0, consensus.ErrUnknownAncestor
		}
		consensusConfig = RetrieveConsensusConfigurations(p.bc, parentHeader, statedb, p.config)
	}
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	if p.config.EnhancedBridge != nil && p.config.EnhancedBridgeForkBlock != nil && p.config.EnhancedBridgeForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyEnhancedBridgeHardFork(statedb, p.config)
	}
	blockContext := NewEVMBlockContext(header, p.bc, nil)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, p.config, cfg)
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		msg, err := tx.AsMessage(p.config, types.MakeSigner(p.config, header.Number), header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.Prepare(tx.Hash(), i)
		receipt, err := applyTransaction(consensusConfig, msg, p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(consensusConfig, p.bc, header, statedb, block.Transactions(), block.Uncles())

	return receipts, allLogs, *usedGas, nil
}

func applyTransaction(consensusConfig *common.ConsensusConfig, msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(consensusConfig, evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(consensusConfig *common.ConsensusConfig, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := tx.AsMessage(config, types.MakeSigner(config, header.Number), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	return applyTransaction(consensusConfig, msg, config, bc, author, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}

var consensusConfigurationCache, _ = lru.NewARC(4096)

func RetrieveConsensusConfigurations(chain ChainContext, header *types.Header, statedb *state.StateDB, chainConfig *params.ChainConfig) *common.ConsensusConfig {
	hasher := sha3.New256()
	hasher.Write(header.Number.Bytes())
	hasher.Write(header.Hash().Bytes())
	key := common.BytesToHash(hasher.Sum(nil))
	if prev, ok := consensusConfigurationCache.Get(key); ok {
		return prev.(*common.ConsensusConfig)
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Read consensus configurations from system contract.
	// It is intended to be used only for `Mainnet Core`.
	// That is, DO NOT enable any consensus configurations in side-chains. (i.e., shared side-chain and dedicated side-chain).

	// prepare message to execute
	fromAddr := common.HexToAddress(common.VirtualMinerAddress) /* pre-defined address used to execute contract call */
	toAddr := common.HexToAddress(common.ConsensusContractAddress)
	data := common.Hex2Bytes(common.GetConsensusConfig)

	msg := types.NewMessage(chainConfig, fromAddr, &toAddr, 0, big.NewInt(0), 90000000000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, false)
	//log.Trace("*****", "vmAccountRef", vm.AccountRef(msg.From()).Address())

	// For `importChain` case, DO NOT execute on canonical block! (In this case, we have to consider any possible side-forks)
	txContext := NewEVMTxContext(msg)
	blockContext := NewEVMBlockContext(header, chain, nil)
	evm := vm.NewEVM(blockContext, txContext, statedb, chainConfig, vm.Config{})
	res, _, vmerr := evm.StaticCall(vm.AccountRef(msg.From()), vm.AccountRef(*msg.To()).Address(), msg.Data(), msg.Gas())
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
	log.Debug(fmt.Sprintf("--- ConsensusConfig info (json): header.Number=%+v, header.Hash=%+v, %s", header.Number, header.Hash(), string(responseData)))
	////////////////////////////////////////////////////////////////////////////////////////////////////////////

	consensusConfigurationCache.Add(key, consensusConfig)
	return consensusConfig
}
