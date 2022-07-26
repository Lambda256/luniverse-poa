// Copyright 2017 The go-ethereum Authors
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

// Package clique implements the proof-of-authority consensus engine.
package clique

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/vm"
	"io"
	"math"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory

	wiggleTime = 500 * time.Millisecond // Random delay (per signer) to allow concurrent signers
)

// Clique proof-of-authority protocol constants.
var (
	epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending votes

	extraVanity = 32                     // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal

	nonceAuthVote = hexutil.MustDecode("0xff") // Magic nonce number to vote on adding a new signer
	nonceDropVote = hexutil.MustDecode("0x00") // Magic nonce number to vote on removing a signer.

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffInTurn = big.NewInt(1) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidTimeContext is returned if current time is invalid after delay
	errInvalidTimeContext = errors.New("invalid time context")

	// errMissingSealTimestamp is returned if extra header does not contain seal timestamp
	errMissingSealTimestamp = errors.New("missing seal timestamp")

	// errInvalidSealTimestamp is returned if seal timestamp is invalid
	errInvalidSealTimestamp = errors.New("invalid seal timestamp")

	// errInvalidExtraProtocol is returned if extra protocol data is wrong. (i.e., ver[1] | type[1] | len[2])
	errInvalidExtraProtocol = errors.New("invalid extra protocol data")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")

	// errInvalidCheckpointVote is returned if a checkpoint/epoch transition block
	// has a vote nonce set to non-zeroes.
	errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of signers (i.e. non divisible by 20 bytes).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of signers different than the one the local node calculated.
	errMismatchingCheckpointSigners = errors.New("mismatching signer list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")
)

// SignerFn hashes and signs the data to be signed by a backing account.
type SignerFn func(signer accounts.Account, mimeType string, message []byte) ([]byte, error)

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// Clique is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type Clique struct {
	cliqueConfig   *params.CliqueConfig // Consensus engine configuration parameters
	chainConfig    *params.ChainConfig
	db             ethdb.Database      // Database to store and retrieve snapshot checkpoints
	blockAccessor  core.BlockAccessor  // it will be set after instantiation
	txPoolAccessor core.TxPoolAccessor // it will be set after instantiation

	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	proposals map[common.Address]bool // Current list of proposals we are pushing

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with
	lock   sync.RWMutex   // Protects the signer fields

	dynamicBlockPeriod uint64       // cached block period
	paramsLock         sync.RWMutex // protects the global parameters (i.e., params.TargetGasLimit, params.TargetGasLimitCalculation, params.TxGasLimit, ...)

	//chainApi *ethapi.PublicBlockChainAPI // used to invoke eth_call() API later (i.e., to refer any system data resides in block reward contract)

	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

// New creates a Clique proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
func New(chainConfig *params.ChainConfig, db ethdb.Database) *Clique {
	// Set any missing consensus parameters to their defaults
	config := *chainConfig.Clique
	if config.Epoch == 0 {
		config.Epoch = epochLength
	}
	if config.SnapshotInterval == 0 {
		config.SnapshotInterval = checkpointInterval
	}

	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)

	return &Clique{
		cliqueConfig: &config,
		chainConfig:  chainConfig,
		db:           db,

		recents:    recents,
		signatures: signatures,
		proposals:  make(map[common.Address]bool),

		dynamicBlockPeriod: config.Period, /* it SHOULD BE same with `blockPeriod` value in system contract */
	}
}

func (c *Clique) Initialize(blockAccessor core.BlockAccessor, txPoolAccessor core.TxPoolAccessor) {
	c.blockAccessor = blockAccessor
	c.txPoolAccessor = txPoolAccessor
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (c *Clique) Author(header *types.Header) (common.Address, error) {
	//return ecrecover(header, c.signatures)
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *Clique) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	//consensusConfig, err := c.GetConsensusConfigurations(header, nil)
	//if err != nil {
	//	return err
	//}
	return c.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (c *Clique) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			//parents := headers[:i]
			//consensusConfig, err := c.GetConsensusConfigurations(header, parents)
			//if err == nil {
			//	err := c.verifyHeader(chain, header, parents)
			//}

			err := c.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *Clique) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Epoch blocks need to enforce zero beneficiary
	isEpochBlock := (number % c.cliqueConfig.Epoch) == 0
	//if checkpoint && header.Coinbase != (common.Address{}) {
	//	return errInvalidCheckpointBeneficiary
	//}
	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	//if !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
	//	return errInvalidVote
	//}
	//if checkpoint && !bytes.Equal(header.Nonce[:], nonceDropVote) {
	//	return errInvalidCheckpointVote
	//}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+8 {
		return errMissingSealTimestamp
	}
	if len(header.Extra) < extraVanity+8+extraSeal {
		return errMissingSignature
	}

	// TODO: Need more enhancement on validity check of seal timestamp
	sealTimestamp := c.ExtractSealTimeUint64(header)
	//log.Info("Verifying seal timestamp", "Number", header.Number.Uint64(), "header.Time", header.Time.Uint64(), "seal-Timestamp", sealTimestamp, "diff", sealTimestamp - (header.Time.Uint64() * 1000))
	if header.Time*1000 > sealTimestamp {
		log.Error("Incorrect seal timestamp", "Number", header.Number.Uint64(), "header.Time", header.Time, "seal-Timestamp", sealTimestamp)
		return errInvalidSealTimestamp
	}

	// Ensure that the extra-data contains (1) a signer list on checkpoint, but (2) none or (3) cast-vote otherwise
	//signersBytes := len(header.Extra) - extraVanity - extraSeal
	//if !checkpoint && signersBytes != 0 {
	//	return errExtraSigners
	//}
	//if checkpoint && signersBytes%common.AddressLength != 0 {
	//	return errInvalidCheckpointSigners
	//}
	protocolDataBytes := header.Extra[extraVanity+8 : len(header.Extra)-extraSeal]
	if len(protocolDataBytes) < 4 {
		return errInvalidExtraProtocol
	}
	protoVer := protocolDataBytes[0]
	protoType := protocolDataBytes[1]
	protoLen := binary.BigEndian.Uint16(protocolDataBytes[2:4])
	protoData := protocolDataBytes[4:]
	if protoVer != 0x00 {
		return errInvalidExtraProtocol
	}
	if protoLen != uint16(len(protoData)) {
		return errInvalidExtraProtocol
	}
	switch protoType {
	case 0x00: // default (No additional protocol data is present)
		if protoLen != 0 {
			return errInvalidExtraProtocol
		}
		if isEpochBlock {
			return errInvalidCheckpointSigners
		}
	case 0x01: // List current singers (only in Epoch block)
		if !isEpochBlock || protoLen <= 0 || protoLen%common.AddressLength != 0 {
			return errInvalidCheckpointSigners
		}
	case 0x02: // Cast vote
		if protoLen != (common.AddressLength + 1) {
			return errInvalidExtraProtocol
		}
		if isEpochBlock {
			return errInvalidCheckpointSigners
		}
		if !bytes.Equal(protoData[common.AddressLength:], nonceAuthVote) && !bytes.Equal(protoData[common.AddressLength:], nonceDropVote) {
			return errInvalidVote
		}
	default:
		return errInvalidExtraProtocol
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
		}
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}
	// All basic checks passed, verify cascading fields
	return c.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (c *Clique) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to its parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	//var blockPeriod uint64
	//if consensusConfig != nil && consensusConfig.BlockPeriod != nil {
	//	blockPeriod = *consensusConfig.BlockPeriod
	//} else {
	//	blockPeriod = c.cliqueConfig.Period
	//}

	// Fixme:	Theoretically, cached blockPeriod may cause incorrect behavior.
	//  		However, there is no way to read parent block's stateDB while execution of bunch of header verification...
	//			1. Caching block time info for each block number? or Storing histories of block period changes?
	//			2. Fix to use equality check instead of '>'?
	if parent.Time+c.dynamicBlockPeriod > header.Time {
		log.Warn("Invalid block time (too close)", "number", header.Number.Uint64(), "hash", header.Hash(), "parent.Time", parent.Time, "blockPeriod", c.dynamicBlockPeriod, "header.Time", header.Time)
		return errInvalidTimestamp
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, want <nil>", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := misc.VerifyEip1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	// If the block is a checkpoint block, verify the signer list
	if number%c.cliqueConfig.Epoch == 0 {
		signers := make([]byte, len(snap.Signers)*common.AddressLength)
		for i, signer := range snap.signers() {
			copy(signers[i*common.AddressLength:], signer[:])
		}
		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity+8+4:extraSuffix], signers) {
			log.Warn("::: Epoch block ::: (verify signers => FAILED)", "number", number, "hash", header.Hash(), "Epoch", c.cliqueConfig.Epoch, "signers", signers)
			return errMismatchingCheckpointSigners
		}
		log.Info("::: Epoch block ::: (verify signers => SUCCESS)", "number", number, "hash", header.Hash(), "Epoch", c.cliqueConfig.Epoch)
	}
	// All basic checks passed, verify the seal and return
	return c.verifySeal(chain, header, parents)
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (c *Clique) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := c.recents.Get(hash); ok {
			log.Trace("::: Authority snapshot ::: (loading from memory => SUCCESS)", "number", number, "hash", hash)
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%c.cliqueConfig.SnapshotInterval == 0 {
			if s, err := loadSnapshot(c.cliqueConfig, c.signatures, c.db, hash); err == nil {
				log.Trace("::: Authority snapshot ::: (loading from DB => SUCCESS)", "number", number, "hash", hash)
				snap = s
				break
			} else {
				log.Warn("::: Authority snapshot ::: (loading from DB => FAILED) - So, moving backward to replay voting history", "number", number, "hash", hash, "err", err)
			}
		}
		// If we're at the genesis, snapshot the initial state. Alternatively if we're
		// at a checkpoint block without a parent (light client CHT), or we have piled
		// up more headers than allowed to be reorged (chain reinit from a freezer),
		// consider the checkpoint trusted and snapshot it.
		if number == 0 || (number%c.cliqueConfig.Epoch == 0 && (len(headers) > params.FullImmutabilityThreshold || chain.GetHeaderByNumber(number-1) == nil)) {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()
				if err := c.VerifyHeader(chain, checkpoint, false); err != nil {
					log.Warn("::: Authority snapshot ::: (Verifying checkpoint snapshot => FAILED)", "err", err)
					return nil, err
				}
				signers := make([]common.Address, (len(checkpoint.Extra)-extraVanity-4-8-extraSeal)/common.AddressLength)
				for i := 0; i < len(signers); i++ {
					copy(signers[i][:], checkpoint.Extra[extraVanity+8+4+(i*common.AddressLength):])
				}
				snap = newSnapshot(c.cliqueConfig, c.signatures, number, hash, signers)
				if err := snap.store(c.db); err != nil {
					log.Warn("::: Authority snapshot ::: (Storing checkpoint snapshot to disk => FAILED)", "err", err)
					return nil, err
				}
				log.Info("::: Authority snapshot ::: (Stored checkpoint snapshot to disk)", "number", number, "hash", hash)
				break
			}
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers)
	if err != nil {
		log.Warn("::: Authority snapshot ::: (Applying pending headers on top of recent snapshot => FAILED)", "number", headers[0].Number, "hash", headers[0].Hash(), "pending headers", headers, "err", err)
		return nil, err
	}
	c.recents.Add(snap.Hash, snap)
	log.Trace("::: Authority snapshot ::: (Applying pending headers on top of recent snapshot => SUCCESS)", "number", snap.Number, "hash", snap.Hash, "pending headers", len(headers), "total snapshots", c.recents.Len())

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%c.cliqueConfig.SnapshotInterval == 0 && len(headers) > 0 {
		if err = snap.store(c.db); err != nil {
			log.Warn("::: Authority snapshot ::: (Storing final snapshot to disk => FAILED)", "number", snap.Number, "hash", snap.Hash, "err", err)
			return nil, err
		}
		log.Trace("::: Authority snapshot ::: (Storing final snapshot to disk => SUCCESS)", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *Clique) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (c *Clique) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return c.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (c *Clique) verifySeal(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, c.signatures)
	if err != nil {
		return err
	}
	if _, ok := snap.Signers[signer]; !ok {
		return errUnauthorizedSigner
	}
	/*
		for seen, recent := range snap.Recents {
			if recent == signer {
				// Signer is among recents, only fail if the current block doesn't shift it out
				if limit := uint64(len(snap.Signers)/2 + 1); seen > number-limit {
					return errRecentlySigned
				}
			}
		}
	*/
	// Ensure that the difficulty corresponds to the turn-ness of the signer
	if !c.fakeDiff {
		inturn, _ := snap.inturn(header.Number.Uint64(), signer)
		if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
			return errWrongDifficulty
		}
		if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
			return errWrongDifficulty
		}
	}
	//log.Info("@@@ verifySeal()", "in-turn=", turn, "number=", number, "signer=", signer, "time=", time.Unix(header.Time.Int64(), 0).Format(time.Stamp))
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *Clique) Prepare(consensusConfig *common.ConsensusConfig, chain consensus.ChainHeaderReader, header *types.Header) error {
	// If the block isn't a checkpoint, cast a random vote (good enough for now)
	//header.Coinbase = common.Address{}
	header.Nonce = types.BlockNonce{} // In this version, this is not used.

	var castVoteAddress *common.Address = nil
	var castVoteValue *[]byte = nil

	number := header.Number.Uint64()
	// Assemble the voting snapshot to check which votes make sense
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if number%c.cliqueConfig.Epoch != 0 {
		c.lock.RLock()

		// Gather all the proposals that make sense voting on
		addresses := make([]common.Address, 0, len(c.proposals))
		for address, authorize := range c.proposals {
			if snap.validVote(address, authorize) {
				addresses = append(addresses, address)
			}
		}
		// If there's pending proposals, cast a vote on them
		if len(addresses) > 0 {
			castVoteAddress = &(addresses[rand.Intn(len(addresses))])
			tmp := make([]byte, 1)
			castVoteValue = &tmp

			if c.proposals[*castVoteAddress] {
				copy((*castVoteValue)[:], nonceAuthVote) // 0xff
			} else {
				copy((*castVoteValue)[:], nonceDropVote) // 0x00
			}
			log.Info("::: Prepare cast vote proposal :::", "castVoteAddress", *castVoteAddress, "castVoteValue", common.Bytes2Hex(*castVoteValue))
		}
		c.lock.RUnlock()
	}
	// Set the correct difficulty
	header.Difficulty = calcDifficulty(snap, c.signer, number)

	// Ensure the extra data has all its components
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	// append time placeholder which will be replaced with time when sealing is completed.
	sealTimestampDataBytes := make([]byte, 8)
	header.Extra = append(header.Extra, sealTimestampDataBytes[:]...)

	// insert additional protocol data if present
	protoVer := []byte{0x00}
	protoType := []byte{0x00} // 0x00: default (No additional protocol data is present)
	protoLen := make([]byte, 2)
	protoData := make([]byte, 0) // variable length

	if number%c.cliqueConfig.Epoch == 0 {
		protoType[0] = 0x01 // List current singers (only in Epoch block)

		signers := snap.signers()
		binary.BigEndian.PutUint16(protoLen, uint16(len(signers)*common.AddressLength))

		for _, signer := range signers {
			protoData = append(protoData, signer[:]...)
		}
	} else if castVoteAddress != nil {
		protoType[0] = 0x02 // Cast vote
		binary.BigEndian.PutUint16(protoLen, uint16(common.AddressLength+1))
		protoData = append(protoData, (*castVoteAddress)[:]...)
		protoData = append(protoData, (*castVoteValue)[:]...)
		log.Info("::: Cast vote binary :::", "protoData", common.Bytes2Hex(protoData))
	}
	header.Extra = append(header.Extra, protoVer[:]...)
	header.Extra = append(header.Extra, protoType[:]...)
	header.Extra = append(header.Extra, protoLen[:]...)
	header.Extra = append(header.Extra, protoData[:]...)
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	var blockPeriod uint64
	if consensusConfig != nil && consensusConfig.BlockPeriod != nil {
		blockPeriod = *consensusConfig.BlockPeriod
	} else {
		blockPeriod = c.cliqueConfig.Period
	}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	nowUnix := time.Now().Unix()
	header.Time = parent.Time + blockPeriod

	//var scheduledTo string
	if header.Time <= uint64(nowUnix) {
		header.Time = uint64(nowUnix)
		//scheduledTo = "now"
	} else {
		//scheduledTo = "future"
	}
	//log.Info("new block time is scheduled to " + scheduledTo, "parent.Time", parent.Time, "period", blockPeriod, "nowUnix", nowUnix)

	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (c *Clique) Finalize(consensusConfig *common.ConsensusConfig, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// Block rewards in PoA, so the state remains as is and uncles are dropped
	if c.cliqueConfig.BlockReward && header.Coinbase != (common.Address{}) {
		luniversePoABlockReward := consensusConfig.Reward

		snap, err := c.snapshot(chain, header.Number.Uint64()-1, header.ParentHash, nil)
		if err != nil {
			panic(fmt.Sprintf("Finalize() - In Block-Reward processing (0), Failed to get Clique snapshot DB with error: %s", err.Error()))
		}
		N := len(snap.signers())
		if N < 25 {
			// Block reward adjustment using N/25 where N is the total number of signers.
			// Especially, if N is greater than 25, no adjustment is required.
			luniversePoABlockReward = new(big.Int).Div(new(big.Int).Mul(luniversePoABlockReward, big.NewInt((int64)(N*4))), big.NewInt(100))
		}

		log.Trace("Processing block reward", "consensusConfig.Reward", consensusConfig.Reward, "N", N, "amount", luniversePoABlockReward)

		fromAddr := common.HexToAddress(common.VirtualMinerAddress) /* pre-defined address used to send block reward to target contract */
		state.SetBalance(fromAddr, luniversePoABlockReward)         /* first, temporarily deposit total block reward, then distribute it to targets */

		// reward to coinbase
		coinbaseRewardRatio := big.NewInt((int64)(*consensusConfig.CoinbaseRatio))
		coinbaseReward := new(big.Int).Div(new(big.Int).Mul(luniversePoABlockReward, coinbaseRewardRatio), big.NewInt(100))

		if coinbaseReward.Cmp(big.NewInt(0)) > 0 {
			if *consensusConfig.AuthorityGovernanceStage == 0 {
				toAddr := common.HexToAddress(common.PreStakingContractAddress) /* This is block-reward holder contract which is activated only in pre-boarding period */

				ABI := append(common.Hex2Bytes("2fd6085e000000000000000000000000"), header.Coinbase.Bytes()...) // blockReward(addr)
				log.Trace("****** reward to coinbase: ", "ABI", common.Bytes2Hex(ABI), "toAddr", toAddr, "coinbase", common.Bytes2Hex(header.Coinbase.Bytes()))

				// prepare message to execute
				msg := types.NewMessage(chain.Config(), fromAddr, &toAddr, 0, coinbaseReward, 90000000000, big.NewInt(0), big.NewInt(0), big.NewInt(0), ABI, nil, false)
				//log.Trace("*****", "vmAccountRef", vm.AccountRef(msg.From()).Address())

				// execute ABI
				context := core.NewEVMBlockContext(header, c.blockAccessor.GetBlockChain(), nil)
				txContext := core.NewEVMTxContext(msg)
				evm := vm.NewEVM(context, txContext, state, c.chainConfig, vm.Config{NoBaseFee: true})
				_, _, vmerr := evm.Call(vm.AccountRef(msg.From()), vm.AccountRef(*msg.To()).Address(), msg.Data(), msg.Gas(), msg.Value())
				if vmerr != nil {
					// The only possible consensus-error would be if there wasn't
					// sufficient balance to make the transfer happen. The first
					// balance transfer may never fail.
					panic(fmt.Sprintf("Finalize() - In Block-Reward processing (1), VM returned with error: %s", vmerr.Error()))
				}
			} else {
				state.AddBalance(header.Coinbase, coinbaseReward)
			}
		}

		// reward to other parties
		for _, pool := range consensusConfig.RewardPools {
			rewardRatio := big.NewInt((int64)(*pool.Ratio))
			toAddr := common.HexToAddress(*pool.Addr)

			if toAddr != (common.Address{}) {
				reward := new(big.Int).Div(new(big.Int).Mul(luniversePoABlockReward, rewardRatio), big.NewInt(100))
				if reward.Cmp(big.NewInt(0)) > 0 {
					ABI := append(common.Hex2Bytes("2fd6085e000000000000000000000000"), toAddr.Bytes()...)
					log.Trace("****** reward to other participants: ", "ABI", common.Bytes2Hex(ABI), "toAddr", toAddr)

					// prepare message to execute
					msg := types.NewMessage(chain.Config(), fromAddr, &toAddr, 0, reward, 90000000000, big.NewInt(0), big.NewInt(0), big.NewInt(0), ABI, nil, false)

					// execute ABI
					context := core.NewEVMBlockContext(header, c.blockAccessor.GetBlockChain(), nil)
					txContext := core.NewEVMTxContext(msg)
					evm := vm.NewEVM(context, txContext, state, c.chainConfig, vm.Config{NoBaseFee: true})
					_, _, vmerr := evm.Call(vm.AccountRef(msg.From()), vm.AccountRef(*msg.To()).Address(), msg.Data(), msg.Gas(), msg.Value())
					if vmerr != nil {
						// The only possible consensus-error would be if there wasn't
						// sufficient balance to make the transfer happen. The first
						// balance transfer may never fail.
						panic(fmt.Sprintf("Finalize() - In Block-Reward processing (2), VM returned with error: %s", vmerr.Error()))
					}
				}
			}
		}

		state.SetBalance(fromAddr, big.NewInt(0)) /* reset it */
	}
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (c *Clique) FinalizeAndAssemble(consensusConfig *common.ConsensusConfig, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Finalize block
	c.Finalize(consensusConfig, chain, header, state, txs, uncles)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *Clique) Authorize(signer common.Address, signFn SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
	c.signFn = signFn
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *Clique) Seal(consensusConfig *common.ConsensusConfig, chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	var blockPeriod uint64
	if consensusConfig != nil && consensusConfig.BlockPeriod != nil {
		blockPeriod = *consensusConfig.BlockPeriod
	} else {
		blockPeriod = c.cliqueConfig.Period
	}

	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if blockPeriod == 0 && len(block.Transactions()) == 0 {
		return errors.New("sealing paused while waiting for transactions")
	}
	// Don't hold the signer fields for the entire sealing procedure
	c.lock.RLock()
	signer, signFn := c.signer, c.signFn
	c.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if _, authorized := snap.Signers[signer]; !authorized {
		return errUnauthorizedSigner
	}
	/*
		// If we're amongst the recent signers, wait for the next block
		for seen, recent := range snap.Recents {
			if recent == signer {
				// Signer is among recents, only wait if the current block doesn't shift it out
				if limit := uint64(len(snap.Signers)/2 + 1); number < limit || seen > number-limit {
					return errors.New("signed recently, must wait for others")
				}
			}
		}
	*/
	// Sweet, the protocol permits us to sign the block, wait for our time
	now := time.Now()
	delay := time.Unix(int64(header.Time), 0).Sub(now) // nolint: gosimple
	/* `diff` SHOULD BE lie in range `0.nnn ~ 1.nnn` seconds */
	//secondsFractionSanityCheck := fmt.Sprintf("%.6f", delay.Seconds())
	//if diff < 0 || diff >= time.Duration( + 1000000000)  {
	//	secondsFractionSanityCheck = fmt.Sprintf("Abnormal %.6f", diff.Seconds())
	//}

	//turn := "Y"
	if isInTurn, offsetDistance := snap.inturn(number, signer); !isInTurn /*header.Difficulty.Cmp(diffNoTurn) == 0*/ {
		//turn = "N"

		// It's not our turn explicitly to sign, delay it a bit
		//wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
		outOfTurnWait := time.Duration(9000000000 + int64(float64(2000000000)*math.Log(float64(offsetDistance)))) // + time.Duration(rand.Int63n(int64(wiggle)))

		delay += outOfTurnWait

		//log.Info("✊ Out-of-turn signing 【 " +secondsFractionSanityCheck+ " 】", "Number", header.Number.Uint64(), "Time", header.Time)
	} else {
		//if diff < 0 {
		//	//log.Info("@@@ Seal(): Due to late arrival of parent block? (i.e., parent was out-of-turn case) or Excessive tx processing is going on? Will send block immediately! { diff < 0 }",
		//	//	"header.time", header.Time.Int64(), "now", now)
		//
		//	//log.Info(fmt.Sprintf("@@@ Time-Check: turn=%s, header.Time=%s, curTime=%s, time-diff=%s, txs=%d",
		//	//		turn,
		//	//		strconv.FormatInt(header.Time.Int64(), 10),
		//	//		strconv.FormatInt(time.Now().Unix(), 10),
		//	//		common.PrettyDuration(diff),
		//	//		block.Transactions().Len()))
		//
		//	//diff = 1000000000 * 1 // assign fixed 0.5 sec to suppress immediate block propagation. considering sync processing of blocks waiting to be consumed. (This workaround is only for slow node)
		//
		//	log.Info("✋ In-turn signing 【 ♥♥ Good ♥♥ 】", "diff", common.PrettyDuration(diff), "header.Time", header.Time)
		//} else {
		//	log.Info("✋ In-turn signing 【 Abnormal time sync? 】", "diff", common.PrettyDuration(diff), "header.Time", header.Time)
		//}

		//log.Info("✋ In-turn signing 【 " +secondsFractionSanityCheck+ " 】", "Number", header.Number.Uint64(), "Time", header.Time)
	}

	// Sign all the things!
	//sighash, err := signFn(accounts.Account{Address: signer}, accounts.MimetypeClique, CliqueRLP(header))
	//if err != nil {
	//	return err
	//}
	//copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

	// Wait until sealing is terminated or delay timeout.
	//log.Info("⌛ ["+secondsFractionSanityCheck+"] Waiting for slot to sign and propagate", "Wait", common.PrettyDuration(delay))
	//log.Info("⌛ Waiting", "Wait", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			//log.Info("⚡⚡⚡ halt! ⚡⚡⚡")
			return
		case <-time.After(delay):
		}

		blockSealed, err := c.sealBlockWithTimestamp(now, delay, header, signer, signFn, block)
		if err != nil {
			log.Error("sealBlockWithTimestamp() failed!", "error", err)
		}
		select {
		case results <- blockSealed:
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

func (c *Clique) sealBlockWithTimestamp(now time.Time, delay time.Duration, header *types.Header, signer common.Address, signFn SignerFn, block *types.Block) (*types.Block, error) {
	afterNow := time.Now()

	// sanity check (reorg defense logic considering event bug)
	var expected = now
	if delay > 0 {
		expected = now.Add(delay)
	}
	diffSeconds := afterNow.Sub(expected).Seconds()
	if math.Abs(diffSeconds) > 0.5 {
		log.Error("Oops! Invalid time context found after delay! Dropping this block!", "number", header.Number.Uint64())
		return nil, errInvalidTimeContext
	}

	// set seal timestamp
	sealTimestamp := afterNow.UnixNano() / 1e6
	binary.BigEndian.PutUint64(header.Extra[extraVanity:extraVanity+8], uint64(sealTimestamp))

	// Sign all the things!
	sighash, err := signFn(accounts.Account{Address: signer}, accounts.MimetypeClique, CliqueRLP(header))
	if err != nil {
		return nil, err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

	//log.Info(
	//	fmt.Sprintf("✎ ✉ 【%s】 Sealed txs=%d, header.number=%s, header.Time=%s, curTime=%s, time-to-wait=%s",
	//		turn,
	//		block.Transactions().Len(),
	//		strconv.FormatInt(header.Number.Int64(), 10),
	//		time.Unix(header.Time.Int64(), 0).Format(time.StampMicro),
	//		//strconv.FormatInt(header.Time.Int64(), 10),
	//		time.Now().Format(time.StampMicro),
	//		//strconv.FormatInt(time.Now().Unix(), 10),
	//		common.PrettyDuration(finalWait)))

	//log.Info(fmt.Sprintf("✎ ✉ 【%s】 Seal completed", turn), "txs", block.Transactions().Len(), "Number", header.Number.Int64(), "Hash", header.Hash(), "Time", time.Unix(header.Time.Int64(), 0).Format(time.Stamp), "curTime", time.Now().Format(time.StampMicro))

	return block.WithSeal(header), nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have:
// * DIFF_NOTURN(2) if BLOCK_NUMBER % SIGNER_COUNT != SIGNER_INDEX
// * DIFF_INTURN(1) if BLOCK_NUMBER % SIGNER_COUNT == SIGNER_INDEX
func (c *Clique) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := c.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	return calcDifficulty(snap, c.signer, parent.Number.Uint64()+1)
}

func calcDifficulty(snap *Snapshot, signer common.Address, blockNumber uint64) *big.Int {
	if inTurn, _ := snap.inturn( /*snap.Number+1*/ blockNumber, signer); inTurn {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func (c *Clique) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

// Close implements consensus.Engine. It's a noop for clique as there are no background threads.
func (c *Clique) Close() error {
	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, true)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

// SealHashWithoutTimestamp returns the hash of a block prior to it being sealed. (Be careful! Currently, it is intended to be used only for pendingTasks mapping between taskLoop and resultLoop in worker)
func SealHashWithoutTimestamp(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, false)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

// CliqueRLP returns the rlp bytes which needs to be signed for the proof-of-authority
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func CliqueRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header, true)
	return b.Bytes()
}

func encodeSigHeader(w io.Writer, header *types.Header, includeTimestamp bool) {
	// set timestamp to zero to preserve sighash
	extra := make([]byte, len(header.Extra)-crypto.SignatureLength)
	copy(extra, header.Extra[:len(header.Extra)-crypto.SignatureLength])
	if !includeTimestamp {
		binary.BigEndian.PutUint64(extra[extraVanity:extraVanity+8], uint64(0))
	}

	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		extra, //header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *Clique) APIs(chain consensus.ChainHeaderReader, ethapis []rpc.API) []rpc.API {
	return []rpc.API{{
		Namespace: "clique",
		Version:   "1.0",
		Service:   &API{chain: chain, clique: c},
		Public:    false,
	}}
}

//func (c *Clique) SetChainApi(chainApi *ethapi.PublicBlockChainAPI) {
//	c.chainApi = chainApi
//}

// retrieve consensusConfig from system contract
func (c *Clique) GetConsensusConfigurations(header *types.Header, parents []*types.Header) (*common.ConsensusConfig, error) {
	if !c.cliqueConfig.HasConsensusConfiguration() {
		return nil, nil
	}

	// Create a new stateDB using the parent block and report an error if it fails.
	blockChain := c.blockAccessor.GetBlockChain()
	block := blockChain.GetBlock(header.ParentHash, header.Number.Uint64()-1)
	if block == nil {
		return nil, consensus.ErrPrunedAncestor
	}

	parentState, err := blockChain.StateAt(block.Root())
	if err != nil {
		return nil, err
	}

	var parent *types.Header
	if parents != nil && len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = blockChain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	}
	return core.RetrieveConsensusConfigurations(blockChain, parent, parentState, c.chainConfig), nil
}

func (c *Clique) SetBlockPeriod(blockPeriod uint64) {
	c.dynamicBlockPeriod = blockPeriod

	//TODO: leave change history to DB
}

func (c *Clique) SetTargetGasLimit(targetGasLimit *big.Int) {
	c.paramsLock.Lock()
	defer c.paramsLock.Unlock()

	params.TargetGasLimit = targetGasLimit.Uint64()
}

func (c *Clique) SetTargetGasLimitCalculation(targetGasLimitCalculation bool) {
	c.paramsLock.Lock()
	defer c.paramsLock.Unlock()

	params.TargetGasLimitCalculation = targetGasLimitCalculation
}

func (c *Clique) SetTxGasLimit(txGasLimit *big.Int) {
	c.paramsLock.Lock()
	defer c.paramsLock.Unlock()

	params.TxGasLimit = txGasLimit.Uint64()
}

func (c *Clique) SetGasPrice(gasPrice *big.Int) {
	c.txPoolAccessor.SetGasPrice(gasPrice)
}

func (c *Clique) ExtractSealTimeUint64(header *types.Header) uint64 {
	sealTimestampDataBytes := header.Extra[extraVanity : extraVanity+8]
	return binary.BigEndian.Uint64(sealTimestampDataBytes)
}
