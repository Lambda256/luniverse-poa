package common

import "math/big"

// Virtual sender address used in system contract for `block reward` and `gas delegation`
var VirtualMinerAddress = "0x00000000000000000000000000000000000003e7" // 999

//=============================================================================================
// Addresses of system contracts

//var MultiSigExecutorContractAddress = "0x00000000000000000000000000000000000001f3" // 499
//var InitialAllocationContractAddress = "0x00000000000000000000000000000000000001f4" // 500
var ConsensusContractAddress = "0x00000000000000000000000000000000000001f9"  // 505
var PreStakingContractAddress = "0x00000000000000000000000000000000000001fa" // 506
var StakingContractAddress = "0x00000000000000000000000000000000000001fb"    // 507

//var ContributionPoolContractAddress = "0x00000000000000000000000000000000000001fe" // 510
//var SustainabilityPoolContractAddress = "0x00000000000000000000000000000000000001ff" // 511
//=============================================================================================

// Block rewrad information (This information is retrieved from contract)
type RewardPool struct {
	Addr  *string `json:"addr"`
	Ratio *uint16 `json:"ratio"`
	Name  *string `json:"name"`
}

type ConsensusConfig struct {
	AuthorityGovernanceStage *uint32	`json:"authorityGovernanceStage"`
	BlockPeriod   *uint64	   `json:"blockPeriod"`
	TargetGasLimit *big.Int      `json:"targetGasLimit"`
	GasLimit      *big.Int      `json:"gasLimit"`
	GasPrice      *big.Int      `json:"gasPrice"`

	Reward        *big.Int      `json:"reward"`
	CoinbaseRatio *uint16      `json:"coinbaseRatio"`
	RewardPools   []RewardPool `json:"rewardPools"`
}

var GetConsensusConfig = "7122b0fd" // ABI to invoke LuniverseConsensus.getAllSystemConfig()

