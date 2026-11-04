# Security Policy

## Supported Versions

Luniverse-PoA is a fork of [go-ethereum](https://github.com/ethereum/go-ethereum) v1.10.15.
Security fixes are applied to the `master` branch of this repository.

## Audit reports

The following audit reports were published by the upstream go-ethereum project for the
code base Luniverse-PoA is derived from. They are kept in the `docs/audits` folder.
They do not cover Luniverse-PoA specific changes such as the PoA consensus.

| Scope | Date | Report Link |
| ------- | ------- | ----------- |
| `geth` | 20170425 | [pdf](docs/audits/2017-04-25_Geth-audit_Truesec.pdf) |
| `clef` | 20180914 | [pdf](docs/audits/2018-09-14_Clef-audit_NCC.pdf) |
| `Discv5` | 20191015 | [pdf](docs/audits/2019-10-15_Discv5_audit_LeastAuthority.pdf) |
| `Discv5` | 20200124 | [pdf](docs/audits/2020-01-24_DiscV5_audit_Cure53.pdf) |

## Reporting a Vulnerability

**Please do not file a public ticket** mentioning the vulnerability.

Report it by email to [support@lambda256.io](mailto:support@lambda256.io).

If the vulnerability also affects upstream go-ethereum, please report it to the
go-ethereum team as well: see the
[go-ethereum security policy](https://github.com/ethereum/go-ethereum/security/policy).
