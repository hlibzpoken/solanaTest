import { PublicKey } from '@solana/web3.js';
import { fromBech32 } from '@cosmjs/encoding';
import { keccak_256 } from '@noble/hashes/sha3';
import { bech32m } from 'bech32';
export class SealevelInstructionWrapper {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
    }
}
export class SealevelTransferRemoteInstruction {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
        this.recipient_pubkey = new PublicKey(this.recipient);
    }
}
export const SealevelTransferRemoteSchema = new Map([
    [
        SealevelInstructionWrapper,
        {
            kind: 'struct',
            fields: [
                ['instruction', 'u8'],
                ['data', SealevelTransferRemoteInstruction],
            ],
        },
    ],
    [
        SealevelTransferRemoteInstruction,
        {
            kind: 'struct',
            fields: [
                ['destination_domain', 'u32'],
                ['recipient', [32]],
                ['amount_or_id', 'u256'],
            ],
        },
    ],
]);
export const SealevelInterchainGasPaymasterType = {
    Igp: 0,
    OverheadIgp: 1,
};
// Config schema, e.g. for use in token data
export class SealevelInterchainGasPaymasterConfig {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
        this.program_id_pubkey = new PublicKey(this.program_id);
        this.igp_account_pub_key = this.igp_account
            ? new PublicKey(this.igp_account)
            : undefined;
    }
}
export const SealevelInterchainGasPaymasterConfigSchema = {
    kind: 'struct',
    fields: [
        ['program_id', [32]],
        ['type', 'u8'],
        ['igp_account', [32]],
    ],
};
/**
 * Gas Oracle Borsh Schema
 */
// Should match https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/rust/sealevel/programs/hyperlane-sealevel-igp/src/accounts.rs#L234
export class SealevelRemoteGasData {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
    }
}
export const SealevelRemoteGasDataSchema = {
    kind: 'struct',
    fields: [
        ['token_exchange_rate', 'u128'],
        ['gas_price', 'u128'],
        ['token_decimals', 'u8'],
    ],
};
// Should match https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/rust/sealevel/programs/hyperlane-sealevel-igp/src/accounts.rs#L45
export var SealevelGasOracleType;
(function (SealevelGasOracleType) {
    SealevelGasOracleType[SealevelGasOracleType["RemoteGasData"] = 0] = "RemoteGasData";
})(SealevelGasOracleType || (SealevelGasOracleType = {}));
export class SealevelGasOracle {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
    }
}
export const SealevelGasOracleSchema = {
    kind: 'struct',
    fields: [
        ['type', 'u8'],
        ['data', SealevelRemoteGasData],
    ],
};
export class SealevelAccountDataWrapper {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
    }
}
export function getSealevelAccountDataSchema(DataClass, discriminator) {
    return {
        kind: 'struct',
        fields: [
            ['initialized', 'u8'],
            ...(discriminator ? [['discriminator', discriminator]] : []),
            ['data', DataClass],
        ],
    };
}
// The format of simulation return data from the Sealevel programs.
// A trailing non-zero byte was added due to a bug in Sealevel RPCs that would
// truncate responses with trailing zero bytes.
export class SealevelSimulationReturnData {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
    }
}
export function getSealevelSimulationReturnDataSchema(DataClass) {
    return {
        kind: 'struct',
        fields: [
            ['data', DataClass],
            ['trailing_byte', 'u8'],
        ],
    };
}
export class SealevelHyperlaneTokenData {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
        this.mailbox_pubkey = new PublicKey(this.mailbox);
        this.mailbox_pubkey = new PublicKey(this.mailbox_process_authority);
        this.owner_pub_key = this.owner ? new PublicKey(this.owner) : undefined;
        this.interchain_security_module_pubkey = this.interchain_security_module
            ? new PublicKey(this.interchain_security_module)
            : undefined;
        this.interchain_gas_paymaster_pubkey = this.interchain_gas_paymaster
            ?.program_id
            ? new PublicKey(this.interchain_gas_paymaster.program_id)
            : undefined;
        this.interchain_gas_paymaster_account_pubkey = this.interchain_gas_paymaster
            ?.igp_account
            ? new PublicKey(this.interchain_gas_paymaster.igp_account)
            : undefined;
        this.remote_router_pubkeys = new Map();
        if (this.remote_routers) {
            for (const [k, v] of this.remote_routers.entries()) {
                this.remote_router_pubkeys.set(k, new PublicKey(v));
            }
        }
    }
}
export const SealevelHyperlaneTokenDataSchema = new Map([
    [
        SealevelAccountDataWrapper,
        getSealevelAccountDataSchema(SealevelHyperlaneTokenData),
    ],
    [
        SealevelHyperlaneTokenData,
        {
            kind: 'struct',
            fields: [
                ['bump', 'u8'],
                ['mailbox', [32]],
                ['mailbox_process_authority', [32]],
                ['dispatch_authority_bump', 'u8'],
                ['decimals', 'u8'],
                ['remote_decimals', 'u8'],
                ['owner', { kind: 'option', type: [32] }],
                ['interchain_security_module', { kind: 'option', type: [32] }],
                [
                    'interchain_gas_paymaster',
                    {
                        kind: 'option',
                        type: SealevelInterchainGasPaymasterConfig,
                    },
                ],
                ['destination_gas', { kind: 'map', key: 'u32', value: 'u64' }],
                ['remote_routers', { kind: 'map', key: 'u32', value: [32] }],
            ],
        },
    ],
    [
        SealevelInterchainGasPaymasterConfig,
        SealevelInterchainGasPaymasterConfigSchema,
    ],
]);
/**
 * Transfer Remote Borsh Schema
 */
// Should match Instruction in https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/rust/sealevel/libraries/hyperlane-sealevel-token/src/instruction.rs
export var SealevelHypTokenInstruction;
(function (SealevelHypTokenInstruction) {
    SealevelHypTokenInstruction[SealevelHypTokenInstruction["Init"] = 0] = "Init";
    SealevelHypTokenInstruction[SealevelHypTokenInstruction["TransferRemote"] = 1] = "TransferRemote";
    SealevelHypTokenInstruction[SealevelHypTokenInstruction["EnrollRemoteRouter"] = 2] = "EnrollRemoteRouter";
    SealevelHypTokenInstruction[SealevelHypTokenInstruction["EnrollRemoteRouters"] = 3] = "EnrollRemoteRouters";
    SealevelHypTokenInstruction[SealevelHypTokenInstruction["SetInterchainSecurityModule"] = 4] = "SetInterchainSecurityModule";
    SealevelHypTokenInstruction[SealevelHypTokenInstruction["TransferOwnership"] = 5] = "TransferOwnership";
})(SealevelHypTokenInstruction || (SealevelHypTokenInstruction = {}));
/**
 * IGP Program Data Borsh Schema
 */
// Should match https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/rust/sealevel/programs/hyperlane-sealevel-igp/src/accounts.rs#L91
export class SealevelOverheadIgpData {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
        this.owner_pub_key = this.owner ? new PublicKey(this.owner) : undefined;
        this.inner_pub_key = new PublicKey(this.inner);
    }
}
export const SealevelOverheadIgpDataSchema = new Map([
    [
        SealevelAccountDataWrapper,
        getSealevelAccountDataSchema(SealevelOverheadIgpData, [8]),
    ],
    [
        SealevelOverheadIgpData,
        {
            kind: 'struct',
            fields: [
                ['bump', 'u8'],
                ['salt', [32]],
                ['owner', { kind: 'option', type: [32] }],
                ['inner', [32]],
                ['gas_overheads', { kind: 'map', key: 'u32', value: 'u64' }],
            ],
        },
    ],
]);
// Should match https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/rust/sealevel/programs/hyperlane-sealevel-igp/src/accounts.rs#L159
export class SealevelIgpData {
    constructor(fields) {
        Object.assign(this, fields);
        this.owner_pub_key = this.owner ? new PublicKey(this.owner) : undefined;
        this.beneficiary_pub_key = new PublicKey(this.beneficiary);
    }
}
export const SealevelIgpDataSchema = new Map([
    [
        SealevelAccountDataWrapper,
        getSealevelAccountDataSchema(SealevelIgpData, [8]),
    ],
    [
        SealevelIgpData,
        {
            kind: 'struct',
            fields: [
                ['bump_seed', 'u8'],
                ['salt', [32]],
                ['owner', { kind: 'option', type: [32] }],
                ['beneficiary', [32]],
                ['gas_oracles', { kind: 'map', key: 'u32', value: SealevelGasOracle }],
            ],
        },
    ],
    [SealevelGasOracle, SealevelGasOracleSchema],
    [SealevelRemoteGasData, SealevelRemoteGasDataSchema],
]);
/**
 * IGP instruction Borsh Schema
 */
// Should match Instruction in https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/8f8853bcd7105a6dd7af3a45c413b137ded6e888/rust/sealevel/programs/hyperlane-sealevel-igp/src/instruction.rs#L19-L42
export var SealevelIgpInstruction;
(function (SealevelIgpInstruction) {
    SealevelIgpInstruction[SealevelIgpInstruction["Init"] = 0] = "Init";
    SealevelIgpInstruction[SealevelIgpInstruction["InitIgp"] = 1] = "InitIgp";
    SealevelIgpInstruction[SealevelIgpInstruction["InitOverheadIgp"] = 2] = "InitOverheadIgp";
    SealevelIgpInstruction[SealevelIgpInstruction["PayForGas"] = 3] = "PayForGas";
    SealevelIgpInstruction[SealevelIgpInstruction["QuoteGasPayment"] = 4] = "QuoteGasPayment";
    SealevelIgpInstruction[SealevelIgpInstruction["TransferIgpOwnership"] = 5] = "TransferIgpOwnership";
    SealevelIgpInstruction[SealevelIgpInstruction["TransferOverheadIgpOwnership"] = 6] = "TransferOverheadIgpOwnership";
    SealevelIgpInstruction[SealevelIgpInstruction["SetIgpBeneficiary"] = 7] = "SetIgpBeneficiary";
    SealevelIgpInstruction[SealevelIgpInstruction["SetDestinationGasOverheads"] = 8] = "SetDestinationGasOverheads";
    SealevelIgpInstruction[SealevelIgpInstruction["SetGasOracleConfigs"] = 9] = "SetGasOracleConfigs";
    SealevelIgpInstruction[SealevelIgpInstruction["Claim"] = 10] = "Claim";
})(SealevelIgpInstruction || (SealevelIgpInstruction = {}));
export class SealevelIgpQuoteGasPaymentInstruction {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
    }
}
export const SealevelIgpQuoteGasPaymentSchema = new Map([
    [
        SealevelInstructionWrapper,
        {
            kind: 'struct',
            fields: [
                ['instruction', 'u8'],
                ['data', SealevelIgpQuoteGasPaymentInstruction],
            ],
        },
    ],
    [
        SealevelIgpQuoteGasPaymentInstruction,
        {
            kind: 'struct',
            fields: [
                ['destination_domain', 'u32'],
                ['gas_amount', 'u64'],
            ],
        },
    ],
]);
export class SealevelIgpQuoteGasPaymentResponse {
    constructor(fields) {
        this.fields = fields;
        Object.assign(this, fields);
    }
}
export const SealevelIgpQuoteGasPaymentResponseSchema = new Map([
    [
        SealevelAccountDataWrapper,
        getSealevelSimulationReturnDataSchema(SealevelIgpQuoteGasPaymentResponse),
    ],
    [
        SealevelIgpQuoteGasPaymentResponse,
        {
            kind: 'struct',
            fields: [['payment_quote', 'u64']],
        },
    ],
]);
/**
 * Gas Oracle Configuration Schemas
 */
export class SealevelGasOracleConfig {
    constructor(domain, gasOracle) {
        this.domain = domain;
        this.gas_oracle = gasOracle;
    }
}
export const SealevelGasOracleConfigSchema = {
    kind: 'struct',
    fields: [
        ['domain', 'u32'],
        ['gas_oracle', { kind: 'option', type: SealevelGasOracle }],
    ],
};
export class SealevelGasOverheadConfig {
    constructor(destination_domain, gas_overhead) {
        this.destination_domain = destination_domain;
        this.gas_overhead = gas_overhead;
    }
}
export const SealevelGasOverheadConfigSchema = {
    kind: 'struct',
    fields: [
        ['destination_domain', 'u32'],
        ['gas_overhead', { kind: 'option', type: 'u64' }],
    ],
};
/**
 * Instruction Schemas
 */
export class SealevelSetGasOracleConfigsInstruction {
    constructor(configs) {
        this.configs = configs;
    }
}
export const SealevelSetGasOracleConfigsInstructionSchema = new Map([
    [
        SealevelInstructionWrapper,
        {
            kind: 'struct',
            fields: [
                ['instruction', 'u8'],
                ['data', SealevelSetGasOracleConfigsInstruction],
            ],
        },
    ],
    [
        SealevelSetGasOracleConfigsInstruction,
        {
            kind: 'struct',
            fields: [['configs', [SealevelGasOracleConfig]]],
        },
    ],
    [SealevelGasOracleConfig, SealevelGasOracleConfigSchema],
    [SealevelGasOracle, SealevelGasOracleSchema],
    [SealevelRemoteGasData, SealevelRemoteGasDataSchema],
]);
export class SealevelSetDestinationGasOverheadsInstruction {
    constructor(configs) {
        this.configs = configs;
    }
}
export const SealevelSetDestinationGasOverheadsInstructionSchema = new Map([
    [
        SealevelInstructionWrapper,
        {
            kind: 'struct',
            fields: [
                ['instruction', 'u8'],
                ['data', SealevelSetDestinationGasOverheadsInstruction],
            ],
        },
    ],
    [
        SealevelSetDestinationGasOverheadsInstruction,
        {
            kind: 'struct',
            fields: [['configs', [SealevelGasOverheadConfig]]],
        },
    ],
    [SealevelGasOverheadConfig, SealevelGasOverheadConfigSchema],
]);
export function isNullish(val) {
    return val === null || val === undefined;
}
export function isNumeric(value) {
    return typeof value === 'number' || /^\d+$/.test(value);
}
export function padBytesToLength(bytes, length) {
    if (bytes.length > length) {
        throw new Error(`bytes must be ${length} bytes or less`);
    }
    return Buffer.concat([Buffer.alloc(length - bytes.length), bytes]);
}
export var ProtocolType;
(function (ProtocolType) {
    ProtocolType["Ethereum"] = "ethereum";
    ProtocolType["Sealevel"] = "sealevel";
    ProtocolType["Cosmos"] = "cosmos";
    ProtocolType["CosmosNative"] = "cosmosnative";
    ProtocolType["Starknet"] = "starknet";
    ProtocolType["Radix"] = "radix";
})(ProtocolType || (ProtocolType = {}));
const EVM_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;
const SEALEVEL_ADDRESS_REGEX = /^[a-zA-Z0-9]{36,44}$/;
const COSMOS_NATIVE_ADDRESS_REGEX = /^(0x)?[0-9a-fA-F]{64}$/;
const STARKNET_ADDRESS_REGEX = /^(0x)?[0-9a-fA-F]{64}$/;
const RADIX_ADDRESS_REGEX = /^(account|component)_(rdx|sim|tdx_[\d]_)[a-z0-9]{55}$/;
const HEX_BYTES32_REGEX = /^0x[a-fA-F0-9]{64}$/;
// https://github.com/cosmos/cosmos-sdk/blob/84c33215658131d87daf3c629e909e12ed9370fa/types/coin.go#L601C17-L601C44
const COSMOS_DENOM_PATTERN = `[a-zA-Z][a-zA-Z0-9]{2,127}`;
// https://en.bitcoin.it/wiki/BIP_0173
const BECH32_ADDRESS_PATTERN = `[a-zA-Z]{1,83}1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,58}`;
const COSMOS_ADDRESS_REGEX = new RegExp(`^${BECH32_ADDRESS_PATTERN}$`);
const IBC_DENOM_REGEX = new RegExp(`^ibc/([A-Fa-f0-9]{64})$`);
const COSMOS_FACTORY_TOKEN_REGEX = new RegExp(`^factory/(${BECH32_ADDRESS_PATTERN})/${COSMOS_DENOM_PATTERN}$`);
const EVM_TX_HASH_REGEX = /^0x([A-Fa-f0-9]{64})$/;
const SEALEVEL_TX_HASH_REGEX = /^[a-zA-Z1-9]{88}$/;
const COSMOS_TX_HASH_REGEX = /^(0x)?[A-Fa-f0-9]{64}$/;
const STARKNET_TX_HASH_REGEX = /^(0x)?[0-9a-fA-F]{64}$/;
const RADIX_TX_HASH_REGEX = /^txid_(rdx|sim|tdx_[\d]_)[a-z0-9]{59}$/;
const EVM_ZEROISH_ADDRESS_REGEX = /^(0x)?0*$/;
const SEALEVEL_ZEROISH_ADDRESS_REGEX = /^1+$/;
const COSMOS_ZEROISH_ADDRESS_REGEX = /^[a-z]{1,10}?1[0]+$/;
const COSMOS_NATIVE_ZEROISH_ADDRESS_REGEX = /^(0x)?0*$/;
const STARKNET_ZEROISH_ADDRESS_REGEX = /^(0x)?0*$/;
const RADIX_ZEROISH_ADDRESS_REGEX = /^0*$/;
export function isAddressEvm(address) {
    return EVM_ADDRESS_REGEX.test(address);
}
export function isAddressCosmos(address) {
    return (COSMOS_ADDRESS_REGEX.test(address) ||
        IBC_DENOM_REGEX.test(address) ||
        COSMOS_FACTORY_TOKEN_REGEX.test(address));
}
export function isAddressCosmosNative(address) {
    return COSMOS_NATIVE_ADDRESS_REGEX.test(address);
}
export function isCosmosIbcDenomAddress(address) {
    return IBC_DENOM_REGEX.test(address);
}
export function isAddressStarknet(address) {
    return STARKNET_ADDRESS_REGEX.test(address);
}
export function isAddressRadix(address) {
    return RADIX_ADDRESS_REGEX.test(address);
}
export function isAddressSealevel(address) {
    return SEALEVEL_ADDRESS_REGEX.test(address);
}
function getAddressProtocolType(address) {
    if (!address)
        return undefined;
    if (isAddressEvm(address)) {
        return ProtocolType.Ethereum;
    }
    else if (isAddressCosmos(address)) {
        return ProtocolType.Cosmos;
    }
    else if (isAddressCosmosNative(address)) {
        return ProtocolType.CosmosNative;
    }
    else if (isAddressSealevel(address)) {
        return ProtocolType.Sealevel;
    }
    else if (isAddressStarknet(address)) {
        return ProtocolType.Starknet;
    }
    else if (isAddressRadix(address)) {
        return ProtocolType.Radix;
    }
    else {
        return undefined;
    }
}
function routeAddressUtil(fns, param, fallback, protocol) {
    protocol || (protocol = getAddressProtocolType(param));
    if (protocol && fns[protocol])
        return fns[protocol](param);
    else if (!isNullish(fallback))
        return fallback;
    else
        throw new Error(`Unsupported protocol ${protocol}`);
}
export function addressToBytes32Evm(address) {
    // Normalize
    let addr = address.toLowerCase().replace(/^0x/, '');
    // Strip leading zeros just like hexStripZeros
    addr = addr.replace(/^0+/, '');
    if (addr.length === 0)
        addr = '0';
    // Pad left with zeros up to 32 bytes (64 hex chars)
    const padded = addr.padStart(64, '0');
    return '0x' + padded;
}
// For EVM addresses only, kept for backwards compatibility and convenience
export function bytes32ToAddress(bytes32) {
    let addr = bytes32.slice(-40);
    addr = addr.toLowerCase();
    // Compute checksum per EIP-55
    const hash = Buffer.from(keccak_256(Buffer.from(addr, 'utf8'))).toString('hex');
    let checksummed = '0x';
    for (let i = 0; i < addr.length; i++) {
        checksummed += parseInt(hash[i], 16) >= 8 ? addr[i].toUpperCase() : addr[i];
    }
    return checksummed;
}
export function strip0x(hexstr) {
    return hexstr.startsWith('0x') ? hexstr.slice(2) : hexstr;
}
export function addressToBytesEvm(address) {
    const addrBytes32 = addressToBytes32Evm(address);
    return Buffer.from(strip0x(addrBytes32), 'hex');
}
export function addressToBytesSol(address) {
    return new PublicKey(address).toBytes();
}
export function addressToBytesCosmos(address) {
    return fromBech32(address).data;
}
export function addressToBytesCosmosNative(address) {
    return Buffer.from(strip0x(address), 'hex');
}
export function isZeroishAddress(address) {
    return (EVM_ZEROISH_ADDRESS_REGEX.test(address) ||
        SEALEVEL_ZEROISH_ADDRESS_REGEX.test(address) ||
        COSMOS_ZEROISH_ADDRESS_REGEX.test(address) ||
        COSMOS_NATIVE_ZEROISH_ADDRESS_REGEX.test(address) ||
        STARKNET_ZEROISH_ADDRESS_REGEX.test(address) ||
        RADIX_ZEROISH_ADDRESS_REGEX.test(address));
}
export function addressToBytesStarknet(address) {
    return new Uint8Array();
}
export function addressToBytesRadix(address) {
    return new Uint8Array(bech32m.fromWords(bech32m.decode(address).words));
}
export function addressToBytes(address, protocol) {
    const bytes = routeAddressUtil({
        [ProtocolType.Ethereum]: addressToBytesEvm,
        [ProtocolType.Sealevel]: addressToBytesSol,
        [ProtocolType.Cosmos]: addressToBytesCosmos,
        [ProtocolType.CosmosNative]: addressToBytesCosmosNative,
        [ProtocolType.Starknet]: addressToBytesStarknet,
        [ProtocolType.Radix]: addressToBytesRadix,
    }, address, new Uint8Array(), protocol);
    if (!(bytes.length && !bytes.every((b) => b == 0)))
        throw Error('address bytes must not be empty');
    return bytes;
}
