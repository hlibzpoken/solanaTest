import { PublicKey } from '@solana/web3.js';
import { fromBech32, normalizeBech32, toBech32 } from '@cosmjs/encoding';
import { keccak_256 } from '@noble/hashes/sha3';
import { bech32m } from 'bech32';

export type Domain = number;
export type Address = string;
export type Numberish = number | string;


export class SealevelInstructionWrapper<Instr> {
    instruction!: number;
    data!: Instr;
    constructor(public readonly fields: any) {
      Object.assign(this, fields);
    }
  }

export class SealevelTransferRemoteInstruction {
    destination_domain!: number;
    recipient!: Uint8Array;
    recipient_pubkey!: PublicKey;
    amount_or_id!: number;
    constructor(public readonly fields: any) {
      Object.assign(this, fields);
      this.recipient_pubkey = new PublicKey(this.recipient);
    }
  }
  
  export const SealevelTransferRemoteSchema = new Map<any, any>([
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
  } as const;
  
  export type SealevelInterchainGasPaymasterType =
    typeof SealevelInterchainGasPaymasterType[keyof typeof SealevelInterchainGasPaymasterType];

  // Config schema, e.g. for use in token data
  export class SealevelInterchainGasPaymasterConfig {
    program_id!: Uint8Array;
    program_id_pubkey!: PublicKey;
    type!: (typeof SealevelInterchainGasPaymasterType)[keyof typeof SealevelInterchainGasPaymasterType];
    igp_account?: Uint8Array;
    igp_account_pub_key?: PublicKey;
  
    constructor(public readonly fields: any) {
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
    token_exchange_rate!: bigint;
    gas_price!: bigint;
    token_decimals!: number;
  
    constructor(public readonly fields: any) {
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
  export enum SealevelGasOracleType {
    RemoteGasData = 0,
  }
  
  export class SealevelGasOracle {
    type!: SealevelGasOracleType;
    data!: SealevelRemoteGasData;
  
    constructor(public readonly fields: any) {
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
  

  
  export class SealevelAccountDataWrapper<T> {
    initialized!: boolean;
    discriminator?: unknown;
    data!: T;
    constructor(public readonly fields: any) {
      Object.assign(this, fields);
    }
  }
  
  export function getSealevelAccountDataSchema<T>(
    DataClass: T,
    discriminator?: any,
  ) {
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
  export class SealevelSimulationReturnData<T> {
    return_data!: T;
    trailing_byte!: number;
    constructor(public readonly fields: any) {
      Object.assign(this, fields);
    }
  }
  
  export function getSealevelSimulationReturnDataSchema<T>(DataClass: T) {
    return {
      kind: 'struct',
      fields: [
        ['data', DataClass],
        ['trailing_byte', 'u8'],
      ],
    };
  }

export class SealevelHyperlaneTokenData {
    /// The bump seed for this PDA.
    bump!: number;
    /// The address of the mailbox contract.
    mailbox!: Uint8Array;
    mailbox_pubkey!: PublicKey;
    /// The Mailbox process authority specific to this program as the recipient.
    mailbox_process_authority!: Uint8Array;
    mailbox_process_authority_pubkey!: PublicKey;
    /// The dispatch authority PDA's bump seed.
    dispatch_authority_bump!: number;
    /// The decimals of the local token.
    decimals!: number;
    /// The decimals of the remote token.
    remote_decimals!: number;
    /// Access control owner.
    owner?: Uint8Array;
    owner_pub_key?: PublicKey;
    /// The interchain security module.
    interchain_security_module?: Uint8Array;
    interchain_security_module_pubkey?: PublicKey;
    // The interchain gas paymaster
    interchain_gas_paymaster?: SealevelInterchainGasPaymasterConfig;
    interchain_gas_paymaster_pubkey?: PublicKey;
    interchain_gas_paymaster_account_pubkey?: PublicKey;
    // Gas amounts by destination
    destination_gas?: Map<Domain, bigint>;
    /// Remote routers.
    remote_routers?: Map<Domain, Uint8Array>;
    remote_router_pubkeys: Map<Domain, PublicKey>;
    constructor(public readonly fields: any) {
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
      this.remote_router_pubkeys = new Map<number, PublicKey>();
      if (this.remote_routers) {
        for (const [k, v] of this.remote_routers.entries()) {
          this.remote_router_pubkeys.set(k, new PublicKey(v));
        }
      }
    }
  }
  
  export const SealevelHyperlaneTokenDataSchema = new Map<any, any>([
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
  export enum SealevelHypTokenInstruction {
    Init,
    TransferRemote,
    EnrollRemoteRouter,
    EnrollRemoteRouters,
    SetInterchainSecurityModule,
    TransferOwnership,
  }
  

  /**
   * IGP Program Data Borsh Schema
   */
  
  // Should match https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/rust/sealevel/programs/hyperlane-sealevel-igp/src/accounts.rs#L91
  export class SealevelOverheadIgpData {
    /// The bump seed for this PDA.
    bump!: number;
    /// The salt used to derive the overhead IGP PDA.
    salt!: Uint8Array;
    /// The owner of the overhead IGP.
    owner?: Uint8Array;
    owner_pub_key?: PublicKey;
    /// The inner IGP account.
    inner!: Uint8Array;
    inner_pub_key!: PublicKey;
    /// The gas overheads to impose on gas payments to each destination domain.
    gas_overheads!: Map<Domain, bigint>;
    constructor(public readonly fields: any) {
      Object.assign(this, fields);
      this.owner_pub_key = this.owner ? new PublicKey(this.owner) : undefined;
      this.inner_pub_key = new PublicKey(this.inner);
    }
  }
  
  export const SealevelOverheadIgpDataSchema = new Map<any, any>([
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
    /// The bump seed for this PDA.
    bump_seed!: number;
    // The salt used to derive the IGP PDA.
    salt!: Uint8Array; // 32 bytes
    /// The owner of the IGP.
    owner?: Uint8Array | null;
    owner_pub_key?: PublicKey;
    /// The beneficiary of the IGP.
    beneficiary!: Uint8Array; // 32 bytes
    beneficiary_pub_key!: PublicKey;
    gas_oracles!: Map<number, SealevelGasOracle>;
  
    constructor(fields: any) {
      Object.assign(this, fields);
      this.owner_pub_key = this.owner ? new PublicKey(this.owner) : undefined;
      this.beneficiary_pub_key = new PublicKey(this.beneficiary);
    }
  }
  
  export const SealevelIgpDataSchema = new Map<any, any>([
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
  export enum SealevelIgpInstruction {
    Init,
    InitIgp,
    InitOverheadIgp,
    PayForGas,
    QuoteGasPayment,
    TransferIgpOwnership,
    TransferOverheadIgpOwnership,
    SetIgpBeneficiary,
    SetDestinationGasOverheads,
    SetGasOracleConfigs,
    Claim,
  }
  
  export class SealevelIgpQuoteGasPaymentInstruction {
    destination_domain!: number;
    gas_amount!: bigint;
    constructor(public readonly fields: any) {
      Object.assign(this, fields);
    }
  }
  
  export const SealevelIgpQuoteGasPaymentSchema = new Map<any, any>([
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
    payment_quote!: bigint;
    constructor(public readonly fields: any) {
      Object.assign(this, fields);
    }
  }
  
  export const SealevelIgpQuoteGasPaymentResponseSchema = new Map<any, any>([
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
    domain!: number;
    gas_oracle!: SealevelGasOracle | null;
  
    constructor(domain: number, gasOracle: SealevelGasOracle | null) {
      this.domain = domain;
      this.gas_oracle = gasOracle;
    }
  }
  
  export const SealevelGasOracleConfigSchema = {
    kind: 'struct' as const,
    fields: [
      ['domain', 'u32'],
      ['gas_oracle', { kind: 'option' as const, type: SealevelGasOracle }],
    ],
  };
  
  export class SealevelGasOverheadConfig {
    destination_domain!: number;
    gas_overhead!: bigint | null;
  
    constructor(destination_domain: number, gas_overhead: bigint | null) {
      this.destination_domain = destination_domain;
      this.gas_overhead = gas_overhead;
    }
  }
  
  export const SealevelGasOverheadConfigSchema = {
    kind: 'struct' as const,
    fields: [
      ['destination_domain', 'u32'],
      ['gas_overhead', { kind: 'option' as const, type: 'u64' }],
    ],
  };
  
  /**
   * Instruction Schemas
   */
  
  export class SealevelSetGasOracleConfigsInstruction {
    configs!: SealevelGasOracleConfig[];
  
    constructor(configs: SealevelGasOracleConfig[]) {
      this.configs = configs;
    }
  }
  
  export const SealevelSetGasOracleConfigsInstructionSchema = new Map<any, any>([
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
    configs!: SealevelGasOverheadConfig[];
  
    constructor(configs: SealevelGasOverheadConfig[]) {
      this.configs = configs;
    }
  }
  
  export const SealevelSetDestinationGasOverheadsInstructionSchema = new Map<
    any,
    any
  >([
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

  export interface TransferParams {
    weiAmountOrId: Numberish;
    recipient: Address;
    // Required for Cosmos + Solana
    fromAccountOwner?: Address;
    // Required for Solana
    fromTokenAccount?: Address;
    interchainGas?: InterchainGasQuote;
  }
  
  export interface TransferRemoteParams extends TransferParams {
    destination: Domain;
    customHook?: Address;
  }
  export interface Quote {
    addressOrDenom?: string; // undefined values represent default native tokens
    amount: bigint;
  }
  
  export interface InterchainGasQuote {
    igpQuote: Quote;
    tokenFeeQuote?: Quote;
  }



  
  export function isNullish<T>(
    val: T,
  ): val is T extends null | undefined ? T : never {
    return val === null || val === undefined;
  }
  
  export function isNumeric(value: string | number) {
    return typeof value === 'number' || /^\d+$/.test(value);
  }

  export function padBytesToLength(bytes: Uint8Array, length: number) {
    if (bytes.length > length) {
      throw new Error(`bytes must be ${length} bytes or less`);
    }
    return Buffer.concat([Buffer.alloc(length - bytes.length), bytes]);
  }

  export enum ProtocolType {
    Ethereum = 'ethereum',
    Sealevel = 'sealevel',
    Cosmos = 'cosmos',
    CosmosNative = 'cosmosnative',
    Starknet = 'starknet',
    Radix = 'radix',
  }

  const EVM_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;
  const SEALEVEL_ADDRESS_REGEX = /^[a-zA-Z0-9]{36,44}$/;
  const COSMOS_NATIVE_ADDRESS_REGEX = /^(0x)?[0-9a-fA-F]{64}$/;
  const STARKNET_ADDRESS_REGEX = /^(0x)?[0-9a-fA-F]{64}$/;
  const RADIX_ADDRESS_REGEX =
    /^(account|component)_(rdx|sim|tdx_[\d]_)[a-z0-9]{55}$/;
  
  const HEX_BYTES32_REGEX = /^0x[a-fA-F0-9]{64}$/;
  
  // https://github.com/cosmos/cosmos-sdk/blob/84c33215658131d87daf3c629e909e12ed9370fa/types/coin.go#L601C17-L601C44
  const COSMOS_DENOM_PATTERN = `[a-zA-Z][a-zA-Z0-9]{2,127}`;
  // https://en.bitcoin.it/wiki/BIP_0173
  const BECH32_ADDRESS_PATTERN = `[a-zA-Z]{1,83}1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,58}`;
  const COSMOS_ADDRESS_REGEX = new RegExp(`^${BECH32_ADDRESS_PATTERN}$`);
  const IBC_DENOM_REGEX = new RegExp(`^ibc/([A-Fa-f0-9]{64})$`);
  const COSMOS_FACTORY_TOKEN_REGEX = new RegExp(
    `^factory/(${BECH32_ADDRESS_PATTERN})/${COSMOS_DENOM_PATTERN}$`,
  );
  
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

  export function isAddressEvm(address: Address) {
    return EVM_ADDRESS_REGEX.test(address);
  }
  export function isAddressCosmos(address: Address) {
    return (
      COSMOS_ADDRESS_REGEX.test(address) ||
      IBC_DENOM_REGEX.test(address) ||
      COSMOS_FACTORY_TOKEN_REGEX.test(address)
    );
  }
  export function isAddressCosmosNative(address: Address) {
    return COSMOS_NATIVE_ADDRESS_REGEX.test(address);
  }
  
  export function isCosmosIbcDenomAddress(address: Address): boolean {
    return IBC_DENOM_REGEX.test(address);
  }
  
  export function isAddressStarknet(address: Address) {
    return STARKNET_ADDRESS_REGEX.test(address);
  }
  
  export function isAddressRadix(address: Address) {
    return RADIX_ADDRESS_REGEX.test(address);
  }
  export function isAddressSealevel(address: Address) {
    return SEALEVEL_ADDRESS_REGEX.test(address);
  }

  function getAddressProtocolType(address: Address) {
    if (!address) return undefined;
    if (isAddressEvm(address)) {
      return ProtocolType.Ethereum;
    } else if (isAddressCosmos(address)) {
      return ProtocolType.Cosmos;
    } else if (isAddressCosmosNative(address)) {
      return ProtocolType.CosmosNative;
    } else if (isAddressSealevel(address)) {
      return ProtocolType.Sealevel;
    } else if (isAddressStarknet(address)) {
      return ProtocolType.Starknet;
    } else if (isAddressRadix(address)) {
      return ProtocolType.Radix;
    } else {
      return undefined;
    }
  }
  

  function routeAddressUtil<T>(
    fns: Partial<Record<ProtocolType, (param: string) => T>>,
    param: string,
    fallback?: T,
    protocol?: ProtocolType,
  ) {
    protocol ||= getAddressProtocolType(param);
    if (protocol && fns[protocol]) return fns[protocol]!(param);
    else if (!isNullish(fallback)) return fallback;
    else throw new Error(`Unsupported protocol ${protocol}`);
  }

  export function addressToBytes32Evm(address: string): string {
    // Normalize
    let addr = address.toLowerCase().replace(/^0x/, '');
  
    // Strip leading zeros just like hexStripZeros
    addr = addr.replace(/^0+/, '');
    if (addr.length === 0) addr = '0';
  
    // Pad left with zeros up to 32 bytes (64 hex chars)
    const padded = addr.padStart(64, '0');
  
    return '0x' + padded;
  }
  
  // For EVM addresses only, kept for backwards compatibility and convenience
  export function bytes32ToAddress(bytes32: string): Address {
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

  export function strip0x(hexstr: string) {
    return hexstr.startsWith('0x') ? hexstr.slice(2) : hexstr;
  }

  export function addressToBytesEvm(address: Address): Uint8Array {
    const addrBytes32 = addressToBytes32Evm(address);
    return Buffer.from(strip0x(addrBytes32), 'hex');
  }
  
  export function addressToBytesSol(address: Address): Uint8Array {
    return new PublicKey(address).toBytes();
  }
  
  export function addressToBytesCosmos(address: Address): Uint8Array {
    return fromBech32(address).data;
  }
  
  export function addressToBytesCosmosNative(address: Address): Uint8Array {
    return Buffer.from(strip0x(address), 'hex');
  }
  
  export function isZeroishAddress(address: Address) {
    return (
      EVM_ZEROISH_ADDRESS_REGEX.test(address) ||
      SEALEVEL_ZEROISH_ADDRESS_REGEX.test(address) ||
      COSMOS_ZEROISH_ADDRESS_REGEX.test(address) ||
      COSMOS_NATIVE_ZEROISH_ADDRESS_REGEX.test(address) ||
      STARKNET_ZEROISH_ADDRESS_REGEX.test(address) ||
      RADIX_ZEROISH_ADDRESS_REGEX.test(address)
    );
  }

  export function addressToBytesStarknet(address: Address): Uint8Array {
    return new Uint8Array()
  }
  export function addressToBytesRadix(address: Address): Uint8Array {
return new Uint8Array(
      bech32m.fromWords(bech32m.decode(address).words),
    );
}

  export function addressToBytes(
    address: Address,
    protocol?: ProtocolType,
  ): Uint8Array {
    const bytes = routeAddressUtil(
      {
        [ProtocolType.Ethereum]: addressToBytesEvm,
        [ProtocolType.Sealevel]: addressToBytesSol,
        [ProtocolType.Cosmos]: addressToBytesCosmos,
        [ProtocolType.CosmosNative]: addressToBytesCosmosNative,
        [ProtocolType.Starknet]: addressToBytesStarknet,
        [ProtocolType.Radix]: addressToBytesRadix,
      },
      address,
      new Uint8Array(),
      protocol,
    );
    if (
      !(bytes.length && !bytes.every((b) => b == 0)))
      throw Error('address bytes must not be empty')
    
    return bytes;
  }