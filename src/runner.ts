import {
    AccountMeta,
    ComputeBudgetProgram,
    Connection,
    Keypair,
    Message,
    PublicKey,
    SystemProgram,
    SYSVAR_CLOCK_PUBKEY,
    SYSVAR_RENT_PUBKEY,
    Transaction,
    TransactionInstruction,
    VersionedTransaction,
  } from '@solana/web3.js';
import type { Address, Domain } from './serialize.js';
import {
    SealevelInstructionWrapper,
    SealevelIgpInstruction,
    SealevelIgpQuoteGasPaymentInstruction,
    SealevelIgpQuoteGasPaymentSchema,
    SealevelIgpQuoteGasPaymentResponseSchema,
    SealevelIgpQuoteGasPaymentResponse,
    SealevelHyperlaneTokenDataSchema,
    SealevelAccountDataWrapper,
    SealevelHyperlaneTokenData,
    SealevelOverheadIgpData,
    SealevelOverheadIgpDataSchema,
    SealevelIgpData,
    SealevelIgpDataSchema,
    SealevelInterchainGasPaymasterType,
    TransferRemoteParams,
    SealevelHypTokenInstruction,
    SealevelTransferRemoteInstruction,
    SealevelTransferRemoteSchema,
    padBytesToLength,
    isNullish,
    isNumeric,
    addressToBytes

} from './serialize.js';

export interface IgpPaymentKeys {
    programId: PublicKey;
    igpAccount: PublicKey;
    overheadIgpAccount?: PublicKey;
  }

import { deserializeUnchecked, serialize, type Schema } from 'borsh';
import { Buffer } from 'buffer';

const TRANSFER_REMOTE_COMPUTE_LIMIT = 1_000_000;
export const SEALEVEL_SPL_NOOP_ADDRESS =
  'noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV';

interface QuoteTransferRemoteParams {
    destination: Domain;
    sender?: Address;
    customHook?: Address;
    recipient?: Address;
    amount?: bigint;
  }

  interface Quote {
    addressOrDenom?: string; // undefined values represent default native tokens
    amount: bigint;
  }

  export interface InterchainGasQuote {
    igpQuote: Quote;
    tokenFeeQuote?: Quote;
  }


  interface KeyListParams {
    sender: PublicKey;
    mailbox: PublicKey;
    randomWallet: PublicKey;
    igp?: IgpPaymentKeys;
    isNative?: boolean
  }




export abstract class Runner {
    protected readonly programId: PublicKey;
    protected readonly warpProgramPubKey: PublicKey; 
    protected readonly mailbox: PublicKey; 
    protected readonly provider: Connection; 
    protected readonly chainName: string; 
  
    constructor(
        public readonly chain: string,
        public readonly _provider: Connection,
        public readonly addresses: Record<string, Address>,
    ) {
      this.programId = new PublicKey(addresses.programId!);
      this.warpProgramPubKey = new PublicKey(addresses.warpRouter!);
      this.mailbox = new PublicKey(addresses.mailbox!);
      this.provider = _provider;
      this.chainName = chain;
    }
    async quoteTransferRemoteGas({
        destination,
        sender,
      }: QuoteTransferRemoteParams): Promise<InterchainGasQuote> {
        const tokenData = await this.getTokenAccountData();
        console.log('Available destination domains:', [...tokenData.destination_gas!.keys()]);
        const destinationGas = tokenData.destination_gas?.get(destination);
        if (isNullish(destinationGas)) {
          return { igpQuote: { amount: 0n } };
        }

        const igp = this.getIgpAdapter(tokenData);
        if (!igp) {
          return { igpQuote: { amount: 0n } };
        }
        if(sender == undefined)
        throw Error('Sender required for Sealevel transfer remote gas quote')

        const igpPayment = await igp.quoteGasPayment(
          destination,
          destinationGas,
          new PublicKey(sender),
        );
    
        return { igpQuote: { amount: igpPayment } };
      }

      async populateTransferRemoteTx({
        weiAmountOrId,
        destination,
        recipient,
        fromAccountOwner,
        isNative
      }: TransferRemoteParams): Promise<Transaction> {
        if (!fromAccountOwner)
          throw new Error('fromAccountOwner required for Sealevel');
        const randomWallet = Keypair.generate();
        const fromWalletPubKey = new PublicKey(fromAccountOwner);
        const mailboxPubKey = new PublicKey(this.mailbox);
    
        const keys = await this.getTransferInstructionKeyList({
          sender: fromWalletPubKey,
          mailbox: mailboxPubKey,
          randomWallet: randomWallet.publicKey,
          igp: await this.getIgpKeys(),
          isNative
        });        
    
        const value = new SealevelInstructionWrapper({
          instruction: SealevelHypTokenInstruction.TransferRemote,
          data: new SealevelTransferRemoteInstruction({
            destination_domain: destination,
            recipient: padBytesToLength(addressToBytes(recipient), 32),
            amount_or_id: BigInt(weiAmountOrId),
          }),
        });
        const serializedData = serialize(SealevelTransferRemoteSchema, value);
    
        const transferRemoteInstruction = new TransactionInstruction({
          keys,
          programId: this.warpProgramPubKey,
          // Array of 1s is an arbitrary 8 byte "discriminator"
          // https://github.com/hyperlane-xyz/issues/issues/462#issuecomment-1587859359
          data: Buffer.concat([
            Buffer.from([1, 1, 1, 1, 1, 1, 1, 1]),
            Buffer.from(serializedData),
          ]),
        });
    
        const setComputeLimitInstruction = ComputeBudgetProgram.setComputeUnitLimit(
          { units: TRANSFER_REMOTE_COMPUTE_LIMIT },
        );
    
        // For more info about priority fees, see:
        // https://solanacookbook.com/references/basic-transactions.html#how-to-change-compute-budget-fee-priority-for-a-transaction
        // https://docs.phantom.app/developer-powertools/solana-priority-fees
        // https://www.helius.dev/blog/priority-fees-understanding-solanas-transaction-fee-mechanics
        const setPriorityFeeInstruction = ComputeBudgetProgram.setComputeUnitPrice({
          microLamports: (await this.getMedianPriorityFee()) || 0,
        });
    
        const recentBlockhash = (
          await this.provider.getLatestBlockhash('finalized')
        ).blockhash;
    
        // @ts-ignore Workaround for bug in the web3 lib, sometimes uses recentBlockhash and sometimes uses blockhash
        const tx = new Transaction({
          feePayer: fromWalletPubKey,
          blockhash: recentBlockhash,
          recentBlockhash,
        })
          .add(setComputeLimitInstruction)
          .add(setPriorityFeeInstruction)
          .add(transferRemoteInstruction);
        tx.partialSign(randomWallet);
        return tx;
      }
    
      async getTransferInstructionKeyList({
        sender,
        mailbox,
        randomWallet,
        igp,
        isNative
      }: KeyListParams): Promise<Array<AccountMeta>> {
        let keys = [
          // 0.   [executable] The system program.
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          // 1.   [executable] The spl_noop program.
          {
            pubkey: new PublicKey(SEALEVEL_SPL_NOOP_ADDRESS),
            isSigner: false,
            isWritable: false,
          },
          // 2.   [] The token PDA account.
          {
            pubkey: this.deriveHypTokenAccount(),
            isSigner: false,
            isWritable: false,
          },
          // 3.   [executable] The mailbox program.
          { pubkey: mailbox, isSigner: false, isWritable: false },
          // 4.   [writeable] The mailbox outbox account.
          {
            pubkey: this.deriveMailboxOutboxAccount(mailbox),
            isSigner: false,
            isWritable: true,
          },
          // 5.   [] Message dispatch authority.
          {
            pubkey: this.deriveMessageDispatchAuthorityAccount(),
            isSigner: false,
            isWritable: false,
          },
          // 6.   [signer] The token sender and mailbox payer.
          { pubkey: sender, isSigner: true, isWritable: false },
          // 7.   [signer] Unique message account.
          { pubkey: randomWallet, isSigner: true, isWritable: false },
          // 8.   [writeable] Message storage PDA.
          {
            pubkey: this.deriveMsgStorageAccount(mailbox, randomWallet),
            isSigner: false,
            isWritable: true,
          },
        ];
        if (igp) {
          keys = [
            ...keys,
            // 9.    [executable] The IGP program.
            { pubkey: igp.programId, isSigner: false, isWritable: false },
            // 10.   [writeable] The IGP program data.
            {
              pubkey: this.deriveIgpProgramPda(igp.programId),
              isSigner: false,
              isWritable: true,
            },
            // 11.   [writeable] Gas payment PDA.
            {
              pubkey: this.deriveGasPaymentPda(
                igp.programId,
                randomWallet,
              ),
              isSigner: false,
              isWritable: true,
            },
          ];
          if (igp.overheadIgpAccount) {
            keys = [
              ...keys,
              // 12.   [] OPTIONAL - The Overhead IGP account, if the configured IGP is an Overhead IGP
              {
                pubkey: igp.overheadIgpAccount,
                isSigner: false,
                isWritable: false,
              },
            ];
          }
          keys = [
            ...keys,
            // 13.   [writeable] The Overhead's inner IGP account (or the normal IGP account if there's no Overhead IGP).
            {
              pubkey: igp.igpAccount,
              isSigner: false,
              isWritable: true,
            },
          ];
          if (isNative) {
            keys.push(
              { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // executable
              { pubkey: this.deriveNativeTokenCollateralAccount(), isSigner: false, isWritable: true } // writeable
            );
          }
        }
        return keys;
      }

      deriveGasPaymentPda(
        igpProgramId: string | PublicKey,
        randomWalletPubKey: PublicKey,
      ): PublicKey {
        return this.derivePda(
          ['hyperlane_igp', '-', 'gas_payment', '-', randomWalletPubKey.toBuffer()],
          igpProgramId,
        );
      }
      deriveIgpProgramPda(igpProgramId: string | PublicKey): PublicKey {
        return this.derivePda(
          ['hyperlane_igp', '-', 'program_data'],
          igpProgramId,
        );
      }
      deriveMailboxOutboxAccount(mailbox: PublicKey): PublicKey {
        return this.derivePda(['hyperlane', '-', 'outbox'], mailbox);
      }
      deriveMessageDispatchAuthorityAccount(): PublicKey {
        return this.derivePda(
          ['hyperlane_dispatcher', '-', 'dispatch_authority'],
          this.warpProgramPubKey,
        );
      }

      deriveMsgStorageAccount(
        mailbox: PublicKey,
        randomWalletPubKey: PublicKey,
      ): PublicKey {
        return this.derivePda(
          [
            'hyperlane',
            '-',
            'dispatched_message',
            '-',
            randomWalletPubKey.toBuffer(),
          ],
          mailbox,
        );
      }
    

    
      // Should match https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/4b3537470eff0139163a2a7aa1d19fc708a992c6/rust/sealevel/programs/hyperlane-sealevel-token/src/plugin.rs#L43-L51
      deriveAtaPayerAccount(): PublicKey {
        return this.derivePda(
          ['hyperlane_token', '-', 'ata_payer'],
          this.warpProgramPubKey,
        );
      }
    

      async getMedianPriorityFee(): Promise<number | undefined> {
    
        // Currently only transactions done in solana requires a priority
        if (this.chainName !== 'solanamainnet') {
          return 0;
        }
    }

      async getIgpKeys(): Promise<IgpPaymentKeys | undefined> {
        const tokenData = await this.getTokenAccountData();
        const igpAdapter = this.getIgpAdapter(tokenData);
        return igpAdapter?.getPaymentKeys();
      }


         getIgpAdapter(
            tokenData: SealevelHyperlaneTokenData,
          ): SealevelIgpProgramAdapter | undefined {
            const igpConfig = tokenData.interchain_gas_paymaster;
        
            if (!igpConfig || igpConfig.igp_account_pub_key === undefined) {
              return undefined;
            }
        
            if (igpConfig.type === SealevelInterchainGasPaymasterType.Igp) {
              return new SealevelIgpAdapter(this.chainName, this.provider, {
                igp: igpConfig.igp_account_pub_key.toBase58(),
                programId: igpConfig.program_id_pubkey.toBase58(),
              });
            } else if (
              igpConfig.type === SealevelInterchainGasPaymasterType.OverheadIgp
            ) {
              return new SealevelOverheadIgpAdapter(
                this.chainName,
                this.provider,
                {
                  overheadIgp: igpConfig.igp_account_pub_key.toBase58(),
                  programId: igpConfig.program_id_pubkey.toBase58(),
                },
              );
            } else {
              throw new Error(`Unsupported IGP type ${igpConfig.type}`);
            }
          }
    

      async getTokenAccountData(): Promise<SealevelHyperlaneTokenData> {
          const tokenPda = this.deriveHypTokenAccount();
          const accountInfo = await this.provider.getAccountInfo(tokenPda);
          if (!accountInfo)
            throw new Error(`No account info found for ${tokenPda}`);
          const wrappedData = deserializeUnchecked(
            SealevelHyperlaneTokenDataSchema as Schema,
            SealevelAccountDataWrapper,
            accountInfo.data,
          );
          return wrappedData.data as SealevelHyperlaneTokenData
 
        }
      
      deriveHypTokenAccount(): PublicKey {
        return this.derivePda(
          ['hyperlane_message_recipient', '-', 'handle', '-', 'account_metas'],
          this.warpProgramPubKey,
        );
      }

      deriveNativeTokenCollateralAccount(): PublicKey {
        return this.derivePda(
          ['hyperlane_token', '-', 'native_collateral'],
          this.warpProgramPubKey,
        );
      }
    
       derivePda(
        seeds: Array<string | Buffer>,
        programId: string | PublicKey,
      ): PublicKey {
        return this.derivePdaWithBump(seeds, programId)[0];
      }
    
     derivePdaWithBump(
        seeds: Array<string | Buffer>,
        programId: string | PublicKey,
      ): [PublicKey, number] {
        const [pda, bump] = PublicKey.findProgramAddressSync(
          seeds.map((s) => Buffer.from(s)),
          new PublicKey(programId),
        );
        return [pda, bump];
      }
    }

    abstract class SealevelIgpProgramAdapter {
        protected readonly programId: PublicKey;
      
        constructor(
          public readonly chainName: string,
          public readonly provider: Connection,
          public readonly addresses: { programId: Address },
        ) {
      
          this.programId = new PublicKey(addresses.programId);
        }
      
        abstract getPaymentKeys(): Promise<IgpPaymentKeys>;

        async quoteGasPayment(
            destination: Domain,
            gasAmount: bigint,
            payerKey: PublicKey,
          ): Promise<bigint> {
            const paymentKeys = await this.getPaymentKeys();
            const keys = [
              // 0. `[executable]` The system program.
              { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
              // 1. `[]` The IGP account.
              {
                pubkey: paymentKeys.igpAccount,
                isSigner: false,
                isWritable: false,
              },
            ];
            if (paymentKeys.overheadIgpAccount) {
              // 2. `[]` The overhead IGP account (optional).
              keys.push({
                pubkey: paymentKeys.overheadIgpAccount,
                isSigner: false,
                isWritable: false,
              });
            }
            const value = new SealevelInstructionWrapper({
              instruction: SealevelIgpInstruction.QuoteGasPayment,
              data: new SealevelIgpQuoteGasPaymentInstruction({
                destination_domain: destination,
                gas_amount: BigInt(gasAmount),
              }),
            });
            const quoteGasPaymentInstruction = new TransactionInstruction({
              keys,
              programId: this.programId,
              data: Buffer.from(serialize(SealevelIgpQuoteGasPaymentSchema, value)),
            });
        
            const message = Message.compile({
              // This is ignored
              recentBlockhash: PublicKey.default.toBase58(),
              instructions: [quoteGasPaymentInstruction],
              payerKey,
            });
        
            const tx = new VersionedTransaction(message);
        
            const connection = this.provider
            const simulationResponse = await connection.simulateTransaction(tx, {
              // ignore the recent blockhash we pass in, and have the node use its latest one
              replaceRecentBlockhash: true,
              // ignore signature verification
              sigVerify: false,
            });
        
            const base64Data = simulationResponse.value.returnData?.data?.[0];
            if(
              base64Data === undefined
            )
            throw Error('No return data when quoting gas payment, may happen if the payer has insufficient funds')
        
            const data = Buffer.from(base64Data, 'base64');
            const quote = deserializeUnchecked(
              SealevelIgpQuoteGasPaymentResponseSchema,
              SealevelIgpQuoteGasPaymentResponse,
              data,
            );
        
            return quote.payment_quote;
          }
        }
        





export class SealevelOverheadIgpAdapter extends SealevelIgpProgramAdapter {
    protected readonly overheadIgp: PublicKey;
  
    constructor(
      public readonly chainName: string,
      public readonly connection: Connection,
      public readonly addresses: { overheadIgp: Address; programId: Address },
    ) {
      super(chainName, connection, addresses);
  
      this.overheadIgp = new PublicKey(addresses.overheadIgp);
    }
  
    async getAccountInfo(): Promise<SealevelOverheadIgpData> {
      const address = this.addresses.overheadIgp;
      const connection = this.provider;
  
      const accountInfo = await connection.getAccountInfo(new PublicKey(address));
      if (accountInfo === null) {
        throw new Error(`No account info found for ${address}`)
      }
  
      const accountData = deserializeUnchecked(
        SealevelOverheadIgpDataSchema,
        SealevelAccountDataWrapper,
        accountInfo.data,
      );
      return accountData.data as SealevelOverheadIgpData;
    }
  
    override async getPaymentKeys(): Promise<IgpPaymentKeys> {
      const igpData = await this.getAccountInfo();
      return {
        programId: this.programId,
        igpAccount: igpData.inner_pub_key,
        overheadIgpAccount: this.overheadIgp,
      };
    }
    
}

export class SealevelIgpAdapter extends SealevelIgpProgramAdapter {
    protected readonly igp: PublicKey;
  
    constructor(
      public readonly chainName: string,
      public readonly connection: Connection,
      public readonly addresses: { igp: Address; programId: Address },
    ) {
      super(chainName, connection, addresses);
  
      this.igp = new PublicKey(addresses.igp);
    }
  
     async getPaymentKeys(): Promise<IgpPaymentKeys> {
      return {
        programId: this.programId,
        igpAccount: this.igp,
      };
    }
  
    async getAccountInfo(): Promise<SealevelIgpData> {
      const address = this.addresses.igp;
      const connection = this.provider;
  
      const accountInfo = await connection.getAccountInfo(new PublicKey(address));
       if(accountInfo === null){
        throw Error(`No account info found for ${address}`)
       } 
  
      const accountData = deserializeUnchecked(
        SealevelIgpDataSchema,
        SealevelAccountDataWrapper,
        accountInfo.data,
      );
      return accountData.data as SealevelIgpData;
    }

    async quoteGasPayment(
        destination: Domain,
        gasAmount: bigint,
        payerKey: PublicKey,
      ): Promise<bigint> {
        const paymentKeys = await this.getPaymentKeys();
        const keys = [
          // 0. `[executable]` The system program.
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          // 1. `[]` The IGP account.
          {
            pubkey: paymentKeys.igpAccount,
            isSigner: false,
            isWritable: false,
          },
        ];
        if (paymentKeys.overheadIgpAccount) {
          // 2. `[]` The overhead IGP account (optional).
          keys.push({
            pubkey: paymentKeys.overheadIgpAccount,
            isSigner: false,
            isWritable: false,
          });
        }
        const value = new SealevelInstructionWrapper({
          instruction: SealevelIgpInstruction.QuoteGasPayment,
          data: new SealevelIgpQuoteGasPaymentInstruction({
            destination_domain: destination,
            gas_amount: BigInt(gasAmount),
          }),
        });
        const quoteGasPaymentInstruction = new TransactionInstruction({
          keys,
          programId: this.programId,
          data: Buffer.from(serialize(SealevelIgpQuoteGasPaymentSchema, value)),
        });
    
        const message = Message.compile({
          // This is ignored
          recentBlockhash: PublicKey.default.toBase58(),
          instructions: [quoteGasPaymentInstruction],
          payerKey,
        });
    
        const tx = new VersionedTransaction(message);
    
        const connection = this.provider;
        const simulationResponse = await connection.simulateTransaction(tx, {
          // ignore the recent blockhash we pass in, and have the node use its latest one
          replaceRecentBlockhash: true,
          // ignore signature verification
          sigVerify: false,
        });
    
        const base64Data = simulationResponse.value.returnData?.data?.[0];
        if
          (base64Data === undefined)
          throw Error('No return data when quoting gas payment, may happen if the payer has insufficient funds')
        
    
        const data = Buffer.from(base64Data, 'base64');
        const quote = deserializeUnchecked(
          SealevelIgpQuoteGasPaymentResponseSchema,
          SealevelIgpQuoteGasPaymentResponse,
          data,
        );
    
        return quote.payment_quote;
      }
    }
    
