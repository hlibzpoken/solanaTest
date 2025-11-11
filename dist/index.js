import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { Runner } from "./runner";
async function main() {
    const connection = new Connection(process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com', 'confirmed');
    const chainName = 'solanamainnet';
    const addresses = {
        programId: 'AYnRuLKV6Tqtibt7iA6DGCCACnRjy4nAhC8b5nPscsYs',
        warpRouter: '975wpF9KmWTVnh398Qs6VcnDtYZsXVWtKiSkXfWH22GP',
        mailbox: 'E588QtVUvresuXq2KoNEwAmoifCzYGpRBdHByN9KQMbi'
    };
    const pk = new Keypair();
    const sender = new PublicKey('4dxRtLucVXZ4o9drN5jtCs5X9TJdv79KwPDp4fsVqtqh');
    const destinationDomain = 42161;
    const runner = new (class extends Runner {
    })(chainName, connection, addresses);
    console.log('Fetching gas quote...');
    const quote = await runner.quoteTransferRemoteGas({
        destination: destinationDomain,
        sender: sender.toBase58(),
    });
    console.log('--- Interchain Gas Quote ---');
    console.log('Igp Quote (lamports):', quote.igpQuote.amount.toString());
    if (quote.tokenFeeQuote)
        console.log('Token Fee Quote:', quote.tokenFeeQuote.amount.toString());
    const remoteTx = await runner.populateTransferRemoteTx({
        weiAmountOrId: 0,
        destination: destinationDomain,
        recipient: '0x851C93819df2C2202803869c93f86769b855f7bF',
        fromAccountOwner: sender.toBase58(),
        interchainGas: quote,
    });
    console.log("Tranasction: ", remoteTx);
}
main().catch((err) => {
    console.error(err);
    process.exit(1);
});
