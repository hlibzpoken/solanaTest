import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { Runner } from "./runner.js";
async function main() {
    const connection = new Connection(process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com', 'confirmed');
    const chainName = 'solanamainnet';
    const addresses = {
        programId: 'AYnRuLKV6Tqtibt7iA6DGCCACnRjy4nAhC8b5nPscsYs',
        warpRouter: 'AYnRuLKV6Tqtibt7iA6DGCCACnRjy4nAhC8b5nPscsYs',
        mailbox: 'E588QtVUvresuXq2KoNEwAmoifCzYGpRBdHByN9KQMbi'
    };
    const pk = new Keypair();
    const sender = new PublicKey('4dxRtLucVXZ4o9drN5jtCs5X9TJdv79KwPDp4fsVqtqh');
    const destinationDomain = 24101;
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
        weiAmountOrId: 10000,
        destination: destinationDomain,
        recipient: '0x74Cae0ECC47B02Ed9B9D32E000Fd70B9417970C5',
        fromAccountOwner: sender.toBase58(),
        interchainGas: quote,
        isNative: true
    });
    try {
        const simulation = await connection.simulateTransaction(remoteTx, undefined, true);
        console.log('\n✅ Simulation Result:');
        console.log('Success:', !simulation.value.err);
        if (simulation.value.err) {
            console.error('❌ Simulation Error:', simulation.value.err);
        }
        console.log('\n📊 Compute Units Consumed:', simulation.value.unitsConsumed);
        console.log('\n📝 Program Logs:');
        if (simulation.value.logs) {
            simulation.value.logs.forEach((log, i) => {
                console.log(`  ${i + 1}. ${log}`);
            });
        }
        // Детальная информация об изменениях аккаунтов
        if (simulation.value.accounts) {
            console.log('\n💼 Account Changes:');
            simulation.value.accounts.forEach((account, i) => {
                if (account) {
                    console.log(`  Account ${i}:`);
                    console.log(`    Lamports: ${account.lamports}`);
                    console.log(`    Owner: ${account.owner}`);
                    console.log(`    Data length: ${account.data.length} bytes`);
                }
            });
        }
        // Проверка на ошибки
        if (simulation.value.err) {
            console.log('\n⚠️ Transaction will fail if sent!');
            console.log('Error details:', JSON.stringify(simulation.value.err, null, 2));
        }
        else {
            console.log('\n✅ Transaction simulation successful!');
            console.log('Transaction should succeed if sent to the network.');
        }
    }
    catch (error) {
        console.error('\n❌ Simulation failed with exception:');
        console.error(error);
        // Дополнительная информация об ошибке
        if (error instanceof Error) {
            console.error('Error message:', error.message);
            console.error('Error stack:', error.stack);
        }
    }
    console.log('\n--- End Simulation ---');
}
main().catch((err) => {
    console.error(err);
    process.exit(1);
});
