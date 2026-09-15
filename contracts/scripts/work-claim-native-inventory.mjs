// Independent block enumeration counts even idempotent calls that emit no event.
import assert from 'node:assert/strict';
import { ethers } from 'ethers';

export async function transactionInventory(send, escrow, allocation) {
  const methods = { submitClaim: 'submit', recordDecision: 'record', withdrawPayment: 'pay', withdrawRefund: 'refund' };
  const result = { submit: [], record: [], pay: [], refund: [] };
  const address = (await escrow.getAddress()).toLowerCase();
  const head = Number(BigInt(await send('eth_blockNumber', [])));
  assert.ok(head <= 128, 'fixture transaction inventory exceeds bound');
  for (let height = 0; height <= head; height++) {
    const block = await send('eth_getBlockByNumber', [ethers.toQuantity(height), true]);
    assert.equal(Number(block.number), height);
    for (const tx of block.transactions) {
      if (tx.to?.toLowerCase() !== address) continue;
      const call = escrow.interface.parseTransaction({ data: tx.input, value: tx.value });
      if (!call || !Object.hasOwn(methods, call.name) || call.args[0] !== allocation) continue;
      const receipt = await send('eth_getTransactionReceipt', [tx.hash]);
      assert.equal(receipt.transactionHash, tx.hash);
      assert.equal(receipt.blockHash, block.hash);
      result[methods[call.name]].push({ hash: tx.hash, status: Number(receipt.status), nonce: Number(tx.nonce) });
    }
  }
  return result;
}
