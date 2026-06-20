// FIXTURE: intentionally vulnerable x402 settlement handler (for x402guard tests)
import { ethers } from 'ethers';

export default async function handler(req, res) {
  try {
    const requestId = 'req_' + Math.random().toString(36).slice(2); // weak random id
    const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
    const wallet = new ethers.Wallet(process.env.TREASURY_PRIVATE_KEY, provider);
    // No HMAC / signature check — anyone hitting this endpoint moves treasury funds:
    const tx = await wallet.sendTransaction({ to: req.body.to, value: req.body.amount });
    return res.json({ requestId, hash: tx.hash });
  } catch (e) {
    return res.status(500).json({ error: e.stack }); // stack trace leaked to client
  }
}
