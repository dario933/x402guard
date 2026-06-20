// FIXTURE: a correctly-hardened version of the same handler (should produce 0 findings)
import { ethers } from 'ethers';
import crypto from 'crypto';

export default async function handler(req, res) {
  const sig = req.headers['x-awm-signature'];
  if (!verifySignature(req.rawBody, sig)) return res.status(401).json({ error: 'unauthorized' });

  const requestId = crypto.randomUUID();
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
  const wallet = new ethers.Wallet(process.env.TREASURY_PRIVATE_KEY, provider);
  const tx = await wallet.sendTransaction({ to: req.body.to, value: req.body.amount });
  return res.json({ ok: true, requestId });
}
