Historical synthetic evidence for Stream #3, never production authority.

`bundle.json`, `receipt.json` and `historical-evaluation.json` retain the original
0.9.0 Ledger / 0.5.0 Compiler / 0.19.0 Guard deny-only evidence. The evaluation
record was selected without modifying its contents from the original history.

`historical-matrix.json` retains bundle/receipt objects for the 11 authorities
that produced the original 33 evaluations. Producer stacks (Ledger / Compiler /
Guard, peeled release commits):

- 0.7.0 a7c800f3510dd328cb4ef857a772b115a5d40379 /
  0.4.0 e6f3813a9627bc65cc23f2ed8dc4997481157523 /
  0.16.0 d9474f39333b32a0fb3f29383c0b2656427f417e
- 0.8.0 73a88e072fcf9027cc7942bfe5e9868e0c32bc8c /
  0.4.0 e6f3813a9627bc65cc23f2ed8dc4997481157523 /
  0.17.0 ad07e3241b94627e06a5cfe3a265500b3e52c388
- same Ledger/Compiler as above /
  0.18.0 5388f9680a0bd7cb3b686349239f57d58dd4fdf8
- 0.9.0 bd82c11dc0c4d4003063c7f2ce0f2e87f12f7bf1 /
  0.5.0 f817a1bca65806c9ee33ccc74c2238952ebf8f01 /
  0.19.0 599c132038f66b5f15b47752505f0ed1aae1d641

Ledger 0.7 rejected role-only finalization; that nonexistent authority is not
fabricated here. All original producer environments used CRI-CORE 0.14.0 and
proposal-normalizer 0.2.0. These are historical producer versions, not patched
backports. Test validation/evaluation uses the active candidate package pair.

`historical-partial-v3.json` is the same synthetic historical Ledger 0.9.0
partial-translation evidence included in the paired Ledger PR. Its compiled
contract is v2; envelope v3 does not change the live-safety rule. The bundle
and receipt objects retain their original hashes.
