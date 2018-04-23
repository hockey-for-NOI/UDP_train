# Homework for UDP

#### CST53 He Qi 2015011299

## Introduction

Use UDP protocol to implement a key-value request server and client.

## Protocol

|Name|Length(in bytes)|Description|
|:-:|--:|:--|

## Safety

P = 0x78000001, R = 31

Server generate ~100 global key Xi with necessary precomputation and indexing.

Client generate key K0, K1, and record it. (0 <= K0 < P, 0 <= K1 < P)

Client send MAGIC0, R^K0, R^K1, K0 + K1 to Server as M, C0, C1, V0.

Server randomly select one key X, verify C0 * C1 = R^V0, generate key T0, send MAGIC1, R^T0 and (C0^T0)xor(C1^T0)xor(R^X) to Client as C2, C3.

Client calculate (C2^K0)xor(C2^K1)xorC3=R^X, set request as Q, send MAGIC2, R^X, R^X^Q.
