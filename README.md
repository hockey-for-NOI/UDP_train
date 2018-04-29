# Homework for UDP

#### CST53 He Qi 2015011299

## Introduction

Use UDP protocol to implement a key-value request server and client.

## Protocol

Client version 0.0.0.1
Server version 0.0.0.1

|Name|Length(in bytes)|Description|
|:-:|--:|:--|
|MAGIC0|4|0xCAFEXXXX, XXXX=client version|
|MAGIC1|4|0XFACEXXXX, XXXX=server version|
|MAGIC2|4|0x9029XXXX, XXXX=client version|
|MAGIC3|4|0x9209XXXX, XXXX=server version|

## Usage

Server:

	mkdir build
	cd build
	cmake ..
	make
	./server

Client

	mkdir build
	cd build
	cmake ..
	make
	./client 127.0.0.1

Or replace 127.0.0.1 with the server address.

## Safety

P = 0x78000001, R = 31. a^b means exp(b\*ln(a)).

Server manages a ~10000 global key pool {Xi} with necessary precomputation and indexing (especially for a map R^X to X). One thread is created to repeatedly refresh the key pool in a low speed (with the total number in a reasonable range).

Client generate key K0, K1, and record it. (0 <= K0 < P, 0 <= K1 < P)

Client send MAGIC0, R^K0, R^K1, R^K0 xor R^K1 to Server as M, C0, C1, V0.

Server verify C0 xor C1 = V0 and check C0 and C1 are not in blacklist. After that, server randomly select one key X, generate key T0, send MAGIC1, R^T0, (C0^T0)xorX, (C1^T0)xorX to Client as M1, C2, C3, V1. After that, T0 is dropped.

Client calculate (C2^K0)xorC3=X, verify (C2^K1)xorV1=X. 

Now client use the key X for identification.

Let Q be the request key. As client already know the length is Q, client determines two bounds ST and ED (1 <= Q <= 1e9, 0 <= ST < ED <= Q, ED - ST <= 1024).

Client generates ED - ST keys, each Ki encrypted with X: Ki xor (X and 255).

Client also generates a key K2 for identification.

Client send MAGIC2, R^X, Q, ST, ED, R^K2, a checksum and all encrypted keys to server.

Server use lookup table to check if R^X exists in key pool. If so, get X using lookup table and decrypt the keys. Checksum is verified at the same time. No matter what happened, X is removed from the pool.

Then, server get the required string, xor them with the keys to encrypt, and generate another checksum.

Server send MAGIC4, R^K2^X(for identification), a checksum and the encrypted string to client.

After the above 4 steps, one package is transformed.

*Conclusion:*

+ Client generate a public key to require a token.

+ Server gives out encrypted token with low cost, and use blacklist to avoid playback attack.

+ Client use the encrypted token as client identification to submit one request, with another public key.

+ Server verify the token and perform real data transform, with re-encrypted token for server identification, and remove the token to avoid playback attack.
