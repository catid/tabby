# Tabby
#### Strong, Fast, and Portable Cryptographic Signatures and Handshakes

The Tabby key agreement protocol is designed for the situation where a client
is attempting to connect to a server it has not connected to before.  After the
protocol completes, a 256-bit secret key is shared by both parties.  The server
has also been authenticated by the client.  Weak "forward secrecy" is provided,
in that after the server changes its ephemeral key, all previous connections
cannot be decrypted if the server's long-term secret key is leaked somehow.
It is a one-round protocol that runs faster than signcryption-based approaches,
while exposing less sensitive information.  Tabby has a "128-bit" security level.

Tabby also provides signatures based on the efficient EdDSA approach.

Tabby uses the [Snowshoe](https://github.com/catid/snowshoe/) elliptic curve
math library, and it also uses the [Cymric](https://github.com/catid/cymric/)
secure random number generator library.  Please refer to those repositories for
more information about the underlying math and software implementation.


#### Benchmarks

The following measurements show normal walltime with Turbo Boost on, and median
cycles with Turbo Boost off.  The measurements were taken over 10,000 samples
for each configuration, unless otherwise noted.

##### libtabby.a on Macbook Air (1.7 GHz Core i5-2557M Sandy Bridge, July 2011):

Key generation:

+ Successfully created a new server key in `378024` cycles, `178` usec (one sample)
+ Generated a client key in `184684` cycles, `86` usec (one sample)
+ Periodic server rekey in `189312` cycles, `75` usec (one sample)

Signatures:

+ Tabby sign: `68672` median cycles, `26.3009` avg usec
+ Tabby verify signature: `163420` median cycles, `62.4262` avg usec

One-round EC-DH with forward secrecy:

+ Tabby server handshake: `144472` median cycles, `55.464` avg usec
+ Tabby client handshake: `205504` median cycles, `78.8678` avg usec

Each of these operations takes roughly 2-3 usec longer than the Snowshoe math
routines they are based on.  Where applicable, these operations do full input
validation, use good random number sources, run in constant time, and clean
up the stack to avoid leaking sensitive information.


#### Tabby Key Generation Process : Algorithm 1

To produce private/public key pairs for Tabby, the following process is performed:

+ Step 1: Seed Cymric.
+ Step 2: Use Cymric to generate a 512-bit random number R : 64 bytes.
+ Step 3: Calculate S = R mod q using Snowshoe : 32 bytes.
+ Step 4: Check if S == 0 in constant-time; if so start over at step 2.
+ Step 5: Calculate P = S * G using Snowshoe : 64 bytes.
+ Step 6: Erase R from memory.

The secret key is S (32 bytes), and the public key is P (64 bytes).


#### Protocol

The following protocol proceeds in time order.

Server offline processing:

+ Server uses Algo. 1 to generate SS and SP, resp. the secret and public long-term server keys.
+ Server publishes its public key SP somehow so that the clients will know it ahead of time.

Server online processing; every 30 minutes:

+ Server uses Algo. 1 to generate ES and EP, resp. the secret and public ephemeral server keys.

Client online processing:

+ Client uses Algo. 1 to generate CS and CP, resp. the secret and public ephemeral client keys.
+ Client uses Cymric to generate a 256-bit number-used-only-once (nonce) CN.

Client sends to server:

+ Client public key (CP) : 64 bytes.
+ Client nonce (CN) : 32 bytes.

Server online processing:

+ Server uses Cymric to generate a 256-bit number-used-only-once (nonce) SN.
+ H = BLAKE2(CP, CN, EP, SP, SN) : 64 bytes.
+ h = H (mod q) with Snowshoe; q is a Snowshoe parameter.
+ Verify in constant-time that h != 0.  If so, start over.
+ e = SS * h + ES (mod q) with Snowshoe.
+ Verify in constant-time that e != 0.  If so, start over.
+ T(X,Y) = e * SP with Snowshoe.
+ k = BLAKE2(H, T) : 64 bytes.
+ Session key is the low 32 bytes of k.
+ The high 32 bytes of k is the server proof of key knowledge (PROOF).

Server sends to client:

+ Server ephemeral public key (EP) : 64 bytes.
+ Server nonce (SN) : 32 bytes.
+ Server proof (PROOF) : 32 bytes.

Client online processing:

+ H = BLAKE2(CP, CN, EP, SP, SN) : 64 bytes.
+ h = H (mod q) with Snowshoe; q is a Snowshoe parameter.
+ Validate that h != 0.
+ d = h * CS (mod q) with Snowshoe.
+ Validate in constant-time that d != 0.
+ T'(X,Y) = CS * EP + d * SP with Snowshoe.
+ k' = BLAKE2(H, T') : 64 bytes.
+ Session key is the low 32 bytes of k'.
+ Verify the high 32 bytes of k' matches PROOF.

Both parties now have a public key.
The server has been authenticated by the client.

#### Discussion of Performance

Not only is Tabby optimally short (one round), it also is exceptionally efficient.

##### Server Cost of Tabby

The server only periodically needs to generate new keys, so the cost of running
the protocol for the server is just one EC-DH operation `e*SP` for each
connection.  Generating nonces and other operations account for less than 5%
overhead on the EC-DH operation.

##### Client Cost of Tabby

The client needs to generate a key, which takes roughly half the time of the
server EC-DH operation, for its first message to the server.

The client needs to perform `CS*SP + d*EP` in constant time for processing the
server response.  Snowshoe is the only library available online that provides
the capability to do it at this time.  In practice this takes about 1.5x the
time of the server's EC-DH operation.

So overall the client has to do about 2x the processing of the server.

#### Comparison to Signcryption

Signcryption would have the server sign an ephemeral key periodically, which
would require two key generations.  This is twice the work required for Tabby,
though it is not in a critical path.

When the server handles a connection, it only has to do normal EC-DH, which is
the same as Tabby's cost also.  So in general signcryption has about the same
cost as Tabby for the server side.

The client still needs to generate a public key, so that cost is the same as
Tabby.

When the client receives the signcryption ephemeral key and the signature, it
has to verify the signature and then perform EC-DH on the ephemeral key.
Verifying a signature takes roughly 1.2x an EC-DH operation.  So overall the
client has to perform 2.7x EC-DH operations for signcryption with similar small
operations, so it is 35% less efficient.

The other place where signcryption is worse is in security properties.  Tabby
only shares two random numbers (CN, SN) and two public keys (CP, EP) in the
clear.  Signcryption shares a linear combination of all the secret keys in the
clear in order to produce a signature.  This scary process has been subject to
attack when implementation flaws exist.  The "attack surface" of Tabby is thus
much smaller.

There is also the issue of ephemeral key lifetime.  Once a signature is made it
can be verified forever, unless a timestamp is attached.  This means any attacker
can pretend to be the server if he knows the private key for any ephemeral key.
On the other hand, handshakes with Tabby are tied to the long-term private key
of the server in addition to the ephemeral key, so this type of impersonation
attack is impossible.

#### TODO

+ References
+ Read through code again and look for bugs
+ Analyze the protocol to make sure it is solid

