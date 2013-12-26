# Tabby
#### Strong, Fast, and Portable Cryptographic Signatures and Handshakes

The Tabby key agreement protocol is designed for the situation where a client
is attempting to connect to a server it has not connected to before.  After the
protocol completes, a 256-bit secret key is shared by both parties.  The server
has also been authenticated by the client.  Perfect forward secrecy is provided,
in that after the server changes its ephemeral key, all previous connections
cannot be decrypted if the server's long-term secret key is leaked somehow.
It is a one-round protocol that runs faster than signcryption-based approaches,
while exposing less sensitive information.  Tabby has a "128-bit" security level.

Tabby also provides signatures based on the efficient EdDSA approach.

Tabby uses the [Snowshoe](https://github.com/catid/snowshoe/) elliptic curve
math library, and it also uses the [Cymric](https://github.com/catid/cymric/)
secure random number generator library.  Please refer to those repositories for
more information about the underlying math and software implementation.


#### Usage

The [header file](https://github.com/catid/tabby/blob/master/include/tabby.h)
provides helpful usage information.

##### Building: Mac

To build the static library, install command-line Xcode tools and simply run the make script:

~~~
make test
~~~

This produces `libtabby.a` with optimizations, and it also runs the unit tester.

##### Example Usage: EC-DH with Forward Secrecy

Link to the Tabby static library `/bin/libtabby.a` (-ltabby)
and include the `./include/tabby.h` header.

Verify binary API compatibility on startup:

~~~
	if (tabby_init()) {
		throw "Buildtime failure: Wrong tabby static library";
	}
~~~

The server side will need to set up a `tabby_server` object, either by generating
a new key pair, or by loading an existing one.  Most commonly the server will be
loading an existing long-term key pair, since the clients that connect will need
to know it ahead of time.

To generate a new server long-term private/public key pair:

~~~
	tabby_server s;
	char public_key[64];
	char private_key[64];

	// Generate a Tabby server object
	if (tabby_server_gen(&s, 0, 0)) {
		return false;
	}

	// Read the public key
	if (tabby_server_get_public_key(&s, public_key)) {
		return false;
	}

	// Read the private key
	if (tabby_server_save_secret(&s, private_key)) {
		return false;
	}

	// Write private key/public key to disk here

	// Always erase sensitive information when done
	tabby_erase(private_key, sizeof(private_key));
	tabby_erase(&s, sizeof(s));
~~~

To reload a server private key:

~~~
	char private_key[64];
	tabby_server s;

	// Read private key from disk here

	if (tabby_server_load_secret(&s, 0, 0, private_key)) {
		return false;
	}
~~~

Now the server is ready to handle connections.  To start a connection,
the client side will need to create a `tabby_client` object.

To create a Tabby client object:

~~~
	tabby_client c;
	char client_request[96];

	if (tabby_client_gen(&c, 0, 0, client_request)) {
		return false;
	}
~~~

This generates the 96 byte `client_request` message that is sent to the server.

To process the client's request on the server:

~~~
	char server_response[128];
	char server_secret_key[32];

	if (tabby_server_handshake(&s, client_request, server_response, server_secret_key)) {
		// Ignore client request message
		return false;
	}
~~~

The server will either reject the request if the function returns non-zero, or the server
will respond with a 128 byte `server_response` message to the client and fill the
`server_secret_key` with the session key shared with the client.

If the client never receives the server's response, it may retry.  So a UDP server should
be able to retransmit the response rather than creating a second connection.

When the client eventually receives the response, it can validate the response and also
calculate the same secret key:

~~~
	char client_secret_key[32];

	if (tabby_client_handshake(&c, public_key, server_response, client_secret_key)) {
		// Ignore server response message
		return false;
	}
~~~

The client will either reject the response if the function returns non-zero, or the client
will have established a 32 byte secret key shared with the server.  This can be used to
set up authenticated encryption with e.g. [Calico](https://github.com/catid/calico).

Periodically the server should rekey.  After each rekeying, all connections made with the
previous key will be protected in the event that the server is compromised and its long-
term secret key is divulged.

To rekey the server, the rekey function should be run from a separate thread periodically:

~~~
	int my_thread_func(tabby_server *s) {
		// Every 30 seconds or until terminated,
		while (my_wait(30000)) {
			// Rekey the server
			tabby_server_rekey(s, 0, 0); // safe to ignore failures
		}
	}
~~~

##### Example Usage: Signatures

The signature API is described in full in the [header file](https://github.com/catid/tabby/blob/master/include/tabby.h).

And there is also an example of signatures in the [unit tester](https://github.com/catid/tabby/blob/master/tests/tabby_test.cpp).


#### Benchmarks

The following measurements show normal walltime with Turbo Boost on, and median
cycles with Turbo Boost off.  The measurements were taken over 10,000 samples
for each configuration, unless otherwise noted.

##### libtabby.a on Macbook Air (1.7 GHz Core i5-2557M Sandy Bridge, July 2011):

Key generation:

+ Successfully created a new server key in `347400` cycles, `167` usec (one sample)
+ Generated a client key in `176308` cycles, `79` usec (one sample)
+ Periodic server rekey in `178284` cycles, `72` usec (one sample)

Signatures:

+ Tabby sign: `69544` median cycles, `26.0792` avg usec
+ Tabby verify signature: `161296` median cycles, `60.1556` avg usec

One-round EC-DH with forward secrecy:

+ Tabby server handshake: `143984` median cycles, `53.8635` avg usec (`18565` connections/second)
+ Tabby client handshake: `206192` median cycles, `77.11` avg usec

Each of these operations takes roughly 2.5 usec longer than the Snowshoe math
routines they are based on.  Where applicable, these operations do full input
validation, use good random number sources, run in constant time, and clean
up the stack to avoid leaking sensitive information.

In general these results are the best for any public domain library at this time.


#### Tabby Key Generation Process : Algorithm 1

To produce private/public key pairs for Tabby, the following process is performed:

+ Step 1: Seed Cymric.
+ Step 2: Use Cymric to generate a 512-bit random number R : 64 bytes.
+ Step 3: Calculate S = R mod q using Snowshoe : 32 bytes.
+ Step 4: Check if S == 0 in constant-time; if so start over at step 2.
+ Step 5: Calculate P = S * G using Snowshoe : 64 bytes.

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
+ T(X,Y) = e * CP with Snowshoe.
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
+ Validate in constant-time that T.X != 0.
+ k' = BLAKE2(H, T') : 64 bytes.
+ Session key is the low 32 bytes of k'.
+ Verify the high 32 bytes of k' matches PROOF.

At this end of this protocol, both parties now have a shared 256-bit secret key
and the server has been authenticated by the client.

#### Performance Discussion

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

So overall the client has to do about 2x the online processing of the server.

#### Protocol Rationale

Since the client does not need to authenticate itself during the protocol,
it is easier to implement and simpler to analyze than e.g. FHMQV.  As a result
Tabby also offers deniability, in that no client authentication is performed in
the clear (nor at all): All of the client's public information is randomly
generated for each new connection.  So there is nothing to indicate WHICH client
is making the request in reality.

The client generates a new CP and CN for each connection, which makes the
public information hash H of CP, CN, EP, SP, and SN difficult to control by
a MitM or malicious server.

Since the client generates a new key for each session, forward secrecy is not
dependent on a client long-term key.

All operations involving secret information (keys, points, etc) are performed
in constant-time with regular execution and memory access patterns.  This
prevents leaking the information through an execution time or cache access time
side-channel [4].

However Tabby is still vulnerable to SPA attacks, since Snowshoe does not
have protection against SPA attacks in constructing its mask for table lookup.

Client sends to server:

+ Client public key (CP) : 64 bytes.
+ Client nonce (CN) : 32 bytes.

Server online processing:

A client is able to provide invalid CP of order 4q.  The private point T is
multiplied by 4, which prevents this potential subgroup attack.  Other invalid
points such as X=0 or points not on the curve are rejected up front.

The server generates a new ephemeral key periodically, which is effectively added
to the secret point T.  This provides forward secrecy in that once the ephemeral
key is erased, a server compromise will not allow the secret session key k for
old sessions to be discovered.

The server generates a new SN for each connection, which defeats any attempts to
replay a previous client request to create a new connection with the same key, and
also prevents a malicious client from controlling the value of H.

The 512-bit public information hash H is reduced modulo q, which makes the result
uniformly distributed over 0..q-1.  And its exceptional value 0 is avoided by
generating a new SN.

The expression `e = SS * h + ES (mod q)` is widely considered safe to share, as
it is the same one used for Schnorr signatures.  Since SS, h, and ES are all
values uniformly distributed in 1..q-1, the result is similarly uniformly
distributed.

The value of `e` is further protected by using it as the secret scalar for the
private point T.  The client does not have a way to reproduce `e` either, so this
is not an avenue for attack.  The value 0 is rejected during generation.

The session secret key k is generated from the private point T as well as the public
information hash H, to ensure that the public parameters are all fully incorporated
into the key.  This prevents any hypothetical attack that may rely on the group order
of point T to alias two values of SN to the same k.

The final step takes the high 32 bytes of k as the server's PROOF and uses the
low 32 bytes of k as the session secret key, which does not lead to any key
leakage since the BLAKE2 hash function is strong.

Server sends to client:

+ Server ephemeral public key (EP) : 64 bytes.
+ Server nonce (SN) : 32 bytes.
+ Server proof (PROOF) : 32 bytes.

Client online processing:

A server is able to provide invalid SP or EP of order 4q.  The private point T is
multiplied by 4, which prevents this potential subgroup attack.  The server may also
provide SP = EP, which must be considered.  Other invalid points such as X=0 or points
not on the curve are rejected up front.

The client validates that the server's SN produces an h that is nonzero, which prevents
the session secret from relying exclusively on the ephemeral keys.

From the client's perspective, the secret point T is just the sum of two secret points,
`CS * EP`, and `h*CS * SP`.  For speed they are calculated simultaneously.  The server
has no control over CS and little control over h, while the client has no control over
EP nor h.

If `SP = EP`, the resulting `T = (1+h)*CS * SP`. The multiplication by `1+h` is problematic
if `h = q-1`, which may be possible since the server has control over the value H.  In this
case T would be the X=0 point, and an attacker could impersonate a server.  Or in general
EP may be chosen as a known multiple of SP.  The main defense against this attack is that
finding a hash by trial-and-error such that H evenly divides q would take roughly q/2 attempts
or ~2^251 attempts, and the attack has to be performed online since the client chooses a new
nonce for each connection.  This is much harder than solving Snowshoe's ECDLP, and it has the
added disadvantage of needing to be performed online, so this is not a realistic attack.

As further protection against this sort of attack, T.X is verified in constant-time to be
non-zero, which should not be possible since the server cannot arrive at this value.  Any of
the remaining points would involve the client's value of CS and would require a malicious
server to actually know its private key to generate a valid PROOF.

The client finally verifies that the server's PROOF matches.  This proves that the server
possesses its long-term private key and the client just established a connection with the
real server.  Since all of the public information has been rolled into the PROOF through
the public information hash H, this proves that:

+ (1) the server's transmitted information came from the real server and
+ (2) that this specific client's request is the one that the real server responded to.


#### Security Claims

Tabby has a few unusually nice security properties that are enumerated here.

The goal of the Tabby protocol is to perform an EC-DH key agreement, provide perfect
forward secrecy, authenticate the server, be robust to KCI attacks, and provide
deniability for the client at a "128-bit" security level.

I make no attempt to achieve "provable security" here.  These are merely claims of security
with rough proofs.  It's way out of my depth since I am not an academic anymore.  Instead
I claim practical security against realistic attacks against Tabby specifically with the
Snowshoe group math.

##### "128-bit" Security Level

The idea of using a number of bits to refer to the level of security offered by a
cryptosystem is a little unrealistic as described in [2].  However the work required to
break Tabby in any sense should be the same as brute-forcing a 256-bit hash, which would
take roughly 2^128 trials on average.  This is where "128 bits" comes from.

In truth Tabby provides more like "126 bits" of security, since the Snowshoe library uses
a 252-bit group order.  All the other design choices are at a "128 bit" security level.

##### Resilience to Key Compromise Impersonation

KCI (Key Compromise Impersonation) attacks are passive attacks where the server's long-term
secret key SS has been compromised.  With the knowledge of SS it is possible for an active
MitM attack against new connections.  However, KCI refers to passive attacks where the
attacker only observes the new connections.

In this case Tabby has resilience to KCI, because the server picks an ephemeral key pair
and uses it intimately in the derivation of the session key.  Since a passive attacker
has no access to this ephemeral secret, the sessions are still secure.  The detailed
reasoning is similar to [1].

##### Deniability

Deniability [3] refers to the ability for a client to deny that it sent a message.  This
is a little out of the scope of handshakes, but can be an issue if the handshake includes
authentication of the client.  Since Tabby leaves out client authentication, and expects
it to be performed in the secrecy of the secure tunnel established after the handshake,
the Tabby handshake possesses the Deniability property for the client.

##### Perfect Forward Secrecy

PFS (Perfect Forward Secrecy), analyzed in depth in [1] for this sort of protocol, is
the property that after a long-term secret key SS is compromised, previous sessions with
the server cannot be decrypted.  This actually follows from KCI protection.  Since passive
attackers cannot decrypt a live session, previous sessions can definitely not be decrypted
since they are in the past and can only be passively recorded.

HMQV, for comparison, does not achieve PFS as described in [1] and [3].  Tabby, however,
does not authenticate the client and so there is no long-term reveal of the client's CS
that leads to any meaningful compromise.  Each time the client connects it uses a new CS,
so learning this key after the fact only allows that one session to be decrypted, which
is also true if all of the server's SS and ES are revealed for a session.  In theory the
client erases its secret key after each connection, so revealing CS is impossible, and
similarly the server erases its ES periodically, so revealing it is also impossible.

##### Small Attack Surface

Tabby is a library that has only the goal of providing Tabby-style signatures and handshakes
and uses Cymric and Snowshoe to achieve this purpose.  The software is as small and easy
to audit as it can be.  Furthermore, the math is fairly simple and easy to understand,
and all of the design choices support a robust and fail-safe design with full input validation
and error checking, with a simple API that is hard to mess up as a user of the library.

In terms of protocol attack surface, the public information consists of CP, CN, SP, SN, and EP.
These are all either 256-bit random numbers or opaque public keys.  For comparison, a
signcryption approach like [NaCL](http://nacl.cr.yp.to/) requires each message to include a
scary linear permutation of the long-term server secret key in the clear.  Ed25519 supposedly
prevents attacks through this parameter, but [the paper](http://ed25519.cr.yp.to/ed25519-20110926.pdf)
does admit this has been an avenue for attack in the past.  Tabby handshakes avoid this issue
entirely.

##### Resilience to Unknown Key Share

UKS (Unknown Key Share) attacks involve successfully validating the PROOF of the protocol
without knowing the long-term secret key of the server.  I claim that these are not possible.

This could be exploited if a MitM somehow managed to set the shared private key T to the
identity element by manipulating the server response.  However as discussed in an earlier
section the T.X = 0 condition is rejected on the client side on top of other protections,
which ensures that the server's SS is involved in every handshake.

This leads into replay protection in that previous session public information cannot be
used to forge a new connection since, especially, the client nonce changes each time, and
so the server's PROOF would be rejected by the client if a replay were attempted, which
would be another form of UKS attack.

##### Replay Protection

Tabby uses ephemeral nonces for each new connection on both ends of the handshake, which
makes it resilient to replay attacks.  The client will be able to detect if the server's
response is replayed because the PROOF will not match for the new CN.

Another interesting comparison is with signcryption approaches that use a signature to
tie an ephemeral key to the long-term secret key of the server.  These approaches add
a potential vulnerability in that if an ephemeral secret key is ever compromised, it is
signed forever and can be used to impersonate the server.  Tabby does not have this
complication since all handshakes are tied to ephemeral parameters.

##### Side-Channel Attack Protection

Practical side-channel attacks are a real issue these days [4] especially for cloud servers
where multiple server applications from different users are running on the same physical box.
Snowshoe uses regular execution and memory access patterns and is small so it fits in L1 cache
(which is a second layer of protection) so it is fully protected against even cache-timing
attacks.  Tabby furthermore does all operations in constant time where possible.

Another side-channel is memory usage.  Tabby and Snowshoe both attempt to wipe secret data
from the stack to avoid it leaking out.  And no dynamic memory allocation is performed by
either library, which makes memory-related security leaks harder to occur.  Buffer reuse
and other tricks are employed to achieve memory security with a minimal impact on speed.


### References

##### [1] ["HMQV: A High-Performance Secure Diffie-Hellman Protocol" (Krawczyk 2005)](http://eprint.iacr.org/2005/176.pdf)
Excellent analysis of one-round protocols similar to Tabby.

##### [2] ["Non-uniform cracks in the concrete" (Bernstein 2013)](http://cr.yp.to/nonuniform/nonuniform-20130914.pdf)
History and discussion of "actual security."

##### [3] ["Exchanging a key - how hard can it be?" (Cremers Feltz 2009)](http://www.isg.rhul.ac.uk/dusko/seminar/slides/111109-CremersC.pdf)
Nice introduction to what key exchange protocols are all about.

##### [4] ["Flush+Reload: a High Resolution, Low Noise, L3 Cache Side-Channel Attack" (Yarom Falkner 2013)](https://eprint.iacr.org/2013/448.pdf)
Modern side-channel attack discussion.


#### Credits

This software was written entirely by myself ( Christopher A. Taylor <mrcatid@gmail.com> ).  If you
find it useful and would like to buy me a coffee, consider [tipping](https://www.gittip.com/catid/).

