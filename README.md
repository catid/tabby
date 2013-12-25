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

+ Successfully created a new server key in `471868` cycles, `175` usec (one sample)
+ Generated a client key in `183120` cycles, `97` usec (one sample)
+ Periodic server rekey in `173192` cycles, `76` usec (one sample)

Signatures:

+ Tabby sign: `69364` median cycles, `26.1098` avg usec
+ Tabby verify signature: `161200` median cycles, `60.5612` avg usec

One-round EC-DH with forward secrecy:

+ Tabby server handshake: `144180` median cycles, `54.2313` avg usec (`18439` connections/second)
+ Tabby client handshake: `206276` median cycles, `77.6487` avg usec

Each of these operations takes roughly 5 usec longer than the Snowshoe math
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
it is easier to implement and simpler to analyze than e.g. FHMQV.

The client generates a new CP and CN for each connection, which makes the
public information hash H of CP, CN, EP, SP, and SN difficult to control by
a MitM or malicious server.

Since the client generates a new key for each session, forward secrecy is not
dependent on a client long-term key.

All operations involving secret information (keys, points, etc) are performed
in constant-time.  This prevents leaking the information through a timing
side-channel.  However Tabby is still vulnerable to SPA attacks.

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


#### Credits

This software was written entirely by myself ( Christopher A. Taylor <mrcatid@gmail.com> ).  If you
find it useful and would like to buy me a coffee, consider [tipping](https://www.gittip.com/catid/).

