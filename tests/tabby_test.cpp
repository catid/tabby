#include <iostream>
#include <cassert>
#include <vector>
using namespace std;

#include "Clock.hpp"
using namespace cat;

#include "tabby.h"

static Clock m_clock;

/*
	This Quickselect routine is based on the algorithm described in
	"Numerical recipes in C", Second Edition,
	Cambridge University Press, 1992, Section 8.5, ISBN 0-521-43108-5
	This code by Nicolas Devillard - 1998. Public domain.
*/
#define ELEM_SWAP(a,b) { register u32 t=(a);(a)=(b);(b)=t; }
static u32 quick_select(u32 arr[], int n)
{
	int low, high ;
	int median;
	int middle, ll, hh;
	low = 0 ; high = n-1 ; median = (low + high) / 2;
	for (;;) {
		if (high <= low) /* One element only */
			return arr[median] ;
		if (high == low + 1) { /* Two elements only */
			if (arr[low] > arr[high])
				ELEM_SWAP(arr[low], arr[high]) ;
			return arr[median] ;
		}
		/* Find median of low, middle and high items; swap into position low */
		middle = (low + high) / 2;
		if (arr[middle] > arr[high]) ELEM_SWAP(arr[middle], arr[high]) ;
		if (arr[low] > arr[high]) ELEM_SWAP(arr[low], arr[high]) ;
		if (arr[middle] > arr[low]) ELEM_SWAP(arr[middle], arr[low]) ;
		/* Swap low item (now in position middle) into position (low+1) */
		ELEM_SWAP(arr[middle], arr[low+1]) ;
		/* Nibble from each end towards middle, swapping items when stuck */
		ll = low + 1;
		hh = high;
		for (;;) {
			do ll++; while (arr[low] > arr[ll]) ;
			do hh--; while (arr[hh] > arr[low]) ;
			if (hh < ll)
				break;
			ELEM_SWAP(arr[ll], arr[hh]) ;
		}
		/* Swap middle item (in position low) back into correct position */
		ELEM_SWAP(arr[low], arr[hh]) ;
		/* Re-set active partition */
		if (hh <= median)
			low = ll;
		if (hh >= median)
			high = hh - 1;
	}
}
#undef ELEM_SWAP

static void tscTime() {
	const u32 c0 = Clock::cycles();
	const double t0 = m_clock.usec();
	const double t_end = t0 + 1000000.0;

	double t;
	u32 c;
	do {
		c = Clock::cycles();
		t = m_clock.usec();
	} while (t < t_end);

	cout << "RDTSC instruction runs at " << (c - c0)/(t - t0)/1000.0 << " GHz" << endl;
}



int main() {
	cout << "Tabby Tester" << endl;

	m_clock.OnInitialize();

	// Initialize Tabby API:

	assert(tabby_init() == 0);

	tscTime();

	// Initialize server offline:

	cout << "Generating a 256-bit entropy server key..." << endl;

	tabby_server s;
	char public_key[64];

	double t0 = m_clock.usec();
	u32 c0 = Clock::cycles();

	assert(0 == tabby_server_gen(&s, 0, 0));

	u32 c1 = Clock::cycles();
	double t1 = m_clock.usec();

	assert(0 == tabby_server_get_public_key(&s, public_key));

	cout << "+ Successfully created a new server key in " << (c1 - c0) << " cycles, " << (t1 - t0) << " usec (one sample)" << endl;

	// Signature test:

	vector<u32> tsi, tva, tvr;
	double wsi = 0, wva = 0, wvr = 0;

	for (int ii = 0; ii < 10000; ++ii) {
		char signature[96];
		char message[64];
		const int message_bytes = 64;

		for (int jj = 0; jj < message_bytes; ++jj) {
			message[jj] = (char)ii;
		}

		t0 = m_clock.usec();
		c0 = Clock::cycles();

		assert(0 == tabby_sign(&s, message, message_bytes, signature));

		c1 = Clock::cycles();
		t1 = m_clock.usec();

		tsi.push_back(c1 - c0);
		wsi += t1 - t0;

		t0 = m_clock.usec();
		c0 = Clock::cycles();

		assert(0 == tabby_verify(message, message_bytes, public_key, signature));

		c1 = Clock::cycles();
		t1 = m_clock.usec();

		tva.push_back(c1 - c0);
		wva += t1 - t0;

		// Make a corrupted message
		char message1[64];
		memcpy(message1, message, 64);
		message1[5] ^= 8;

		t0 = m_clock.usec();
		c0 = Clock::cycles();

		assert(0 != tabby_verify(message1, message_bytes, public_key, signature));

		c1 = Clock::cycles();
		t1 = m_clock.usec();

		tvr.push_back(c1 - c0);
		wvr += t1 - t0;
	}

	u32 msi = quick_select(&tsi[0], (int)tsi.size());
	wsi /= tsi.size();
	u32 mva = quick_select(&tva[0], (int)tva.size());
	wva /= tva.size();
	u32 mvr = quick_select(&tvr[0], (int)tvr.size());
	wvr /= tvr.size();

	cout << "+ Tabby sign: `" << dec << msi << "` median cycles, `" << wsi << "` avg usec" << endl;
	cout << "+ Tabby verify signature: `" << dec << mva << "` median cycles, `" << wva << "` avg usec" << endl;
	cout << "+ Tabby reject signature: `" << dec << mvr << "` median cycles, " << wvr << "` avg usec" << endl;

	cout << "+ Signature validation test successful!" << endl;

	// Handshake test:

	cout << "Generating a 256-bit entropy client key..." << endl;

	t0 = m_clock.usec();
	c0 = Clock::cycles();

	tabby_client c;
	char client_request[96];

	assert(0 == tabby_client_gen(&c, 0, 0, client_request));

	c1 = Clock::cycles();
	t1 = m_clock.usec();

	cout << "+ Generated a client key in " << (c1 - c0) << " cycles, " << (t1 - t0) << " usec (one sample)" << endl;

	vector<u32> tr, ts, tc;
	double wr = 0, ws = 0, wc = 0;

	for (int ii = 0; ii < 10000; ++ii) {
		if (ii == 1000) {
			t0 = m_clock.usec();
			c0 = Clock::cycles();

			tabby_server_rekey(&s, 0, 0);

			c1 = Clock::cycles();
			t1 = m_clock.usec();

			cout << "+ Periodic server rekey in " << (c1 - c0) << " cycles, " << (t1 - t0) << " usec" << endl;
		}

		t0 = m_clock.usec();
		c0 = Clock::cycles();

		assert(0 == tabby_client_rekey(&c, &c, 0, 0, client_request));

		c1 = Clock::cycles();
		t1 = m_clock.usec();

		tr.push_back(c1 - c0);
		wr += t1 - t0;

		char server_response[128];
		char server_secret_key[32];

		t0 = m_clock.usec();
		c0 = Clock::cycles();

		assert(0 == tabby_server_handshake(&s, client_request, server_response, server_secret_key));

		c1 = Clock::cycles();
		t1 = m_clock.usec();

		ts.push_back(c1 - c0);
		ws += t1 - t0;

		char client_secret_key[32];

		t0 = m_clock.usec();
		c0 = Clock::cycles();

		assert(0 == tabby_client_handshake(&c, public_key, server_response, client_secret_key));

		c1 = Clock::cycles();
		t1 = m_clock.usec();

		tc.push_back(c1 - c0);
		wc += t1 - t0;

		assert(0 == memcmp(server_secret_key, client_secret_key, 32));

		tabby_erase(server_secret_key, 32);
		tabby_erase(client_secret_key, 32);
	}

	u32 mr = quick_select(&tr[0], (int)tr.size());
	wr /= tr.size();
	u32 ms = quick_select(&ts[0], (int)ts.size());
	ws /= ts.size();
	u32 mc = quick_select(&tc[0], (int)tc.size());
	wc /= tc.size();

	int cps = (int)(1000000.0 / ws);

	cout << "+ Tabby client rekey: `" << dec << mr << "` median cycles, `" << wr << "` avg usec" << endl;
	cout << "+ Tabby server handshake: `" << dec << ms << "` median cycles, `" << ws << "` avg usec (`" << cps << "` connections/second)" << endl;
	cout << "+ Tabby client handshake: `" << dec << mc << "` median cycles, `" << wc << "` avg usec" << endl;


	// Password authentication:

	const char *username = "catid";
	const char *realm = "AWESOME APP";
	const char *password = "password1";

	t0 = m_clock.usec();
	c0 = Clock::cycles();

	// Generate server database entry for user
	char password_verifier[72];
	assert(!tabby_password(&c, username, strlen(username), realm, strlen(realm), password, strlen(password), password_verifier));

	c1 = Clock::cycles();
	t1 = m_clock.usec();

	cout << "+ Client generated server verifier for password database in " << (c1 - c0) << " cycles, " << (t1 - t0) << " usec (one sample)" << endl;

	t0 = m_clock.usec();
	c0 = Clock::cycles();

	// Generate challenge message and secret
	char challenge_secret[224], challenge[72];
	assert(!tabby_password_challenge(&s, password_verifier, challenge_secret, challenge));

	c1 = Clock::cycles();
	t1 = m_clock.usec();

	cout << "+ Server password challenge generated in " << (c1 - c0) << " cycles, " << (t1 - t0) << " usec (one sample)" << endl;

	t0 = m_clock.usec();
	c0 = Clock::cycles();

	// Generate client proof and server verifier
	char server_verifier[32], client_proof[96];
	assert(!tabby_password_client_proof(&c, username, strlen(username), realm, strlen(realm), password, strlen(password), challenge, public_key, server_verifier, client_proof));

	c1 = Clock::cycles();
	t1 = m_clock.usec();

	cout << "+ Client proof of password generated in " << (c1 - c0) << " cycles, " << (t1 - t0) << " usec (one sample)" << endl;

	t0 = m_clock.usec();
	c0 = Clock::cycles();

	// Generate server proof
	char server_proof[32];
	assert(!tabby_password_server_proof(&s, client_proof, challenge_secret, server_proof));

	c1 = Clock::cycles();
	t1 = m_clock.usec();

	cout << "+ Server proof of password generated in " << (c1 - c0) << " cycles, " << (t1 - t0) << " usec (one sample)" << endl;

	t0 = m_clock.usec();
	c0 = Clock::cycles();

	// Verify server proof
	assert(!tabby_password_check_server(server_proof, server_verifier));

	c1 = Clock::cycles();
	t1 = m_clock.usec();

	cout << "+ Client checked server password proof in " << (c1 - c0) << " cycles, " << (t1 - t0) << " usec (one sample)" << endl;

	cout << "Tests succeeded!" << endl;

	// Erase sensitive data from memory
	tabby_erase(&s, sizeof(s));
	tabby_erase(&c, sizeof(c));

	m_clock.OnFinalize();

	return 0;
}

