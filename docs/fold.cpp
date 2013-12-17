#include <iostream>
#include <iomanip>
using namespace std;

int main() {
	cout << "Integer fold tester" << endl;

	const int p = 7919;
	int f = p;
	f |= f >> 1;
	f |= f >> 2;
	f |= f >> 4;
	f |= f >> 8;
	f |= f >> 16;
	f++;
	int m = f*f;

	int *bins = new int[p];

	for (int ii = 0; ii < p; ++ii) {
		bins[ii] = 0;
	}

	for (int ii = 0; ii < m; ++ii) {
		int n = ii % p;
		bins[n]++;
	}

	int avg = (int)(m/(double)p);

	for (int ii = 0; ii < p; ++ii) {
		cout << ii << " : " << bins[ii] << " = " << (1. - avg / (double)bins[ii]) << endl;
	}

	delete []bins;

	return 0;
}
