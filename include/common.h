#pragma once

namespace	oi
{

typedef	long long	ll;

const	int	P = 0x78000001;
const	int	R = 31;

inline	int	powr(int x, int base = R)
{
	ll s = (x & 1 ? base : 1), t = base;
	while (x >>= 1)
	{
		t = (t * t) % P;
		if (x & 1) s = (s * t) % P;
	}
	return s;
}

}	// end namespace oi
