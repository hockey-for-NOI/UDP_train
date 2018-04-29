#include "data_provider.h"

namespace	oi
{

char	NaiveDataProvider::get(int key, int pos)
{
	return (((unsigned)key ^ (unsigned)(pos + 0xCAFEFACEu)) % 10) | 48;
}

}	// end namespace oi
