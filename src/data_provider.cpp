#include "data_provider.h"

namespace	oi
{

char	NaiveDataProvider::get(int q0, int q1, int pos)
{
    long long q = ((long long) q0) << 32 | q1;
    auto &entry = m_data[q];
    if (entry.size() <= pos) return 0; else return entry[pos];
}

void	NaiveDataProvider::set(int q0, int q1, int pos, char value)
{
    long long q = ((long long) q0) << 32 | q1;
    if (!m_data.count(q)) m_data[q].clear();
    auto &entry = m_data[q];
    if (pos >= entry.size()) entry.resize(pos + 1);
    entry[pos] = value;
}

}	// end namespace oi
