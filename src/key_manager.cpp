#include "key_manager.h"
#include <unistd.h>
#include <thread>

namespace	oi
{

KeyManager::KeyManager(int size): m_size(size)
{
	std::uniform_int_distribution<int> d(1, P-1);
	m_keys.reserve(size); m_pool.reserve(size);
	for (int i=0; i<size; i++)
	{
		int x = d(m_e);
		while (m_pool.count(powr(x))) x = d(m_e);
		m_keys.push_back(x);
		m_pool[powr(x)] = i;
	}
	m_thread = std::thread([this](){refresher();});
}

int	KeyManager::dispatch_readonly()
{
	std::uniform_int_distribution<int> d(0, m_size - 1);
	m_mutex.lock();
	int x = m_keys[d(m_e)];
	m_mutex.unlock();
	return x;
}

int	KeyManager::lookup_and_remove(int powrkey)
{
	std::uniform_int_distribution<int> d(1, P-1);
	int x;
	m_mutex.lock();
	if (m_pool.count(powrkey))
	{
		int pos = m_pool[powrkey];
		m_pool.erase(powrkey);
		x = m_keys[pos];
		int y = d(m_e);
		while (m_pool.count(powr(y))) y = d(m_e);
		m_keys[pos] = y;
		m_pool[powr(y)] = pos;
	}
	else x = 0;
	m_mutex.unlock();
	return x;
}

void	KeyManager::refresher()
{
	std::uniform_int_distribution<int> d0(0, m_size-1);
	std::uniform_int_distribution<int> d1(1, P-1);
	while (1)
	{
		sleep(REFRESH_SECOND);
		m_mutex.lock();
		for (int i=0; i<REFRESH_NUM; i++)
		{
			int pos = d0(m_e);
			int x = m_keys[pos];
			m_pool.erase(powr(x));
			int y = d1(m_e);
			while (m_pool.count(powr(y))) y = d1(m_e);
			m_keys[pos] = y;
			m_pool[powr(y)] = pos;
		}
		m_mutex.unlock();
	}
}

}	// end namespace oi
