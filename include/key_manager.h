#pragma once

#include "common.h"

#include <unordered_map>
#include <vector>
#include <thread>
#include <random>
#include <mutex>

namespace	oi
{

class	KeyManager
{
public:
	static	const	int	DEFAULT_POOL_SIZE = 16384;
	static	const	int	REFRESH_SECOND = 1;
	static	const	int	REFRESH_NUM = 64;
	KeyManager(int size = DEFAULT_POOL_SIZE);
	int	dispatch_readonly();
	int	lookup_and_remove(int powrkey);
private:
	std::thread m_thread;
	std::mutex m_mutex;
	std::unordered_map <int, int> m_pool; 
	std::vector <int> m_keys;
	int m_size;

	std::default_random_engine m_e;
	void	refresher();
};

}	// end namespace oi
