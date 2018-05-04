#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cstdlib>
#include <cstring>
#include <cassert>

#include <mutex>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <exception>
#include <stdexcept>
#include <memory>
#include <random>

#include "key_manager.h"
#include "data_provider.h"

const	int	MAX_EPOLL_SIZE = 8000;
const	unsigned short port0 = 0xCAFE, port1 = 0xFACE;
const	int	MAGIC0 = 0xCAFE0002;
const	int	MAGIC1 = 0xFACE0002;
const	int	MAGIC2 = 0x90290002;
const	int	MAGIC3 = 0x92090002;

using	namespace	oi;

int	key_dispatch(std::shared_ptr<KeyManager> km,
		int sockfd, int epollfd)
{
	std::default_random_engine e;
	std::uniform_int_distribution<int> d(1, P-1);

	sockaddr_storage target_addr;
	socklen_t target_addr_len = sizeof(target_addr);

	epoll_event	events[MAX_EPOLL_SIZE];
	char	buf[20];
	while (1)
	{
		int num = epoll_wait(epollfd, events, MAX_EPOLL_SIZE, 0);
		if (num < 0) continue;
		for (int i=0; i<num; i++)
		{
			int fd = events[i].data.fd;
			int ret = recvfrom(fd, buf, 16, 0, (sockaddr*)&target_addr, &target_addr_len);
			if (ret != 16) continue;
			if (ntohl(*(int*)buf) != MAGIC0) continue;

			int c0 = ntohl(*(int*)(buf + 4));
			if (c0 <= 0 || c0 >= P) continue;
			int c1 = ntohl(*(int*)(buf + 8));
			if (c1 <= 0 || c1 >= P) continue;
			int v0 = ntohl(*(int*)(buf + 12));
			if (c0 ^ c1 ^ v0) continue;


			int x = km->dispatch_readonly();
			int t0 = d(e);
			*(int*)buf = htonl(MAGIC1);
			*(int*)(buf + 4) = htonl(powr(t0));
			*(int*)(buf + 8) = htonl(powr(t0, c0) ^ x);
			*(int*)(buf + 12) = htonl(powr(t0, c1) ^ x);
			ret = sendto(fd, buf, 16, 0, (sockaddr*)&target_addr, target_addr_len);
			if (ret != 16) continue;
            printf("Dispatch.\n");
		}
	}
}

int	data_transform(std::shared_ptr<KeyManager> km,
		std::shared_ptr<DataProviderBase> dp,
		int sockfd, int epollfd)
{
	sockaddr_storage target_addr;
	socklen_t target_addr_len = sizeof(target_addr);

	epoll_event	events[MAX_EPOLL_SIZE];
	char	buf[1040]; //Protocol 1000 + 36, padding + 4
	while (1)
	{
		int num = epoll_wait(epollfd, events, MAX_EPOLL_SIZE, 0);
		if (num < 0) continue;
		for (int i=0; i<num; i++)
		{
			int fd = events[i].data.fd;
			int ret = recvfrom(fd, buf, 1036, 0, (sockaddr*)&target_addr, &target_addr_len);
			if (ret < 36) continue;
			memset(buf + ret, 0, 4); // Pad the buffer by 4 for checksum verifying.

			if (ntohl(*(int*)buf) != MAGIC2) continue;
			int powrx = ntohl(*(int*)(buf + 4)), x;
			if (!(x = km->lookup_and_remove(powrx))) continue;

			int powrk2 = ntohl(*(int*)(buf + 8));
			if (powrk2 <= 0 || powrk2 >= P) continue;
			int q0 = ntohl(*(int*)(buf + 12));
			int q1 = ntohl(*(int*)(buf + 16));
            int op = ntohl(*(int*)(buf + 20));

			int arg1 = ntohl(*(int*)(buf + 24));
			int arg2 = ntohl(*(int*)(buf + 28));
			int chksum = ntohl(*(int*)(buf + 32));
			chksum ^= powrx ^ powrk2 ^ q0 ^ q1 ^ op ^ arg1 ^ arg2;
			for (int i=36; i<ret; i+=4) chksum ^= ntohl(*(int*)(buf + i));
			if (chksum)
			{
				printf("Chksum Failed.\n");
				continue;
			}

            if (op == 0) //Read
            {
                printf("Read OP.\n");
                int st = arg1, ed = arg2;
                if (st < 0) continue;
                if (ed <= st || ed - st != ret - 36) continue;

                char k = x & 255;
                int v1 = powr(x, powrk2);
                *(int*)buf = htonl(MAGIC3);
                *(int*)(buf + 4) = htonl(v1);
                chksum = v1; 
                for (int i=st; i<ed; i++) buf[i - st + 12] = buf[i - st + 44] ^ k ^ dp->get(q0, q1, i);
                memset(buf + ed - st + 12, 0, 4);
                for (int i=st; i<ed; i+=4) chksum ^= ntohl(*(int*)(buf + i - st + 12));
                *(int*)(buf + 8) = htonl(chksum);

                ret = sendto(fd, buf, ed - st + 12, 0, (sockaddr*)&target_addr, target_addr_len);
                if (ret != ed - st + 12) continue;
                
                continue;
            }

            if (op == 1) //Write
            {
                printf("Write OP.\n");
                int st = arg1, ed = arg2;
                if (st < 0) continue;
                if (ed <= st || ed - st != ret - 36) continue;

                char k = x & 255;
                int v1 = powr(x, powrk2);
                *(int*)buf = htonl(MAGIC3);
                *(int*)(buf + 4) = htonl(v1);
                chksum = v1; 
                for (int i=st; i<ed; i++) dp->set(q0, q1, i, buf[i - st + 12] = buf[i - st + 44] ^ k);
                memset(buf + ed - st + 12, 0, 4);
                for (int i=st; i<ed; i+=4) chksum ^= ntohl(*(int*)(buf + i - st + 12));
                *(int*)(buf + 8) = htonl(chksum);

                ret = sendto(fd, buf, 12, 0, (sockaddr*)&target_addr, target_addr_len);
                if (ret != 12) continue;
                
                continue;
            }
		}
	}
}

int	main()
{

	rlimit rt;
	rt.rlim_max = rt.rlim_cur = MAX_EPOLL_SIZE | 192;
	if (setrlimit(RLIMIT_NOFILE, &rt))
		throw std::runtime_error("Operation setrlimit failed.");
	
	int sockfd0 = socket(PF_INET, SOCK_DGRAM, 0);
	int sockfd1 = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd0 == -1 || sockfd1 == -1)
		throw std::runtime_error("Socket creation failed.");

	int opt = 1;
	if (setsockopt(sockfd0, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0)
		throw std::runtime_error("Set SO_REUSEADDR failed.");
	if (setsockopt(sockfd1, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0)
		throw std::runtime_error("Set SO_REUSEADDR failed.");

	if (fcntl(sockfd0, F_SETFL, fcntl(sockfd0, F_GETFD, 0) | O_NONBLOCK) < 0)
		throw std::runtime_error("Set NONBLOCK failed.");
	if (fcntl(sockfd1, F_SETFL, fcntl(sockfd1, F_GETFD, 0) | O_NONBLOCK) < 0)
		throw std::runtime_error("Set NONBLOCK failed.");

	sockaddr_in addr0, addr1;
	memset(&addr0, 0, sizeof(sockaddr_in));
	memset(&addr1, 0, sizeof(sockaddr_in));
	addr0.sin_family = addr1.sin_family = PF_INET;
	addr0.sin_port = htons(port0);
	addr1.sin_port = htons(port1);
	addr0.sin_addr.s_addr = addr1.sin_addr.s_addr = INADDR_ANY;
	if (bind(sockfd0, (sockaddr*)&addr0, sizeof(sockaddr)) < 0)
		throw std::runtime_error("Bind failed.");
	if (bind(sockfd1, (sockaddr*)&addr1, sizeof(sockaddr)) < 0)
		throw std::runtime_error("Bind failed.");

	int epollfd0 = epoll_create(MAX_EPOLL_SIZE);
	int epollfd1 = epoll_create(MAX_EPOLL_SIZE);
	epoll_event ev0, ev1;
	ev0.events = ev1.events = EPOLLIN | EPOLLET;
	ev0.data.fd = sockfd0; ev1.data.fd = sockfd1;

	if (epoll_ctl(epollfd0, EPOLL_CTL_ADD, sockfd0, &ev0) < 0)
		throw std::runtime_error("Epoll add failed.");
	if (epoll_ctl(epollfd1, EPOLL_CTL_ADD, sockfd1, &ev1) < 0)
		throw std::runtime_error("Epoll add failed.");

	std::shared_ptr<DataProviderBase> dp(new NaiveDataProvider());
	std::shared_ptr<KeyManager> km(new KeyManager());

	std::thread t1(key_dispatch, km, sockfd0, epollfd0);
	std::thread t2(data_transform, km, dp, sockfd1, epollfd1);
	
	t1.join(); t2.join();
	return 0;
}
