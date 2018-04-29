#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <stdexcept>
#include <random>

#include "common.h"


const	unsigned	short	port0 = 0XCAFE, port1 = 0xFACE;
const	int	MAGIC0 = 0xCAFE0001;
const	int	MAGIC1 = 0xFACE0001;
const	int	MAGIC2 = 0x90290001;
const	int	MAGIC3 = 0x92090001;
const	int	MAX_QUERY = 1000000000;
const	int	TIMEOUT_SEC = 5;
const	int	BASE_LENGTH = 4;
const	int	CAP_LENGTH = 1000;
const	int	DEF_TIMES = 10;

using namespace oi;

std::default_random_engine	e;

int	request_token(int connfd, sockaddr_in& serv_addr)
{
	std::uniform_int_distribution<int> d(1, P-1);
	char buf[20];

	sockaddr_storage scapegoat;
	socklen_t scapelen;
	while (1)
	{
		int k0 = d(e), k1 = d(e);
		int c0 = powr(k0), c1 = powr(k1);
		
		*(int*)buf = htonl(MAGIC0);
		*(int*)(buf + 4) = htonl(c0);
		*(int*)(buf + 8) = htonl(c1);
		*(int*)(buf + 12) = htonl(c0 ^ c1);

		int ret = sendto(connfd, buf, 16, 0, (sockaddr*)&serv_addr, sizeof(sockaddr_in));
		if (ret != 16) continue;

		for (int def_t=0; def_t < DEF_TIMES; def_t++)
		{
			ret = recvfrom(connfd, buf, 16, 0, (sockaddr*)&scapegoat, &scapelen);
			if (ret < 0) break;
			if (ret != 16) continue;
		/*	
			if (scapegoat.ss_family != AF_INET) continue;

			sockaddr_in& t = *(sockaddr_in*)&scapegoat;
			if (t.sin_addr.s_addr != serv_addr.sin_addr.s_addr ||
					t.sin_port != serv_addr.sin_port) continue;
		*/

			if (ntohl(*(int*)buf) != MAGIC1) continue;
			int c2 = ntohl(*(int*)(buf + 4));
			int c3 = ntohl(*(int*)(buf + 8));
			int v1 = ntohl(*(int*)(buf + 12));
			int x = powr(k0, c2) ^ c3;
			if (x != (powr(k1, c2) ^ v1)) continue;

			return x;
		}
	}
}

int	query_with_token(int x, int q, int st, int ed,
		int connfd, sockaddr_in& serv_addr, char *buf)
{
	std::uniform_int_distribution<int> d(1, P-1);
	std::uniform_int_distribution<int> keygen(0, 255);

	sockaddr_storage scapegoat;
	socklen_t scapelen;

	char	keys[CAP_LENGTH];

	int k2 = d(e), px = powr(x), pk2 = powr(k2), chksum = px ^ q ^ st ^ ed ^ pk2;

	*(int*)buf = htonl(MAGIC2);
	*(int*)(buf + 4) = htonl(px);
	*(int*)(buf + 8) = htonl(q);
	*(int*)(buf + 12) = htonl(st);
	*(int*)(buf + 16) = htonl(ed);
	*(int*)(buf + 20) = htonl(pk2);

	for (int i=st, p=0; i<ed; i++, p++)
	{
		keys[p] = keygen(e);
		buf[28 + p] = keys[p] ^ (x & 255);
	}

	memset(buf + 28 + ed - st, 0, 4);

	for (int i=st; i<ed; i+=4) chksum ^= ntohl(*(int*)(buf + i - st + 28));
	*(int*)(buf + 24) = htonl(chksum);
	
	int ret = sendto(connfd, buf, ed - st + 28, 0, (sockaddr*)&serv_addr, sizeof(sockaddr_in));
	if (ret != ed - st + 28) return 0;

	int v1 = powr(x, pk2);

	for (int def_t=0; def_t < DEF_TIMES; def_t++)
	{
		ret = recvfrom(connfd, buf, ed - st + 12, 0, (sockaddr*)&scapegoat, &scapelen);
		if (ret < 0) break;
		if (ret != ed - st + 12) continue;

		/*
		if (scapegoat.ss_family != AF_INET) continue;

		sockaddr_in& t = *(sockaddr_in*)&scapegoat;
		if (t.sin_addr.s_addr != serv_addr.sin_addr.s_addr ||
				t.sin_port != serv_addr.sin_port) continue;
		*/

		if (ntohl(*(int*)buf) != MAGIC3) continue;
		if (ntohl(*(int*)(buf + 4)) != v1) continue;

		memset(buf + ret, 0, 4);

		chksum = v1 ^ ntohl(*(int*)(buf + 8));
		for (int i=st; i<ed; i+=4) chksum ^= ntohl(*(int*)(buf + i - st + 12));
		if (chksum) continue;

		for (int i=st, p=0; i<ed; i++, p++)
			buf[p] = buf[p + 12] ^ keys[p];

		return ed - st;
	}
	return 0;
}

int	main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("Usage: %s [server address]\n", argv[0]);
		return 0;
	}

	sockaddr_in serv_addr0, serv_addr1;
	if (inet_pton(AF_INET, argv[1], &serv_addr0.sin_addr) != 1)
		throw std::runtime_error("Address cannot be recognized.");
	serv_addr0.sin_family = AF_INET;
	serv_addr0.sin_port = htons(port0);
	serv_addr1 = serv_addr0;
	serv_addr1.sin_port = htons(port1);

	int connfd0 = socket(PF_INET, SOCK_DGRAM, 0);
	int connfd1 = socket(PF_INET, SOCK_DGRAM, 0);

	timeval tv;
	tv.tv_sec = TIMEOUT_SEC;
	tv.tv_usec = 0;
	if (setsockopt(connfd0, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0)
		throw std::runtime_error("Set receive timeout failed.");
	if (setsockopt(connfd0, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) < 0)
		throw std::runtime_error("Set send timeout failed.");
	if (setsockopt(connfd1, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0)
		throw std::runtime_error("Set receive timeout failed.");
	if (setsockopt(connfd1, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) < 0)
		throw std::runtime_error("Set send timeout failed.");

	int q;
	while (1)
	{
		printf("Query = ");
		scanf("%d", &q);
		if (q <= 0)
		{
			printf("Error: negative query.");
			continue;
		}

		if (q > MAX_QUERY)
			printf("Warning: query out of range, server may not response.");

		int length = BASE_LENGTH;
		int now = 0;

		char buf[CAP_LENGTH + 32];

		while (now < q)
		{
			if (length > q - now) length = q - now;
			int x = request_token(connfd0, serv_addr0);
			if (query_with_token(x, q, now, now + length, connfd1, serv_addr1, buf) == length)
			{
				now += length;
				buf[length] = 0;
				printf("%s", buf);
				length <<= 1;
				if (length > CAP_LENGTH) length = CAP_LENGTH;
			}
			else length = BASE_LENGTH;
		}
		printf("\n");
	}
	
	return 0;
}
