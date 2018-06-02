/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This file system mirrors the existing file system hierarchy of the
 * system, starting at the root file system. This is implemented by
 * just "passing through" all requests to the corresponding user-space
 * libc functions. Its performance is terrible.
 *
 * Compile with
 *
 *     gcc -Wall passthrough.c `pkg-config fuse3 --cflags --libs` -o passthrough
 *
 * ## Source code ##
 * \include passthrough.c
 */


#define FUSE_USE_VERSION 31

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdlib.h>
#include <time.h>


typedef	long long	ll;

const	int	P = 0x78000001;
const	int	R = 31;

static  inline	int	powr2(int x, int base)
{
	ll s = (x & 1 ? base : 1), t = base;
	while (x >>= 1)
	{
		t = (t * t) % P;
		if (x & 1) s = (s * t) % P;
	}
	return s;
}
static  inline  int powr(int x) {return powr2(x, R);}

const   char    server_addr_str[] = "120.25.160.91";
const   char    my_fuse_path[] = "/.myfuse/";
const	unsigned	short	port0 = 0XCAFE, port1 = 0xFACE;
const	int	MAGIC0 = 0xCAFE0002;
const	int	MAGIC1 = 0xFACE0002;
const	int	MAGIC2 = 0x90290002;
const	int	MAGIC3 = 0x92090002;
const	int	TIMEOUT_SEC = 5;
const	int	BASE_LENGTH = 4;
const	int	CAP_LENGTH = 1000;
const	int	DEF_TIMES = 10;

static  inline  void myseed(void) {srand48(time(0));}
static  inline  int myrand(void) {return lrand48();}

struct MyGlobalConnStorage
{
    struct sockaddr_in serv_addr0, serv_addr1;
    int connfd0, connfd1;
}   global_conn_storage;

static int	request_token(void)
{
    int connfd = global_conn_storage.connfd0;
    struct sockaddr_in serv_addr = global_conn_storage.serv_addr0;
	char buf[20];

	struct sockaddr_storage scapegoat;
	socklen_t scapelen;
	while (1)
	{
        int k0 = myrand() % (P - 1) + 1, k1 = myrand() % (P - 1) + 1;
		int c0 = powr(k0), c1 = powr(k1);
		
		*(int*)buf = htonl(MAGIC0);
		*(int*)(buf + 4) = htonl(c0);
		*(int*)(buf + 8) = htonl(c1);
		*(int*)(buf + 12) = htonl(c0 ^ c1);

		int ret = sendto(connfd, buf, 16, 0, (struct sockaddr*)&serv_addr, sizeof(struct sockaddr_in));
		if (ret != 16) continue;

		for (int def_t=0; def_t < DEF_TIMES; def_t++)
		{
			ret = recvfrom(connfd, buf, 16, 0, (struct sockaddr*)&scapegoat, &scapelen);
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
			int x = powr2(k0, c2) ^ c3;
			if (x != (powr2(k1, c2) ^ v1)) continue;

			return x;
		}
	}
}

static int	query_with_token(int x, int q0, int q1, int st, int ed, char *res)
{
    int connfd = global_conn_storage.connfd1;
    struct sockaddr_in serv_addr = global_conn_storage.serv_addr1;

	struct sockaddr_storage scapegoat;
	socklen_t scapelen;

	char	keys[CAP_LENGTH];
    char    buf[1040];

	int k2 = myrand() % (P - 1) + 1, px = powr(x), pk2 = powr(k2), op = 0;
    int chksum = op ^ px ^ q0 ^ q1 ^ st ^ ed ^ pk2;

	*(int*)buf = htonl(MAGIC2);
	*(int*)(buf + 4) = htonl(px);
	*(int*)(buf + 8) = htonl(pk2);
	*(int*)(buf + 12) = htonl(q0);
	*(int*)(buf + 16) = htonl(q1);
	*(int*)(buf + 20) = htonl(op);
	*(int*)(buf + 24) = htonl(st);
	*(int*)(buf + 28) = htonl(ed);

	for (int i=st, p=0; i<ed; i++, p++)
	{
		keys[p] = myrand() & 255;
		buf[36 + p] = keys[p] ^ (x & 255);
	}

	memset(buf + 36 + ed - st, 0, 4);

	for (int i=st; i<ed; i+=4) chksum ^= ntohl(*(int*)(buf + i - st + 36));
	*(int*)(buf + 32) = htonl(chksum);
	
	int ret = sendto(connfd, buf, ed - st + 36, 0, (struct sockaddr*)&serv_addr, sizeof(struct sockaddr_in));
	if (ret != ed - st + 36) return 0;

	int v1 = powr2(x, pk2);

	for (int def_t=0; def_t < DEF_TIMES; def_t++)
	{
		ret = recvfrom(connfd, buf, ed - st + 12, 0, (struct sockaddr*)&scapegoat, &scapelen);
		if (ret == -EAGAIN) break;
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
			res[p] = buf[p + 12] ^ keys[p];

		return ed - st;
	}
	return 0;
}

static int	write_with_token(int x, int q0, int q1, int st, int ed, char const*data)
{
    int connfd = global_conn_storage.connfd1;
    struct sockaddr_in serv_addr = global_conn_storage.serv_addr1;

	struct sockaddr_storage scapegoat;
	socklen_t scapelen;

    char    buf[1040];

	int k2 = myrand() % (P - 1) + 1, px = powr(x), pk2 = powr(k2), op = 1;
    int chksum = op ^ px ^ q0 ^ q1 ^ st ^ ed ^ pk2;

	*(int*)buf = htonl(MAGIC2);
	*(int*)(buf + 4) = htonl(px);
	*(int*)(buf + 8) = htonl(pk2);
	*(int*)(buf + 12) = htonl(q0);
	*(int*)(buf + 16) = htonl(q1);
	*(int*)(buf + 20) = htonl(op);
	*(int*)(buf + 24) = htonl(st);
	*(int*)(buf + 28) = htonl(ed);

	for (int i=st, p=0; i<ed; i++, p++)
	{
		buf[36 + p] = data[p] ^ (x & 255);
	}

	memset(buf + 36 + ed - st, 0, 4);

	for (int i=st; i<ed; i+=4) chksum ^= ntohl(*(int*)(buf + i - st + 36));
	*(int*)(buf + 32) = htonl(chksum);
	
	int ret = sendto(connfd, buf, ed - st + 36, 0, (struct sockaddr*)&serv_addr, sizeof(struct sockaddr_in));
	if (ret != ed - st + 36) return 0;

	int v1 = powr2(x, pk2);

	for (int def_t=0; def_t < DEF_TIMES; def_t++)
	{
		ret = recvfrom(connfd, buf, 12, 0, (struct sockaddr*)&scapegoat, &scapelen);
		if (ret == -EAGAIN) break;
		if (ret != 12) continue;

		/*
		if (scapegoat.ss_family != AF_INET) continue;

		sockaddr_in& t = *(sockaddr_in*)&scapegoat;
		if (t.sin_addr.s_addr != serv_addr.sin_addr.s_addr ||
				t.sin_port != serv_addr.sin_port) continue;
		*/

		if (ntohl(*(int*)buf) != MAGIC3) continue;
		if (ntohl(*(int*)(buf + 4)) != v1) continue;
        
        //We can verify checksum here, but it's not necessary.

		return ed - st;
	}
	return 0;
}

static int myread(int q0, int q1, char* buf, int size, int offset)
{
    int length = BASE_LENGTH;
    int now = 0;

    while (now < size)
    {
	    printf("R: %d %d %d\n", now, size, offset);
        if (length > size - now) length = size - now;
        int x = request_token();
        if (query_with_token(x, q0, q1, offset + now, offset + now + length, buf + now) == length)
        {
            now += length;
            length <<= 1;
            if (length > CAP_LENGTH) length = CAP_LENGTH;
        }
        else length = BASE_LENGTH;
    }
    return now;
}

static int mywrite(int q0, int q1, char const* buf, int size, int offset)
{
    int length = BASE_LENGTH;
    int now = 0;

    while (now < size)
    {
	    printf("W: %d %d %d\n", now, size, offset);
        if (length > size - now) length = size - now;
        int x = request_token();
        if (write_with_token(x, q0, q1, offset + now, offset + now + length, buf + now) == length)
        {
            now += length;
            length <<= 1;
            if (length > CAP_LENGTH) length = CAP_LENGTH;
        }
        else length = BASE_LENGTH;
    }
    return now;
}

static char* packpath(const char* path)
{
    int l1 = strlen(getenv("HOME")), l2 = strlen(my_fuse_path), l3 = strlen(path);
    char *buf = malloc(l1 + l2 + l3 + 1);
    memcpy(buf, getenv("HOME"), l1);
    memcpy(buf + l1, my_fuse_path, l2);
    memcpy(buf + l1 + l2, path, l3);
    buf[l1 + l2 + l3] = 0;
    return buf;
}


static void *xmp_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
{
	(void) conn;
	cfg->use_ino = 1;

	/* Pick up changes from lower filesystem right away. This is
	   also necessary for better hardlink support. When the kernel
	   calls the unlink() handler, it does not know the inode of
	   the to-be-removed entry and can therefore not invalidate
	   the cache of the associated inode - resulting in an
	   incorrect st_nlink value being reported for any remaining
	   hardlinks to this inode. */
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;

	return NULL;
}

static void *pack_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
{
	mkdir(packpath(""), 0755);

    myseed();

	struct sockaddr_in serv_addr0;
	struct sockaddr_in serv_addr1;

	inet_pton(AF_INET, server_addr_str, &serv_addr0.sin_addr);

	serv_addr0.sin_family = AF_INET;
	serv_addr0.sin_port = htons(port0);
	serv_addr1 = serv_addr0;
	serv_addr1.sin_port = htons(port1);

    int connfd0, connfd1;
	connfd0 = socket(PF_INET, SOCK_DGRAM, 0);
	connfd1 = socket(PF_INET, SOCK_DGRAM, 0);

	struct timeval tv;
	tv.tv_sec = TIMEOUT_SEC;
	tv.tv_usec = 0;
	setsockopt(connfd0, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
	setsockopt(connfd0, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
	setsockopt(connfd1, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
	setsockopt(connfd1, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    global_conn_storage.serv_addr0 = serv_addr0;
    global_conn_storage.serv_addr1 = serv_addr1;
    global_conn_storage.connfd0 = connfd0;
    global_conn_storage.connfd1 = connfd1;

    return xmp_init(conn, cfg);
}

static int modified_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

    if (S_ISREG(stbuf->st_mode))
    {
        res = open(path, O_RDWR | O_CREAT, 0755);
        if (res == -1)
            return -errno;

        int data[3];
        if (pread(res, (void*)data, 12, 0) != 12)
            return -errno;

        stbuf->st_size = data[2];
    }

	return 0;
}

static int pack_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
    char* ppath = packpath(path);
    int ret = modified_getattr(ppath, stbuf, fi);
    free(ppath);
    return ret;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
		       enum fuse_readdir_flags flags)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	(void) flags;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int pack_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
		       enum fuse_readdir_flags flags)
{
    char* ppath = packpath(path);
    int ret = xmp_readdir(ppath, buf, filler, offset, fi, flags);
    free(ppath);
    return ret;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int pack_mkdir(const char *path, mode_t mode)
{
    char* ppath = packpath(path);
    int ret = xmp_mkdir(ppath, mode);
    free(ppath);
    return ret;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int pack_rmdir(const char *path)
{
    char* ppath = packpath(path);
    int ret = xmp_rmdir(ppath);
    free(ppath);
    return ret;
}

static int xmp_rename(const char *from, const char *to, unsigned int flags)
{
	int res;

	if (flags)
		return -EINVAL;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int pack_rename(const char *from, const char *to, unsigned int flags)
{
    char *pfrom = packpath(from), *pto = packpath(to);
    int ret = xmp_rename(pfrom, pto, flags);
    free(pfrom); free(pto);
    return ret;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int pack_unlink(const char *path)
{
    char* ppath = packpath(path);
    int ret = xmp_unlink(ppath);
    free(ppath);
    return ret;
}

static int modified_create(const char *path, mode_t mode,
		      struct fuse_file_info *fi)
{
	int res;

	res = open(path, O_RDWR | O_CREAT | O_TRUNC, mode);
	if (res == -1)
		return -errno;

    int data[3]; data[0] = myrand(); data[1] = myrand(); data[2] = 0;
    if (pwrite(res, (void*)data, 12, 0) == -1)
        return -errno;

    if (!fi)
	    close(res);
    else
        fi->fh = res;
	return 0;
}

static int pack_create(const char *path, mode_t mode,
		      struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_create(ppath, mode, fi);
    free(ppath);
    return ret;
}

static int modified_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	res = open(path, O_RDWR | O_CREAT, 0755);
	if (res == -1)
		return -errno;

    int data[3];
    if (pread(res, (void*)data, 12, 0) != 12)
    {
        close(res);
        res = open(path, O_RDWR | O_TRUNC, 0755);
	    if (res == -1)
		    return -errno;

        data[0] = myrand(); data[1] = myrand(); data[2] = 0;
        if (pwrite(res, (void*)data, 12, 0) != 12)
        {
            return -errno;
        }
    }

    if (fi->flags & O_TRUNC)
    {
        data[2] = 0;
        if (pwrite(res, (void*)data, 12, 0) != 12)
        {
            return -errno;
        }
    }

    if (fi)
        fi->fh = res;
    else
        close(res);

	return 0;
}

static int pack_open(const char *path, struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_open(ppath, fi);
    free(ppath);
    return ret;
}

static int modified_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

    if (!fi)
	    fd = open(path, O_RDWR);
    else
        fd = fi->fh;
	
	if (fd == -1)
		return -errno;

    int data[3];
    if (pread(fd, (void*)data, 12, 0) == -1)
        return -errno;

    if (offset > data[2])
        return 0;

    if (offset + size > data[2])
        size = data[2] - offset;

	res = myread(data[0], data[1], buf, size, offset);

    if (!fi)
    	close(fd);

    if (size + offset > data[2])
        return data[2] - size;

	return res;
}

static int pack_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_read(ppath, buf, size, offset, fi);
    free(ppath);
    return ret;
}

static int modified_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
    if (!fi)
	    fd = open(path, O_RDWR);
    else
        fd = fi->fh;
	
	if (fd == -1)
		return -errno;

    int data[3];
    if (pread(fd, (void*)data, 12, 0) == -1)
        return -errno;

    if (size + offset > data[2])
    {
        data[2] = size + offset;
        if (pwrite(fd, (void*)data, 12, 0) == -1)
            return -errno;
    }

	res = mywrite(data[0], data[1], buf, size, offset);

    if (!fi)
	    close(fd);

	return res;
}

static int pack_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_write(ppath, buf, size, offset, fi);
    free(ppath);
    return ret;
}

static int modified_truncate(const char *path, off_t offset,
             struct fuse_file_info *fi)
{
	int fd;

	(void) fi;
    if (!fi)
	    fd = open(path, O_RDWR);
    else
        fd = fi->fh;
	
	if (fd == -1)
		return -errno;

    int data[3];
    if (pread(fd, (void*)data, 12, 0) == -1)
        return -errno;

    if (offset != data[2])
    {
        data[2] = offset;
        if (pwrite(fd, (void*)data, 12, 0) == -1)
            return -errno;
    }

    if (!fi)
	    close(fd);

	return 0;
}

static int pack_truncate(const char *path, off_t offset,
             struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = modified_truncate(ppath, offset, fi);
    free(ppath);
    return ret;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	close(fi->fh);
	return 0;
}

static int pack_release(const char *path, struct fuse_file_info *fi)
{
    char * ppath = packpath(path);
    int ret = xmp_release(ppath, fi);
    free(ppath);
    return ret;
}

static struct fuse_operations xmp_oper = {
	.init       = pack_init,
	.getattr	= pack_getattr,
	.readdir	= pack_readdir,
	.mkdir		= pack_mkdir,
	.rmdir		= pack_rmdir,
	.rename		= pack_rename,
    .unlink     = pack_unlink,
	.open		= pack_open,
	.create 	= pack_create,
	.read		= pack_read,
	.write		= pack_write,
    .truncate   = pack_truncate,
    .release    = pack_release
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
