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

inline	int	powr2(int x, int base)
{
	ll s = (x & 1 ? base : 1), t = base;
	while (x >>= 1)
	{
		t = (t * t) % P;
		if (x & 1) s = (s * t) % P;
	}
	return s;
}
inline  int powr(int x) {return powr2(x, R);}

const   char    server_addr_str[] = "120.25.160.91";
const	unsigned	short	port0 = 0XCAFE, port1 = 0xFACE;
const	int	MAGIC0 = 0xCAFE0002;
const	int	MAGIC1 = 0xFACE0002;
const	int	MAGIC2 = 0x90290002;
const	int	MAGIC3 = 0x92090002;
const	int	TIMEOUT_SEC = 5;
const	int	BASE_LENGTH = 4;
const	int	CAP_LENGTH = 1000;
const	int	DEF_TIMES = 10;

inline  void myseed() {srand48(time(0));}
inline  int myrand() {return lrand48();}

struct MyGlobalConnStorage
{
    struct sockaddr_in serv_addr0, serv_addr1;
    int connfd0, connfd1;
}   global_conn_storage;

int	request_token()
{
    int connfd = global_conn_storage.connfd0;
    struct sockaddr_in serv_addr = global_conn_storage.serv_addr0;
	char buf[20];

	struct sockaddr_storage scapegoat;
	socklen_t scapelen;
	while (1)
	{
        int k0 = myrand() % P, k1 = myrand() % P;
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

int	query_with_token(int x, int q0, int q1, int st, int ed, char *res)
{
    int connfd = global_conn_storage.connfd1;
    struct sockaddr_in serv_addr = global_conn_storage.serv_addr1;

	struct sockaddr_storage scapegoat;
	socklen_t scapelen;

	char	keys[CAP_LENGTH];
    char    buf[1040];

	int k2 = myrand() % P, px = powr(x), pk2 = powr(k2), op = 0;
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
			res[p] = buf[p + 12] ^ keys[p];

		return ed - st;
	}
	return 0;
}

int	write_with_token(int x, int q0, int q1, int st, int ed, char const*data)
{
    int connfd = global_conn_storage.connfd1;
    struct sockaddr_in serv_addr = global_conn_storage.serv_addr1;

	struct sockaddr_storage scapegoat;
	socklen_t scapelen;

    char    buf[1040];

	int k2 = myrand() % P, px = powr(x), pk2 = powr(k2), op = 0;
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
		ret = recvfrom(connfd, buf, ed - st + 12, 0, (struct sockaddr*)&scapegoat, &scapelen);
		if (ret < 0) break;
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

int myread(int q0, int q1, char* buf, int size, int offset)
{
    int length = BASE_LENGTH;
    int now = 0;

    while (now < size)
    {
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

int mywrite(int q0, int q1, char const* buf, int size, int offset)
{
    int length = BASE_LENGTH;
    int now = 0;

    while (now < size)
    {
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

	return NULL;
}

static int xmp_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
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

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
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

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode,
		     struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid,
		     struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size,
			struct fuse_file_info *fi)
{
	int res;

	if (fi != NULL)
		res = ftruncate(fi->fh, size);
	else
		res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2],
		       struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

static int xmp_create(const char *path, mode_t mode,
		      struct fuse_file_info *fi)
{
	int res;

	res = open(path, O_RDWR, mode);
	if (res == -1)
		return -errno;

    int data[3]; data[0] = myrand(); data[1] = myrand(); data[2] = 0;
    if (pwrite(res, (void*)data, 12, 0) == -1)
        return -errno;

	fi->fh = res;
	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	res = open(path, O_RDWR);
	if (res == -1)
		return -errno;

    int data[3];
    if (pread(res, (void*)data, 12, 0) == -1)
        return -errno;

	fi->fh = res;
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

	if(fi == NULL)
		fd = open(path, O_RDONLY);
	else
		fd = fi->fh;
	
	if (fd == -1)
		return -errno;

    int data[3];
    if (pread(fd, (void*)data, 12, 0) == -1)
        return -errno;

    if (size + offset > data[2])
        return 0;

	res = myread(data[0], data[1], buf, size, offset);

	if(fi == NULL)
		close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	if(fi == NULL)
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

	if(fi == NULL)
		close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	close(fi->fh);
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;

	if (mode)
		return -EOPNOTSUPP;

	if(fi == NULL)
		fd = open(path, O_WRONLY);
	else
		fd = fi->fh;
	
	if (fd == -1)
		return -errno;

    int data[3];
    if (pread(fd, (void*)data, 12, 0) == -1)
        return -errno;

    if (length + offset > data[2])
    {
        data[2] = length + offset;
        if (pwrite(fd, (void*)data, 12, 0) == -1)
            return -errno;
    }

    res = 0;

	if(fi == NULL)
		close(fd);
	return res;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.init           = xmp_init,
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= xmp_utimens,
#endif
	.open		= xmp_open,
	.create 	= xmp_create,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
