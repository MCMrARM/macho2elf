#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

extern "C" {

typedef int32_t darwin_dev_t;
typedef uint64_t darwin_ino64_t;
typedef uint16_t darwin_mode_t;
typedef uint16_t darwin_nlink_t;
typedef uint32_t darwin_id_t;
typedef int64_t darwin_off_t;
typedef int64_t darwin_blkcnt_t;
typedef int32_t darwin_blksize_t;
typedef long darwin_time_t;


struct darwin_timespec {
    darwin_time_t tv_sec;
    long tv_nsec;
};
struct darwin_stat {
    darwin_dev_t st_dev;
    darwin_mode_t st_mode;
    darwin_nlink_t st_nlink;
    darwin_ino64_t st_ino;
    darwin_id_t st_uid;
    darwin_id_t st_gid;
    darwin_dev_t st_rdev;
    darwin_timespec st_atimespec;
    darwin_timespec st_mtimespec;
    darwin_timespec st_ctimespec;
    darwin_timespec st_birthtimespec;
    darwin_off_t st_size;
    darwin_blkcnt_t st_blocks;
    darwin_blksize_t st_blksize;
    uint32_t st_flags;
    uint32_t st_gen;
    int32_t st_lspare;
    int64_t st_qspare[2];
};

#define __DARWIN_MAXPATHLEN 1024
struct darwin_dirent {
    __uint64_t d_ino;
	__uint64_t d_seekoff;
	__uint16_t d_reclen;
	__uint16_t d_namlen;
	__uint8_t d_type;
	char d_name[__DARWIN_MAXPATHLEN];
};


int alphasort$INODE64(const struct darwin_dirent **, const struct darwin_dirent **) {
    abort();
}
int scandir$INODE64(const char* dirp, struct darwin_dirent*** namelist, int (*filter)(const struct darwin_dirent *),
                     int (*compar)(const struct darwin_dirent **, const struct darwin_dirent **)) {
    if (filter != nullptr) {
        fprintf(stderr, "scandir: filter is not supported\n");
        abort();
    }
    if (compar != alphasort$INODE64) {
        fprintf(stderr, "scandir: only alphasort is supported\n");
        abort();
    }

    struct dirent64** host_namelist = nullptr;
    int ret = scandir64(dirp, &host_namelist, nullptr, alphasort64);
    if (ret < 0)
        return ret;
    if (host_namelist) {
        auto ret_namelist = (struct darwin_dirent**) malloc(sizeof(darwin_dirent) * ret);
        *namelist = ret_namelist;
        for (int i = 0; i < ret; i++) {
            ret_namelist[i] = new darwin_dirent;
            ret_namelist[i]->d_ino = host_namelist[i]->d_ino;
            ret_namelist[i]->d_seekoff = host_namelist[i]->d_off;
            ret_namelist[i]->d_reclen = host_namelist[i]->d_reclen;
            ret_namelist[i]->d_namlen = strlen(host_namelist[i]->d_name);
            ret_namelist[i]->d_type = host_namelist[i]->d_type;
            strncpy(ret_namelist[i]->d_name, host_namelist[i]->d_name, __DARWIN_MAXPATHLEN);
        }
    }
    return ret;
}

static void convertStat(struct statx const& host, struct darwin_stat* res) {
    res->st_dev = (host.stx_dev_major << 24) | host.stx_dev_minor;
    res->st_mode = host.stx_mode;
    res->st_nlink = host.stx_nlink;
    res->st_ino = host.stx_ino;
    res->st_uid = host.stx_uid;
    res->st_gid = host.stx_gid;
    res->st_rdev = (host.stx_rdev_major << 24) | host.stx_rdev_minor;
    res->st_atimespec = {host.stx_atime.tv_sec, host.stx_atime.tv_nsec};
    res->st_mtimespec = {host.stx_mtime.tv_sec, host.stx_mtime.tv_nsec};
    res->st_ctimespec = {host.stx_ctime.tv_sec, host.stx_ctime.tv_nsec};
    res->st_birthtimespec = {host.stx_btime.tv_sec, host.stx_btime.tv_nsec};
    res->st_size = host.stx_size;
    res->st_blocks = host.stx_blocks;
    res->st_blksize = host.stx_blksize;
    res->st_flags = 0;
    res->st_gen = 0;
}

int fstat$INODE64(int fd, struct darwin_stat* res) {
    struct statx host {};
    int ret = statx(fd, "", AT_EMPTY_PATH, STATX_TYPE|STATX_MODE|STATX_NLINK|STATX_UID|STATX_GID|STATX_ATIME|STATX_MTIME|STATX_CTIME|STATX_INO|STATX_SIZE|STATX_BLOCKS|STATX_BASIC_STATS|STATX_BTIME, &host);
    if (ret)
        return ret;
    convertStat(host, res);
    return 0;
}
int stat$INODE64(const char* path, struct darwin_stat* res) {
    struct statx host {};
    int ret = statx(AT_FDCWD, path, 0, STATX_TYPE|STATX_MODE|STATX_NLINK|STATX_UID|STATX_GID|STATX_ATIME|STATX_MTIME|STATX_CTIME|STATX_INO|STATX_SIZE|STATX_BLOCKS|STATX_BASIC_STATS|STATX_BTIME, &host);
    if (ret)
        return ret;
    convertStat(host, res);
    return 0;
}


int darwin_open(const char *file, int oflag, mode_t mode) {
    int host_oflag = 0;

    if (oflag & 1) host_oflag |= O_WRONLY;
    if (oflag & 2) host_oflag |= O_RDWR;
    if (oflag & 4) host_oflag |= O_NONBLOCK;
    if (oflag & 8) host_oflag |= O_APPEND;
//    if (oflag & 0x10) host_oflag |= O_SHLOCK;
//    if (oflag & 0x20) host_oflag |= O_EXLOCK;
    if (oflag & 0x40) host_oflag |= O_ASYNC;
    if (oflag & 0x80) host_oflag |= O_SYNC;
    if (oflag & 0x100) host_oflag |= O_NOFOLLOW;
    if (oflag & 0x200) host_oflag |= O_CREAT;
    if (oflag & 0x400) host_oflag |= O_TRUNC;
    if (oflag & 0x800) host_oflag |= O_EXCL;

    return open(file, host_oflag, mode);
}

}