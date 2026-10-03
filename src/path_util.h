#ifndef PATH_UTIL_H
#define PATH_UTIL_H

#include <stdio.h>
#include <string.h>
#include <stddef.h>

#ifdef _WIN32
    #include <windows.h>
    #include <direct.h>
    #include <io.h>
    #define PATH_MKDIR(p) _mkdir(p)
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #define PATH_MKDIR(p) mkdir(p, 0755)
#endif

// ---- atomic file replace --------------------------------------------------
// A crash must never leave a data file truncated. Instead of truncating the
// target in place (fopen "wb"), write to a temp file in the same directory,
// flush it to disk, then atomically rename it over the target. The original
// stays intact until the rename succeeds, so a crash leaves either the old
// file or the complete new one - never a corrupt one.
static inline FILE *atomic_open(const char *path, char *tmp, size_t tmp_size) {
    snprintf(tmp, tmp_size, "%s.tmp", path);
    return fopen(tmp, "wb");
}

// Flush, fsync, close and rename tmp over path. Returns 0 on success.
static inline int atomic_commit(const char *path, const char *tmp, FILE *f) {
    if (!f) return -1;
    if (fflush(f) != 0) { fclose(f); remove(tmp); return -1; }
#ifdef _WIN32
    FlushFileBuffers((HANDLE)_get_osfhandle(_fileno(f)));
#else
    fsync(fileno(f));
#endif
    if (fclose(f) != 0) { remove(tmp); return -1; }
#ifdef _WIN32
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING)) { remove(tmp); return -1; }
#else
    if (rename(tmp, path) != 0) { remove(tmp); return -1; }
#endif
    return 0;
}

// Discard a temp file opened by atomic_open (on error before commit).
static inline void atomic_abort(const char *tmp, FILE *f) {
    if (f) fclose(f);
    if (tmp) remove(tmp);
}

// Create a single directory if it does not already exist.
static inline void ensure_dir(const char *path) {
    if (path && path[0]) PATH_MKDIR(path);   // ignore EEXIST
}

// Directory containing the running executable (static buffer, cached).
static inline const char *exe_dir(void) {
    static char dir[1024] = {0};
    if (dir[0]) return dir;

#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, dir, (DWORD)sizeof(dir));
    if (n == 0 || n >= sizeof(dir)) { strcpy(dir, "."); return dir; }
#else
    ssize_t n = readlink("/proc/self/exe", dir, sizeof(dir) - 1);
    if (n <= 0) { strcpy(dir, "."); return dir; }
    dir[n] = '\0';
#endif

    char *slash = strrchr(dir, '/');
#ifdef _WIN32
    char *bs = strrchr(dir, '\\');
    if (bs && (!slash || bs > slash)) slash = bs;
#endif
    if (slash) *slash = '\0';
    return dir;
}

// Resolve a data directory located next to the project root (a sibling of the
// executable's directory), so the location is stable no matter the CWD.
static inline void data_dir_path(const char *name, char *out, size_t out_size) {
    snprintf(out, out_size, "%s/../%s", exe_dir(), name);
}

#endif
