#ifndef PATH_UTIL_H
#define PATH_UTIL_H

#include <stdio.h>
#include <string.h>
#include <stddef.h>

#ifdef _WIN32
    #include <windows.h>
    #include <direct.h>
    #define PATH_MKDIR(p) _mkdir(p)
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #define PATH_MKDIR(p) mkdir(p, 0755)
#endif

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
