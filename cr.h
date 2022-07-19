#ifndef __CR_H__
#define __CR_H__

#include <algorithm>
#include <chrono>  // duration for sleep
#include <cstring> // memcpy
#include <string>
#include <thread> // this_thread::sleep_for

// Overridable macros
#ifndef CR_LOG
#ifdef CR_DEBUG
#include <stdio.h>
#define CR_LOG(...) fprintf(stdout, __VA_ARGS__)
#else
#define CR_LOG(...)
#endif
#endif

#ifndef CR_ERROR
#ifdef CR_DEBUG
#include <stdio.h>
#define CR_ERROR(...) fprintf(stderr, __VA_ARGS__)
#else
#define CR_ERROR(...)
#endif
#endif

#ifndef CR_TRACE
#ifdef CR_DEBUG
#include <stdio.h>
#define CR_TRACE fprintf(stdout, "CR_TRACE: %s\n", __FUNCTION__);
#else
#define CR_TRACE
#endif
#endif

#ifndef CR_ASSERT
#include <assert.h>            // NOLINT
#define CR_ASSERT(e) assert(e) // NOLINT
#endif

#ifndef CR_REALLOC
#include <stdlib.h>                                // NOLINT
#define CR_REALLOC(ptr, size) ::realloc(ptr, size) // NOLINT
#endif

#ifndef CR_FREE
#include <stdlib.h>              // NOLINT
#define CR_FREE(ptr) ::free(ptr) // NOLINT
#endif

#ifndef CR_MALLOC
#include <stdlib.h>                    // NOLINT
#define CR_MALLOC(size) ::malloc(size) // NOLINT
#endif

//
// Global OS specific defines/customizations
//

#if defined(_WIN32)
#define CR_WINDOWS
#elif defined(__linux__)
#define CR_LINUX
#elif defined(__APPLE__)
#define CR_OSX
#else
#error "Unknown/unsupported platform, please open an issue if you think this \
platform should be supported."
#endif // CR_WINDOWS || CR_LINUX || CR_OSX

#if defined(CR_WINDOWS)
using so_handle = HMODULE;
#else
using so_handle = void *;
#endif

// cr_mode defines how much we validate global state transfer between
// instances. The default is CR_UNSAFE, you can choose another mode by
// defining CR_HOST, ie.: #define CR_HOST CR_SAFEST
enum cr_mode {
    CR_SAFEST = 0, // validate address and size of the state section, if
                   // anything changes the load will rollback
    CR_SAFE = 1,   // validate only the size of the state section, this means
                   // that address is assumed to be safe if avoided keeping
                   // references to global/static states
    CR_UNSAFE = 2, // don't validate anything but that the size of the section
                   // fits, may not be identical though
    CR_DISABLE = 3 // completely disable the auto state transfer
};

#define CR_OP_MODE CR_DISABLE

// cr_op is passed into the guest process to indicate the current operation
// happening so the process can manage its internal data if it needs.
enum cr_op {
    CR_LOAD = 0,
    CR_STEP = 1,
    CR_UNLOAD = 2,
    CR_CLOSE = 3,
};

enum cr_failure {
    CR_NONE,     // No error
    CR_SEGFAULT, // SIGSEGV / EXCEPTION_ACCESS_VIOLATION
    CR_ILLEGAL,  // illegal instruction (SIGILL) / EXCEPTION_ILLEGAL_INSTRUCTION
    CR_ABORT,    // abort (SIGBRT)
    CR_MISALIGN, // bus error (SIGBUS) / EXCEPTION_DATATYPE_MISALIGNMENT
    CR_BOUNDS,   // EXCEPTION_ARRAY_BOUNDS_EXCEEDED
    CR_STACKOVERFLOW,     // EXCEPTION_STACK_OVERFLOW
    CR_STATE_INVALIDATED, // one or more global data section changed and does
                          // not safely match basically a failure of
                          // cr_plugin_validate_sections
    CR_BAD_IMAGE, // The binary is not valid - compiler is still writing it
    CR_INITIAL_FAILURE, // Plugin version 1 crashed, cannot rollback
    CR_OTHER,           // Unknown or other signal,
    CR_USER = 0x100,
};

struct cr_plugin;

// keep track of some internal state about the plugin, should not be messed
// with by user

static bool cr_plugin_open(cr_plugin &ctx, const char *fullpath);
static void cr_plugin_close(cr_plugin &ctx);
static bool cr_plugin_reload(cr_plugin &ctx);
static int cr_plugin_unload(cr_plugin &ctx);
static bool cr_plugin_rollback(cr_plugin &ctx);
static bool cr_plugin_changed(cr_plugin &ctx);
static time_t cr_last_write_time(const std::string &path);
static void cr_del(const std::string &path);
static bool cr_exists(const std::string &path);
static bool cr_copy(const std::string &from, const std::string &to);
static bool cr_plugin_load_internal(cr_plugin &ctx, bool rollback);

template <typename T>
static T cr_so_symbol(so_handle handle, const std::string &symbolName);

template <typename T, typename Ret>
static Ret cr_plugin_call(cr_plugin &ctx, T func);

// public interface for the plugin context, this has some user facing
// variables that may be used to manage reload feedback.
// - version is the reload counter (after loading the first instance it will
//   be 1, not 0)
// - failure is the (platform specific) last error code for any crash that may
//   happen to cause a rollback reload used by the crash protection system

struct cr_internal {
    std::string fullname = {};
    std::string temppath = {};
    time_t timestamp = {};
    cr_mode mode = CR_DISABLE;
    void *handle = nullptr;
};

struct cr_plugin {
    cr_internal *p = nullptr;
    unsigned int version;
    enum cr_failure failure;
    unsigned int next_version;
    unsigned int last_working_version;
    std::string PluginFactorySymbolName;

    inline bool Open(const std::string &pluginPath,
                     const std::string &pluginFactorySymbolName) {
        this->PluginFactorySymbolName = pluginFactorySymbolName;
        if (p == nullptr) {
            return cr_plugin_open(*this, pluginPath.c_str());
        }

        return false;
    }

    template <typename T>
    inline T CreatePlugin() {
        using PluginFactoryFunc = T (*)();

        auto *p2 = p;
        auto func = cr_so_symbol<PluginFactoryFunc>(p2->handle,
                                                    PluginFactorySymbolName);
        return cr_plugin_call<PluginFactoryFunc, T>(*this, func);
    }

    inline bool Failure() {
        if (p != nullptr) {
            return failure != CR_NONE;
        }

        return false;
    }

    inline bool RollbackPlugin() {
        if (p != nullptr) {
            return cr_plugin_rollback(*this);
        }

        return false;
    }

    inline bool PluginUpdated() {
        if (p != nullptr) {
            return cr_plugin_changed(*this);
        }

        return false;
    }

    inline bool ReloadPlugin() {
        if (p != nullptr) {
            return cr_plugin_reload(*this);
        }
    }

    ~cr_plugin() {
        if (p != nullptr) {
            cr_plugin_close(*this);
        }
    }
};

bool cr_plugin_changed(cr_plugin &ctx) {
    auto p = static_cast<cr_internal *>(ctx.p);
    const auto src = cr_last_write_time(p->fullname);
    const auto cur = p->timestamp;
    return src > cur;
}

#if defined(CR_WINDOWS)
#define CR_PATH_SEPARATOR '\\'
#define CR_PATH_SEPARATOR_INVALID '/'
#else
#define CR_PATH_SEPARATOR '/'
#define CR_PATH_SEPARATOR_INVALID '\\'
#endif

static void cr_split_path(std::string path, std::string &parent_dir,
                          std::string &base_name, std::string &ext) {
    std::replace(path.begin(), path.end(), CR_PATH_SEPARATOR_INVALID,
                 CR_PATH_SEPARATOR);
    auto sep_pos = path.rfind(CR_PATH_SEPARATOR);
    auto dot_pos = path.rfind('.');

    if (sep_pos == std::string::npos) {
        parent_dir = "";
        if (dot_pos == std::string::npos) {
            ext = "";
            base_name = path;
        } else {
            ext = path.substr(dot_pos);
            base_name = path.substr(0, dot_pos);
        }
    } else {
        parent_dir = path.substr(0, sep_pos + 1);
        if (dot_pos == std::string::npos || sep_pos > dot_pos) {
            ext = "";
            base_name = path.substr(sep_pos + 1);
        } else {
            ext = path.substr(dot_pos);
            base_name = path.substr(sep_pos + 1, dot_pos - sep_pos - 1);
        }
    }
}

static std::string cr_version_path(const std::string &basepath,
                                   unsigned version,
                                   const std::string &temppath) {
    std::string folder, fname, ext;
    cr_split_path(basepath, folder, fname, ext);
    std::string ver = std::to_string(version);
#if defined(_MSC_VER)
    // When patching PDB file path in library file we will drop path and leave
    // only file name. Length of path is extra space for version number. Trim
    // file name only if version number length exceeds pdb folder path length.
    // This is not relevant on other platforms.
    if (ver.size() > folder.size()) {
        fname = fname.substr(0, fname.size() - (ver.size() - folder.size()));
    }
#endif
    if (!temppath.empty()) {
        folder = temppath;
    }
    return folder + fname + ver + ext;
}

#if defined(CR_WINDOWS)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <dbghelp.h>
#include <windows.h>
#if defined(_MSC_VER)
#pragma comment(lib, "dbghelp.lib")
#endif

#ifdef UNICODE
#define CR_WINDOWS_ConvertPath(_newpath, _path)                                \
    std::wstring _newpath(cr_utf8_to_wstring(_path))

static std::wstring cr_utf8_to_wstring(const std::string &str) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, 0, 0);
    wchar_t wpath_small[MAX_PATH];
    std::unique_ptr<wchar_t[]> wpath_big;
    wchar_t *wpath = wpath_small;
    if (wlen > _countof(wpath_small)) {
        wpath_big = std::unique_ptr<wchar_t[]>(new wchar_t[wlen]);
        wpath = wpath_big.get();
    }

    if (MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wpath, wlen) != wlen) {
        return L"";
    }

    return wpath;
}
#else
#define CR_WINDOWS_ConvertPath(_newpath, _path)                                \
    const std::string &_newpath = _path
#endif // UNICODE

time_t cr_last_write_time(const std::string &path) {
    CR_WINDOWS_ConvertPath(_path, path);
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesEx(_path.c_str(), GetFileExInfoStandard, &fad)) {
        return -1;
    }

    if (fad.nFileSizeHigh == 0 && fad.nFileSizeLow == 0) {
        return -1;
    }

    LARGE_INTEGER time;
    time.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    time.LowPart = fad.ftLastWriteTime.dwLowDateTime;

    return static_cast<time_t>(time.QuadPart / 10000000 - 11644473600LL);
}

bool cr_exists(const std::string &path) {
    CR_WINDOWS_ConvertPath(_path, path);
    return GetFileAttributes(_path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool cr_copy(const std::string &from, const std::string &to) {
    CR_WINDOWS_ConvertPath(_from, from);
    CR_WINDOWS_ConvertPath(_to, to);
    return CopyFile(_from.c_str(), _to.c_str(), FALSE) ? true : false;
}

void cr_del(const std::string &path) {
    CR_WINDOWS_ConvertPath(_path, path);
    DeleteFile(_path.c_str());
}

// If using Microsoft Visual C/C++ compiler we need to do some workaround the
// fact that the compiled binary has a fullpath to the PDB hardcoded inside
// it. This causes a lot of headaches when trying compile while debugging as
// the referenced PDB will be locked by the debugger.
// To solve this problem, we patch the binary to rename the PDB to something
// we know will be unique to our in-flight instance, so when debugging it will
// lock this unique PDB and the compiler will be able to overwrite the
// original one.
#if defined(_MSC_VER)
#include <crtdbg.h>
#include <limits.h>
#include <stdio.h>
#include <tchar.h>

static std::string cr_replace_extension(const std::string &filepath,
                                        const std::string &ext) {
    std::string folder, filename, old_ext;
    cr_split_path(filepath, folder, filename, old_ext);
    return folder + filename + ext;
}

template <class T>
static T struct_cast(void *ptr, LONG offset = 0) {
    return reinterpret_cast<T>(reinterpret_cast<intptr_t>(ptr) + offset);
}

// RSDS Debug Information for PDB files
using DebugInfoSignature = DWORD;
#define CR_RSDS_SIGNATURE 'SDSR'
struct cr_rsds_hdr {
    DebugInfoSignature signature;
    GUID guid;
    long version;
    char filename[1];
};

static bool cr_pe_debugdir_rva(PIMAGE_OPTIONAL_HEADER optionalHeader,
                               DWORD &debugDirRva, DWORD &debugDirSize) {
    if (optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto optionalHeader64 =
            struct_cast<PIMAGE_OPTIONAL_HEADER64>(optionalHeader);
        debugDirRva =
            optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
                .VirtualAddress;
        debugDirSize =
            optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
    } else {
        auto optionalHeader32 =
            struct_cast<PIMAGE_OPTIONAL_HEADER32>(optionalHeader);
        debugDirRva =
            optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
                .VirtualAddress;
        debugDirSize =
            optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
    }

    if (debugDirRva == 0 && debugDirSize == 0) {
        return true;
    } else if (debugDirRva == 0 || debugDirSize == 0) {
        return false;
    }

    return true;
}

static bool cr_pe_fileoffset_rva(PIMAGE_NT_HEADERS ntHeaders, DWORD rva,
                                 DWORD &fileOffset) {
    bool found = false;
    auto *sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections;
         i++, sectionHeader++) {
        auto sectionSize = sectionHeader->Misc.VirtualSize;
        if ((rva >= sectionHeader->VirtualAddress) &&
            (rva < sectionHeader->VirtualAddress + sectionSize)) {
            found = true;
            break;
        }
    }

    if (!found) {
        return false;
    }

    const int diff = static_cast<int>(sectionHeader->VirtualAddress -
                                      sectionHeader->PointerToRawData);
    fileOffset = rva - diff;
    return true;
}

static char *cr_pdb_find(LPBYTE imageBase, PIMAGE_DEBUG_DIRECTORY debugDir) {
    CR_ASSERT(debugDir && imageBase);
    LPBYTE debugInfo = imageBase + debugDir->PointerToRawData;
    const auto debugInfoSize = debugDir->SizeOfData;
    if (debugInfo == 0 || debugInfoSize == 0) {
        return nullptr;
    }

    if (IsBadReadPtr(debugInfo, debugInfoSize)) {
        return nullptr;
    }

    if (debugInfoSize < sizeof(DebugInfoSignature)) {
        return nullptr;
    }

    if (debugDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
        auto signature = *(DWORD *)debugInfo;
        if (signature == CR_RSDS_SIGNATURE) {
            auto *info = (cr_rsds_hdr *)(debugInfo);
            if (IsBadReadPtr(debugInfo, sizeof(cr_rsds_hdr))) {
                return nullptr;
            }

            if (IsBadStringPtrA((const char *)info->filename, UINT_MAX)) {
                return nullptr;
            }

            return info->filename;
        }
    }

    return nullptr;
}

static bool cr_pdb_replace(const std::string &filename,
                           const std::string &pdbname, std::string &orig_pdb) {
    CR_WINDOWS_ConvertPath(_filename, filename);

    HANDLE fp = nullptr;
    HANDLE filemap = nullptr;
    LPVOID mem = 0;
    bool result = false;
    do {
        fp = CreateFile(_filename.c_str(), GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
        if ((fp == INVALID_HANDLE_VALUE) || (fp == nullptr)) {
            break;
        }

        filemap = CreateFileMapping(fp, nullptr, PAGE_READWRITE, 0, 0, nullptr);
        if (filemap == nullptr) {
            break;
        }

        mem = MapViewOfFile(filemap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (mem == nullptr) {
            break;
        }

        auto dosHeader = struct_cast<PIMAGE_DOS_HEADER>(mem);
        if (dosHeader == 0) {
            break;
        }

        if (IsBadReadPtr(dosHeader, sizeof(IMAGE_DOS_HEADER))) {
            break;
        }

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            break;
        }

        auto ntHeaders =
            struct_cast<PIMAGE_NT_HEADERS>(dosHeader, dosHeader->e_lfanew);
        if (ntHeaders == 0) {
            break;
        }

        if (IsBadReadPtr(ntHeaders, sizeof(ntHeaders->Signature))) {
            break;
        }

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            break;
        }

        if (IsBadReadPtr(&ntHeaders->FileHeader, sizeof(IMAGE_FILE_HEADER))) {
            break;
        }

        if (IsBadReadPtr(&ntHeaders->OptionalHeader,
                         ntHeaders->FileHeader.SizeOfOptionalHeader)) {
            break;
        }

        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
            ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            break;
        }

        auto sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
        if (IsBadReadPtr(sectionHeaders,
                         ntHeaders->FileHeader.NumberOfSections *
                             sizeof(IMAGE_SECTION_HEADER))) {
            break;
        }

        DWORD debugDirRva = 0;
        DWORD debugDirSize = 0;
        if (!cr_pe_debugdir_rva(&ntHeaders->OptionalHeader, debugDirRva,
                                debugDirSize)) {
            break;
        }

        if (debugDirRva == 0 || debugDirSize == 0) {
            break;
        }

        DWORD debugDirOffset = 0;
        if (!cr_pe_fileoffset_rva(ntHeaders, debugDirRva, debugDirOffset)) {
            break;
        }

        auto debugDir =
            struct_cast<PIMAGE_DEBUG_DIRECTORY>(mem, debugDirOffset);
        if (debugDir == 0) {
            break;
        }

        if (IsBadReadPtr(debugDir, debugDirSize)) {
            break;
        }

        if (debugDirSize < sizeof(IMAGE_DEBUG_DIRECTORY)) {
            break;
        }

        int numEntries = debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
        if (numEntries == 0) {
            break;
        }

        for (int i = 1; i <= numEntries; i++, debugDir++) {
            char *pdb = cr_pdb_find((LPBYTE)mem, debugDir);
            if (pdb) {
                auto len = strlen(pdb);
                if (len >= strlen(pdbname.c_str())) {
                    orig_pdb = pdb;
                    memcpy_s(pdb, len, pdbname.c_str(), pdbname.length());
                    pdb[pdbname.length()] = 0;
                    result = true;
                }
            }
        }
    } while (0);

    if (mem != nullptr) {
        UnmapViewOfFile(mem);
    }

    if (filemap != nullptr) {
        CloseHandle(filemap);
    }

    if ((fp != nullptr) && (fp != INVALID_HANDLE_VALUE)) {
        CloseHandle(fp);
    }

    return result;
}

bool static cr_pdb_process(const std::string &desination) {
    std::string folder, fname, ext, orig_pdb;
    cr_split_path(desination, folder, fname, ext);
    bool result = cr_pdb_replace(desination, fname + ".pdb", orig_pdb);
    result &= cr_copy(orig_pdb, cr_replace_extension(desination, ".pdb"));
    return result;
}
#endif // _MSC_VER

static void cr_so_unload(cr_plugin &ctx) {
    auto *p = ctx.p;
    CR_ASSERT(p->handle);
    FreeLibrary((HMODULE)p->handle);
}

static so_handle cr_so_load(const std::string &filename) {
    CR_WINDOWS_ConvertPath(_filename, filename);
    auto new_dll = LoadLibrary(_filename.c_str());
    if (!new_dll) {
        CR_ERROR("Couldn't load plugin: %d\n", GetLastError());
    }
    return new_dll;
}

template <typename T>
T cr_so_symbol(so_handle handle, const std::string &symbolName) {
    CR_ASSERT(handle);
    auto symbol = (T)GetProcAddress(handle, symbolName.c_str());
    if (!symbol) {
        CR_ERROR("Couldn't find symbol: %d\n", GetLastError());
    }
    return symbol;
}

static int cr_seh_filter(cr_plugin &ctx, unsigned long seh) {
    if (ctx.version == 1) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    ctx.version = ctx.last_working_version;
    switch (seh) {
    case EXCEPTION_ACCESS_VIOLATION:
        ctx.failure = CR_SEGFAULT;
        return EXCEPTION_EXECUTE_HANDLER;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        ctx.failure = CR_ILLEGAL;
        return EXCEPTION_EXECUTE_HANDLER;
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        ctx.failure = CR_MISALIGN;
        return EXCEPTION_EXECUTE_HANDLER;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        ctx.failure = CR_BOUNDS;
        return EXCEPTION_EXECUTE_HANDLER;
    case EXCEPTION_STACK_OVERFLOW:
        ctx.failure = CR_STACKOVERFLOW;
        return EXCEPTION_EXECUTE_HANDLER;
    default:
        break;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

template <typename T, typename Ret>
Ret cr_plugin_call(cr_plugin &ctx, T func) {
    auto p = (cr_internal *)ctx.p;
#ifndef __MINGW32__
    __try {
        return func();
    } __except (cr_seh_filter(ctx, GetExceptionCode())) {
        return nullptr;
    }
#else
    CR_ASSERT(p);
    return func();
#endif

    return nullptr;
}

#endif // CR_WINDOWS

#if defined(CR_LINUX) || defined(CR_OSX)

#include <csignal>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ucontext.h>
#include <unistd.h>

#if defined(CR_LINUX)
#include <sys/sendfile.h> // sendfile
#elif defined(CR_OSX)
#include <copyfile.h> // copyfile
#endif

time_t cr_last_write_time(const std::string &path) {
    struct stat stats;
    if (stat(path.c_str(), &stats) == -1) {
        return -1;
    }

    if (stats.st_size == 0) {
        return -1;
    }

#if defined(CR_OSX)
    return stats.st_mtime;
#else
    return stats.st_mtim.tv_sec;
#endif
}

bool cr_exists(const std::string &path) {
    struct stat stats {};
    return stat(path.c_str(), &stats) != -1;
}

bool cr_copy(const std::string &from, const std::string &to) {
#if defined(CR_LINUX)
    // Reference:
    // http://www.informit.com/articles/article.aspx?p=23618&seqNum=13
    int input, output;
    struct stat src_stat;
    if ((input = open(from.c_str(), O_RDONLY)) == -1) {
        return false;
    }
    fstat(input, &src_stat);

    if ((output = open(to.c_str(), O_WRONLY | O_CREAT,
                       O_NOFOLLOW | src_stat.st_mode)) == -1) {
        close(input);
        return false;
    }

    auto result =
        sendfile(output, input, NULL, static_cast<size_t>(src_stat.st_size));
    close(input);
    close(output);
    return result > -1;
#elif defined(CR_OSX)
    return copyfile(from.c_str(), to.c_str(), NULL,
                    COPYFILE_ALL | COPYFILE_NOFOLLOW_DST) == 0;
#endif
}

void cr_del(const std::string &path) {
    unlink(path.c_str());
}

static void cr_so_unload(cr_plugin &ctx) {
    CR_ASSERT(ctx.p);
    auto *p = ctx.p;
    CR_ASSERT(p->handle);

    const int r = dlclose(p->handle);
    if (r) {
        CR_ERROR("Error closing plugin: %d\n", r);
    }

    p->handle = nullptr;
}

static so_handle cr_so_load(const std::string &new_file) {
    dlerror();
    auto new_dll = dlopen(new_file.c_str(), RTLD_NOW);
    if (!new_dll) {
        CR_ERROR("Couldn't load plugin: %s\n", dlerror());
    }
    return new_dll;
}
template <typename T>
T cr_so_symbol(so_handle handle, const std::string &symbolName) {
    CR_ASSERT(handle);
    dlerror();
    auto symbol = reinterpret_cast<T>(dlsym(handle, symbolName.c_str()));
    if (!symbol) {
        CR_ERROR("Couldn't find plugin entry point: %s\n", dlerror());
    }
    return symbol;
}

template <typename T, typename Ret>
Ret cr_plugin_call(cr_plugin &ctx, T func) {
    auto *p = ctx.p;
    CR_ASSERT(p);
    return func();
}

#endif // CR_LINUX || CR_OSX

bool cr_plugin_load_internal(cr_plugin &ctx, bool rollback) {
    CR_TRACE
    auto *p = ctx.p;
    const auto file = p->fullname;
    if (cr_exists(file) || rollback) {
        const auto old_file = cr_version_path(file, ctx.version, p->temppath);
        CR_LOG("unload '%s' with rollback: %d\n", old_file.c_str(), rollback);
        int r = cr_plugin_unload(ctx);
        if (r < 0) {
            return false;
        }

        auto new_version = rollback ? ctx.version : ctx.next_version;
        auto new_file = cr_version_path(file, new_version, p->temppath);
        if (rollback) {
            if (ctx.version == 0) {
                ctx.failure = CR_INITIAL_FAILURE;
                return false;
            }
            // Don't rollback to this version again, if it crashes.
            ctx.last_working_version = ctx.version > 0 ? ctx.version - 1 : 0;
        } else {
            // Save current version for rollback.
            ctx.last_working_version = ctx.version;
            cr_copy(file, new_file);

            // Update `next_version` for use by the next reload.
            ctx.next_version = new_version + 1;

#if defined(_MSC_VER)
            if (!cr_pdb_process(new_file)) {
                CR_ERROR("Couldn't process PDB, debugging may be "
                         "affected and/or reload may fail\n");
            }
#endif // defined(_MSC_VER)
        }

        static constexpr auto RELOAD_TRY_COUNT = 50;

        so_handle new_dll = nullptr;
        for (int i = 0; i < RELOAD_TRY_COUNT; i++) {
            new_dll = cr_so_load(new_file);
            if (new_dll == nullptr) {
                ctx.failure = CR_BAD_IMAGE;
            } else {
                ctx.failure = CR_NONE;
                break;
            }
        }

        if (ctx.failure == CR_BAD_IMAGE) {
            return false;
        }
        ctx.failure = CR_NONE;
        auto *p2 = ctx.p;
        p2->handle = new_dll;
        if (ctx.failure != CR_BAD_IMAGE) {
            p2->timestamp = cr_last_write_time(file);
        }
        ctx.version = new_version;
        CR_LOG("loaded: %s (version: %d)\n", new_file.c_str(), ctx.version);
    } else {
        CR_ERROR("Error loading plugin.\n");
        return false;
    }
    return true;
}

// internal
// Unload current running plugin, if it is not a rollback it will trigger a
// last update with `cr_op::CR_UNLOAD` (that may crash and cause another
// rollback, etc.) storing global static states to use with next load. If the
// unload is due a rollback, no `cr_op::CR_UNLOAD` is called neither any state
// is saved, giving opportunity to the previous version to continue with valid
// previous state.
int cr_plugin_unload(cr_plugin &ctx) {
    CR_TRACE
    auto *p = ctx.p;
    int r = 0;
    if (p->handle) {
        cr_so_unload(ctx);
        p->handle = nullptr;
    }
    return r;
}

// internal
// Force a version rollback, causing a partial-unload and a load with the
// previous version, also triggering an update with `cr_op::CR_LOAD` that
// in turn may also cause more rollbacks.
bool cr_plugin_rollback(cr_plugin &ctx) {
    CR_TRACE
    ctx.failure = CR_NONE;

    CR_LOG("1 ROLLBACK version was %d\n", ctx.version);
    auto loaded = cr_plugin_load_internal(ctx, true);
    CR_LOG("1 ROLLBACK version is now %d\n", ctx.version);

    return loaded;
}

// internal
// Checks if a rollback or a reload is needed, do the unload/loading and call
// update one time with `cr_op::CR_LOAD`. Note that this may fail due to crash
// handling during this first update, effectivelly rollbacking if possible and
// causing a consecutive `CR_LOAD` with the previous version.
bool cr_plugin_reload(cr_plugin &ctx) {
    CR_TRACE
    return cr_plugin_load_internal(ctx, false);
}

// Loads a plugin from the specified full path (or current directory if NULL).
bool cr_plugin_open(cr_plugin &ctx, const char *fullpath) {
    CR_TRACE
    CR_ASSERT(fullpath);
    if (!cr_exists(fullpath)) {
        return false;
    }
    auto p = new (CR_MALLOC(sizeof(cr_internal))) cr_internal();
    p->mode = static_cast<cr_mode>(CR_OP_MODE);
    p->fullname = fullpath;
    ctx.p = p;
    ctx.next_version = 1;
    ctx.last_working_version = 0;
    ctx.version = 0;
    ctx.failure = CR_NONE;
    cr_plugin_load_internal(ctx, false);
    return true;
}

// Call to cleanup internal state once the plugin is not required anymore.
void cr_plugin_close(cr_plugin &ctx) {
    CR_TRACE
    cr_plugin_unload(ctx);
    auto *p = ctx.p;

    // delete backups
    const auto file = p->fullname;
    for (unsigned int i = ctx.version; i > 0; i--) {
        cr_del(cr_version_path(file, i, p->temppath));
#if defined(_MSC_VER)
        cr_del(cr_replace_extension(cr_version_path(file, i, p->temppath),
                                    ".pdb"));
#endif
    }

    p->~cr_internal();
    CR_FREE(p);
    ctx.p = nullptr;
    ctx.version = 0;
}

#endif // __CR_H__
/*
```

</details>
*/
