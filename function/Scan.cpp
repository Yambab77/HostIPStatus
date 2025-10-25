#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#ifndef UNICODE
#define UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <mutex>
#include <thread>
#include <future>
#include <chrono>
#include <unordered_set>

#include "../Resource.h"   // + 引入资源ID
#include "Scan.h"
#include "AppMessages.h"

//（保持）前置声明
static std::wstring ReverseDnsLookup(const std::wstring& ip);
static std::wstring ResolveHostNameWithTimeout(const std::wstring& ip, DWORD timeoutMs);

// 新增：PE 架构探测的前置声明（必须位于 ScanThreadProc 之前）
static WORD GetPeMachine(const std::wstring& path);
static const wchar_t* PeMachineToStr(WORD m);

// 通用：把 RT_RCDATA 资源落地成文件（已存在直接跳过）
static bool EnsureFileFromResource(int resId, const std::wstring& outPath) {
    DWORD attrs = GetFileAttributesW(outPath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) return true;

    HMODULE hMod = GetModuleHandleW(nullptr);
    HRSRC hRes = FindResourceW(hMod, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hRes) return false;
    HGLOBAL hData = LoadResource(hMod, hRes);
    if (!hData) return false;
    DWORD size = SizeofResource(hMod, hRes);
    void* p = LockResource(hData);
    if (!p || size == 0) return false;

    HANDLE hFile = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(hFile, p, size, &written, nullptr);
    CloseHandle(hFile);
    if (!ok || written != size) {
        DeleteFileW(outPath.c_str());
        return false;
    }
    return true;
}

// 从资源解包 nmap.exe 和其依赖到 %TEMP%\HostIPStatus\，返回 nmap.exe 完整路径（失败返回空）
static std::wstring EnsureNmapOnDisk() {
    wchar_t tempDir[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, tempDir) || tempDir[0] == L'\0') return L"";
    std::wstring dir = std::wstring(tempDir) + L"HostIPStatus\\";
    CreateDirectoryW(dir.c_str(), nullptr);

    const std::wstring nmapPath = dir + L"nmap.exe";
    const std::wstring libssh2 = dir + L"libssh2.dll";
    const std::wstring zlibwapi = dir + L"zlibwapi.dll";
    const std::wstring libcrypto3 = dir + L"libcrypto-3.dll";
    const std::wstring libssl3 = dir + L"libssl-3.dll";
    const std::wstring vcr140 = dir + L"vcruntime140.dll";
    const std::wstring vcr140_1 = dir + L"vcruntime140_1.dll";
    const std::wstring msvcp140 = dir + L"msvcp140.dll";

    // 可执行与 Nmap 依赖
    if (!EnsureFileFromResource(IDR_NMAP_EXE, nmapPath))   return L"";
    if (!EnsureFileFromResource(IDR_LIBSSH2_DLL, libssh2))    return L"";
    if (!EnsureFileFromResource(IDR_ZLIBWAPI_DLL, zlibwapi))   return L"";
    if (!EnsureFileFromResource(IDR_LIBCRYPTO3_DLL, libcrypto3)) return L"";
    if (!EnsureFileFromResource(IDR_LIBSSL3_DLL, libssl3))    return L"";

    // MSVC 运行库（供 nmap.exe 使用）
    if (!EnsureFileFromResource(IDR_VCRUNTIME140_DLL, vcr140))   return L"";
    if (!EnsureFileFromResource(IDR_VCRUNTIME140_1_DLL, vcr140_1)) return L"";
    if (!EnsureFileFromResource(IDR_MSVC_RUNTIME_DLL, msvcp140)) return L"";

    // Nmap 数据文件（保持现状）
    if (!EnsureFileFromResource(IDR_NMAP_SERVICES, dir + L"nmap-services"))        return L"";
    if (!EnsureFileFromResource(IDR_NMAP_SERVICE_PROBES, dir + L"nmap-service-probes"))  return L"";
    if (!EnsureFileFromResource(IDR_NMAP_PROTOCOLS, dir + L"nmap-protocols"))       return L"";
    if (!EnsureFileFromResource(IDR_NMAP_RPC, dir + L"nmap-rpc"))             return L"";
    if (!EnsureFileFromResource(IDR_NMAP_MAC_PREFIXES, dir + L"nmap-mac-prefixes"))    return L"";
    if (!EnsureFileFromResource(IDR_NMAP_OS_DB, dir + L"nmap-os-db"))           return L"";

    return nmapPath;
}

//（保持）前置声明
static std::wstring ReverseDnsLookup(const std::wstring& ip);
static std::wstring ResolveHostNameWithTimeout(const std::wstring& ip, DWORD timeoutMs);

struct ScanTaskArgs {
    HWND hDlg;
    std::wstring range;
};

static void PostStatus(HWND hDlg, const std::wstring& text) {
    auto msg = new std::wstring(text);
    if (!PostMessageW(hDlg, WM_APP_STATUS, 0, reinterpret_cast<LPARAM>(msg))) {
        delete msg;
    }
}

static void PostAddIp(HWND hDlg, const std::wstring& ip) {
    auto msg = new std::wstring(ip);
    if (!PostMessageW(hDlg, WM_APP_ADD_IP, 0, reinterpret_cast<LPARAM>(msg))) {
        delete msg;
    }
}

// 解析 nmap -oG 的一行，提取 IP/主机名/端口状态并生成“制表符分隔”文本：
// IP\t主机名\tSSH\tRDP\tTELNET\tHTTP/HTTPS
static std::wstring ParseGrepableServicesDisplay(const std::string& lineA) {
    size_t hostPos = lineA.find("Host:");
    if (hostPos == std::string::npos) return L"";

    // 先提取 IP + 可选主机名
    size_t p = hostPos + 5;
    while (p < lineA.size() && lineA[p] == ' ') ++p;
    if (p >= lineA.size()) return L"";

    size_t ipEnd = lineA.find(' ', p);
    if (ipEnd == std::string::npos) return L"";
    std::string ipA = lineA.substr(p, ipEnd - p);

    std::string hostA;
    size_t q = ipEnd;
    while (q < lineA.size() && lineA[q] == ' ') ++q;
    if (q < lineA.size() && lineA[q] == '(') {
        size_t r = lineA.find(')', q + 1);
        if (r != std::string::npos && r > q + 1) {
            hostA = lineA.substr(q + 1, r - (q + 1));
        }
    }

    // 仅处理包含 Ports: 的行；不再对仅有 "Status: Up" 的行输出，避免重复
    size_t portsPos = lineA.find("Ports:");
    if (portsPos == std::string::npos) {
        return L"";
    }

    // 提取端口状态字段
    size_t portsFieldStart = portsPos + 6;
    while (portsFieldStart < lineA.size() && (lineA[portsFieldStart] == ' ' || lineA[portsFieldStart] == '\t')) ++portsFieldStart;
    std::string portsField = (portsFieldStart < lineA.size()) ? lineA.substr(portsFieldStart) : std::string();
    while (!portsField.empty() && (portsField.back() == '\r' || portsField.back() == '\n')) portsField.pop_back();

    bool ssh = false, telnet = false, http = false, rdp = false;
    size_t cur = 0;
    while (cur < portsField.size()) {
        size_t comma = portsField.find(',', cur);
        std::string item = (comma == std::string::npos) ? portsField.substr(cur) : portsField.substr(cur, comma - cur);
        if (comma == std::string::npos) cur = portsField.size(); else cur = comma + 1;

        size_t is = 0; while (is < item.size() && item[is] == ' ') ++is;
        if (is >= item.size()) continue;

        size_t slash1 = item.find('/', is);
        if (slash1 == std::string::npos) continue;
        std::string portStr = item.substr(is, slash1 - is);

        size_t slash2 = item.find('/', slash1 + 1);
        if (slash2 == std::string::npos) continue;
        std::string state = item.substr(slash1 + 1, slash2 - (slash1 + 1));

        int port = 0;
        for (char c : portStr) { if (c < '0' || c > '9') { port = -1; break; } port = port * 10 + (c - '0'); }
        if (port <= 0) continue;

        bool isOpen = (_stricmp(state.c_str(), "open") == 0);
        switch (port) {
        case 22:   ssh = isOpen || ssh;   break;
        case 23:   telnet = isOpen || telnet; break;
        case 80:
        case 443:  http = isOpen || http;  break;
        case 3389: rdp = isOpen || rdp;   break;
        default: break;
        }
    }

    // 转宽字串
    auto MbToW = [](const std::string& s) -> std::wstring {
        if (s.empty()) return L"";
        int wlen = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
        if (wlen <= 0) return L"";
        std::wstring w; w.resize(wlen);
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), &w[0], wlen);
        return w;
        };
    std::wstring ip = MbToW(ipA);
    std::wstring host = MbToW(hostA);

    // 主机名快速回退（可选，10ms 超时）
    constexpr DWORD kHostResolveTimeoutMs = 10;
    if (host.empty()) {
        host = ResolveHostNameWithTimeout(ip, kHostResolveTimeoutMs);
    }

    // 仅同一扫描线程内对 IP 去重（仅保留首条 Ports 行）
    static thread_local std::unordered_set<std::wstring> s_emittedIPs;
    if (!ip.empty()) {
        auto it = s_emittedIPs.find(ip);
        if (it != s_emittedIPs.end()) return L""; // 已输出过，跳过
        s_emittedIPs.insert(ip);
    }

    // 若四个端口均未开放，则跳过该主机（避免不存在/无响应主机出现在结果中）
    if (!(ssh || rdp || telnet || http)) {
        return L"";
    }

    const wchar_t* OK = L"○";
    const wchar_t* NO = L"×";

    std::wstringstream disp;
    disp << ip << L"\t"
        << host << L"\t"
        << (ssh ? OK : NO) << L"\t"
        << (rdp ? OK : NO) << L"\t"
        << (telnet ? OK : NO) << L"\t"
        << (http ? OK : NO);
    return disp.str();
}

static DWORD WINAPI ScanThreadProc(LPVOID param) {
    std::unique_ptr<ScanTaskArgs> args(reinterpret_cast<ScanTaskArgs*>(param));
    HWND hDlg = args->hDlg;
    const std::wstring& range = args->range;

    // 确保 nmap 已落地
    std::wstring nmapPath = EnsureNmapOnDisk();
    if (nmapPath.empty()) {
        PostStatus(hDlg, L"无法准备 nmap，资源缺失或解包失败。");
        PostMessageW(hDlg, WM_APP_DONE, 0, 0);
        return 2;
    }
    std::wstring nmapDir = nmapPath.substr(0, nmapPath.find_last_of(L"\\/"));

    // 在 EnsureNmapOnDisk() 返回后、构造 cmdLine 之前
    auto fileExists = [](const std::wstring& p)->bool { return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES; };
    std::wstring log = L"nmap 目录: " + nmapDir +
        L"\n[vcruntime140] " + (fileExists(nmapDir + L"\\vcruntime140.dll") ? L"OK" : L"缺失") +
        L"\n[vcruntime140_1] " + (fileExists(nmapDir + L"\\vcruntime140_1.dll") ? L"OK" : L"缺失") +
        L"\n[msvcp140] " + (fileExists(nmapDir + L"\\msvcp140.dll") ? L"OK" : L"缺失");
    PostStatus(hDlg, log);

    WORD mNmap = GetPeMachine(nmapPath);
    WORD mVcr = GetPeMachine(nmapDir + L"\\vcruntime140.dll");
    WORD mVcr1 = GetPeMachine(nmapDir + L"\\vcruntime140_1.dll");
    WORD mMsvcp = GetPeMachine(nmapDir + L"\\msvcp140.dll");

    std::wstringstream arch;
    arch << L"PE 架构: nmap=" << PeMachineToStr(mNmap)
        << L", vcruntime140=" << PeMachineToStr(mVcr)
        << L", vcruntime140_1=" << PeMachineToStr(mVcr1)
        << L", msvcp140=" << PeMachineToStr(mMsvcp);
    PostStatus(hDlg, arch.str());

    if (mNmap && ((mVcr && mVcr != mNmap) || (mVcr1 && mVcr1 != mNmap) || (mMsvcp && mMsvcp != mNmap))) {
        PostStatus(hDlg, L"位数不匹配：请用与 nmap.exe 相同架构的 VC 运行库（或更换 nmap.exe 为同架构）。");
    }

    std::wstring cmdLine = L"\"";
    cmdLine += nmapPath;
    // 强制端口扫描、跳过主机发现、仅显示开放端口主机、提升速度，并加 -v 便于诊断
    cmdLine += L"\" -Pn -sT -n --open -T4 --max-retries 1 --host-timeout 5s -v -p 22,23,80,443,3389 ";
    cmdLine += range;
    cmdLine += L" -oG -";

    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;

    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        PostStatus(hDlg, L"创建管道失败。");
        PostMessageW(hDlg, WM_APP_DONE, 0, 0);
        return 1;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags |= STARTF_USESTDHANDLES; si.hStdOutput = hWrite; si.hStdError = hWrite;

    // 调试文件：记录 nmap 原始输出
    std::wstring dbgPath = nmapDir + L"\\nmap_last_output.txt";
    HANDLE hDbg = CreateFileW(dbgPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end()); cmdBuf.push_back(L'\0');

    // 1) 临时把解包目录加入 PATH，确保子进程能定位到运行库 DLL
    DWORD need = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    std::wstring oldPath; oldPath.resize(need ? (need - 1) : 0);
    if (need) GetEnvironmentVariableW(L"PATH", &oldPath[0], need);
    std::wstring newPath = nmapDir + L";" + oldPath;
    SetEnvironmentVariableW(L"PATH", newPath.c_str());

    BOOL ok = CreateProcessW(
        nullptr, cmdBuf.data(),
        nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr,
        nmapDir.c_str(),   // 子进程工作目录
        &si, &pi);

    // 2) 立刻恢复父进程 PATH
    SetEnvironmentVariableW(L"PATH", oldPath.c_str());

    if (!ok) {
        if (hDbg != INVALID_HANDLE_VALUE) CloseHandle(hDbg);
        CloseHandle(hRead); CloseHandle(hWrite);
        PostStatus(hDlg, L"启动 nmap 失败，请确认权限/运行库位数是否匹配。");
        PostMessageW(hDlg, WM_APP_DONE, 0, 0);
        return 2;
    }

    CloseHandle(hWrite);

    auto MbToW = [](const std::string& s) -> std::wstring {
        if (s.empty()) return L"";
        int wlen = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
        if (wlen <= 0) return L"";
        std::wstring w; w.resize(wlen);
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), &w[0], wlen);
        return w;
        };

    int dbgStatusShown = 0;
    std::string acc; char buf[4096]; DWORD bytesRead = 0;
    while (ReadFile(hRead, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0) {
        // 记录原始输出到调试文件
        if (hDbg != INVALID_HANDLE_VALUE) {
            DWORD wr = 0; WriteFile(hDbg, buf, bytesRead, &wr, nullptr);
        }

        acc.append(buf, buf + bytesRead);
        size_t pos = 0;
        while (true) {
            size_t nl = acc.find('\n', pos);
            if (nl == std::string::npos) { acc.erase(0, pos); break; }

            std::string line = acc.substr(pos, nl - pos + 1);
            pos = nl + 1;

            // 将前几条关键行抛到状态栏便于诊断
            if (dbgStatusShown < 5) {
                if (line.find("Host:") != std::string::npos ||
                    line.find("Ports:") != std::string::npos ||
                    line.find("Status:") != std::string::npos ||
                    line.find("Nmap done") != std::string::npos ||
                    line.find("Error") != std::string::npos ||
                    line.find("Failed") != std::string::npos) {
                    std::wstring w = MbToW(line);
                    if (!w.empty()) { PostStatus(hDlg, L"[nmap] " + w); ++dbgStatusShown; }
                }
            }

            std::wstring display = ParseGrepableServicesDisplay(line);
            if (!display.empty()) { PostAddIp(hDlg, display); }
        }
    }

    // 处理尾部未以换行结尾的最后一行
    if (!acc.empty()) {
        if (hDbg != INVALID_HANDLE_VALUE) {
            const char nl[] = "\n"; DWORD wr = 0; WriteFile(hDbg, nl, 1, &wr, nullptr);
        }
        std::wstring display = ParseGrepableServicesDisplay(acc);
        if (!display.empty()) { PostAddIp(hDlg, display); }
        else if (dbgStatusShown < 5) {
            std::wstring w = MbToW(acc);
            if (!w.empty()) { PostStatus(hDlg, L"[nmap-last] " + w); }
        }
    }

    if (hDbg != INVALID_HANDLE_VALUE) CloseHandle(hDbg);
    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);

    PostMessageW(hDlg, WM_APP_DONE, 0, 0);
    return 0;
}

bool CheckNmapExists() {
    // 改为检查资源解包结果
    return !EnsureNmapOnDisk().empty();
}

bool StartScan(HWND hDlg, const std::wstring& range) {
    auto* args = new ScanTaskArgs{ hDlg, range };
    HANDLE hTh = CreateThread(nullptr, 0, ScanThreadProc, args, 0, nullptr);
    if (!hTh) {
        delete args;
        return false;
    }
    CloseHandle(hTh);
    return true;
}

// 线程安全初始化 Winsock
static void EnsureWinsockInit() {
    static std::once_flag g_wsOnce;
    std::call_once(g_wsOnce, [] {
        WSADATA wd{};
        WSAStartup(MAKEWORD(2, 2), &wd);
        });
}

// 反向 DNS：根据 IPv4 字符串获取主机名；失败返回空字符串
static std::wstring ReverseDnsLookup(const std::wstring& ip) {
    EnsureWinsockInit();

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (InetPtonW(AF_INET, ip.c_str(), &sa.sin_addr) != 1) return L"";

    wchar_t host[NI_MAXHOST]{};
    int ret = GetNameInfoW(reinterpret_cast<sockaddr*>(&sa), sizeof(sa),
        host, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
    if (ret == 0 && host[0] != L'\0') return host;
    return L"";
}

static inline const wchar_t* Sym(bool ok) { return ok ? L"✓" : L"×"; }

// 构造 6 列（IP\t主机名\tSSH\tRDP\tTELNET\tHTTP/HTTPS）并投递到 UI
static void PostHostResult(HWND hDlg,
    const std::wstring& ip,
    const std::wstring& hostOptional,
    const std::wstring& ssh,
    const std::wstring& rdp,
    const std::wstring& telnet,
    const std::wstring& http)
{
    std::wstring host = hostOptional;
    if (host.empty()) {
        host = ReverseDnsLookup(ip); // 如需也控制超时，可改为 ResolveHostNameWithTimeout(ip, 10);
    }

    std::wstring line;
    line.reserve(ip.size() + host.size() + ssh.size() + rdp.size() + telnet.size() + http.size() + 8);
    line.append(ip);
    line.append(L"\t");
    line.append(host);
    line.append(L"\t");
    line.append(ssh);
    line.append(L"\t");
    line.append(rdp);
    line.append(L"\t");
    line.append(telnet);
    line.append(L"\t");
    line.append(http);

    auto payload = new std::wstring(std::move(line));
    PostMessageW(hDlg, WM_APP_ADD_IP, 0, reinterpret_cast<LPARAM>(payload));
}

static void PostHostResult(HWND hDlg,
    const std::wstring& ip,
    const std::wstring& hostOptional,
    bool sshOpen, bool rdpOpen, bool telnetOpen,
    const std::wstring& httpText)
{
    auto Sym = [](bool ok) { return ok ? L"✓" : L"×"; };
    PostHostResult(hDlg, ip, hostOptional,
        std::wstring(1, Sym(sshOpen)[0]),
        std::wstring(1, Sym(rdpOpen)[0]),
        std::wstring(1, Sym(telnetOpen)[0]),
        httpText);
}

// 超时主机名解析：timeoutMs==0 时直接返回空；>0 时在后台线程解析并等待指定超时
static std::wstring ResolveHostNameWithTimeout(const std::wstring& ip, DWORD timeoutMs) {
    if (timeoutMs == 0) return L"";

    std::promise<std::wstring> prom;
    std::future<std::wstring> fut = prom.get_future();
    std::thread([ip, p = std::move(prom)]() mutable {
        std::wstring r = ReverseDnsLookup(ip);
        try { p.set_value(std::move(r)); }
        catch (...) {}
        }).detach();

    if (fut.wait_for(std::chrono::milliseconds(timeoutMs)) == std::future_status::ready) {
        return fut.get();
    }
    return L"";
}

// 读取 PE 头判断文件位数（x86 0x014C / x64 0x8664），失败返回 0
static WORD GetPeMachine(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;

    IMAGE_DOS_HEADER dos{};
    DWORD rd = 0;
    if (!ReadFile(h, &dos, sizeof(dos), &rd, nullptr) || rd != sizeof(dos) || dos.e_magic != 0x5A4D /*MZ*/) {
        CloseHandle(h); return 0;
    }
    if (SetFilePointer(h, dos.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(h); return 0;
    }
    DWORD sig = 0;
    if (!ReadFile(h, &sig, sizeof(sig), &rd, nullptr) || rd != sizeof(sig) || sig != 0x00004550 /*PE00*/) {
        CloseHandle(h); return 0;
    }
    IMAGE_FILE_HEADER fh{};
    if (!ReadFile(h, &fh, sizeof(fh), &rd, nullptr) || rd != sizeof(fh)) {
        CloseHandle(h); return 0;
    }
    CloseHandle(h);
    return fh.Machine;
}

static const wchar_t* PeMachineToStr(WORD m) {
    switch (m) {
    case 0x014C: return L"x86(0x14C)";
    case 0x8664: return L"x64(0x8664)";
    default:     return L"未知";
    }
}