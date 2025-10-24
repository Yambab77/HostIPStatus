#ifndef UNICODE
#define UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <sstream>

#include "Scan.h"
#include "AppMessages.h"

// 固定的 nmap 路径（如需自定义可改这里）
static const wchar_t* NMAP_PATH = L"C:\\Program Files (x86)\\Nmap\\nmap.exe";

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

// 解析 nmap -oG 的一行，提取 IP 与端口状态并生成“制表符分隔”的文本：IP\tSSH\tRDP\tTELNET\tHTTP/HTTPS
static std::wstring ParseGrepableServicesDisplay(const std::string& lineA) {
    size_t hostPos = lineA.find("Host:");
    size_t portsPos = lineA.find("Ports:");
    if (hostPos == std::string::npos || portsPos == std::string::npos) return L"";

    size_t start = hostPos + 5;
    while (start < lineA.size() && lineA[start] == ' ') ++start;
    if (start >= lineA.size()) return L"";
    size_t end = lineA.find(' ', start);
    std::string ipA = (end == std::string::npos) ? lineA.substr(start) : lineA.substr(start, end - start);
    while (!ipA.empty() && (ipA.back() == '\r' || ipA.back() == '\n')) ipA.pop_back();
    if (ipA.empty()) return L"";

    bool ssh = false, telnet = false, http = false, rdp = false;

    size_t p = portsPos + 6;
    while (p < lineA.size() && (lineA[p] == ' ' || lineA[p] == '\t')) ++p;
    std::string portsField = (p < lineA.size()) ? lineA.substr(p) : std::string();
    while (!portsField.empty() && (portsField.back() == '\r' || portsField.back() == '\n')) portsField.pop_back();

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
        for (char c : portStr) { if (c < '0' || c>'9') { port = -1; break; } port = port * 10 + (c - '0'); }
        if (port <= 0) continue;

        bool isOpen = (_stricmp(state.c_str(), "open") == 0);
        switch (port) {
        case 22: ssh = isOpen || ssh; break;
        case 23: telnet = isOpen || telnet; break;
        case 80: http = isOpen || http; break;
        case 443: http = isOpen || http; break;
        case 3389: rdp = isOpen || rdp; break;
        default: break;
        }
    }

    int wlen = MultiByteToWideChar(CP_ACP, 0, ipA.c_str(), (int)ipA.size(), nullptr, 0);
    if (wlen <= 0) return L"";
    std::wstring ip; ip.resize(wlen);
    MultiByteToWideChar(CP_ACP, 0, ipA.c_str(), (int)ipA.size(), &ip[0], wlen);

    const wchar_t* OK = L"○";
    const wchar_t* NO = L"×";

    std::wstringstream disp;
    disp << ip << L"\t"
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

    std::wstring cmdLine = L"\"";
    cmdLine += NMAP_PATH;
    cmdLine += L"\" -n -p 22,23,80,443,3389 ";
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

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end()); cmdBuf.push_back(L'\0');

    BOOL ok = CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) {
        CloseHandle(hRead); CloseHandle(hWrite);
        PostStatus(hDlg, L"启动 nmap 失败，请确认路径与权限。");
        PostMessageW(hDlg, WM_APP_DONE, 0, 0);
        return 2;
    }

    CloseHandle(hWrite);

    std::string acc; char buf[4096]; DWORD bytesRead = 0;
    while (ReadFile(hRead, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0) {
        acc.append(buf, buf + bytesRead);
        size_t pos = 0;
        while (true) {
            size_t nl = acc.find('\n', pos);
            if (nl == std::string::npos) { acc.erase(0, pos); break; }
            std::string line = acc.substr(pos, nl - pos + 1);
            pos = nl + 1;
            std::wstring display = ParseGrepableServicesDisplay(line);
            if (!display.empty()) { PostAddIp(hDlg, display); }
        }
    }

    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);

    PostMessageW(hDlg, WM_APP_DONE, 0, 0);
    return 0;
}

bool CheckNmapExists() {
    return GetFileAttributesW(NMAP_PATH) != INVALID_FILE_ATTRIBUTES;
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