#ifndef UNICODE
#define UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h> // 新增：Header 控件
#pragma comment(lib, "Comctl32.lib")
#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <atomic>

#include "resource.h"

// 固定的 nmap 路径（如需自定义可改这里）
static const wchar_t* NMAP_PATH = L"C:\\Program Files (x86)\\Nmap\\nmap.exe";

// 自定义消息
#define WM_APP_ADD_IP   (WM_APP + 1)
#define WM_APP_STATUS   (WM_APP + 2)
#define WM_APP_DONE     (WM_APP + 3)

// 右键菜单命令ID
#define IDM_COPYSEL     40001

struct ScanTaskArgs {
    HWND hDlg;
    std::wstring range;
};

// 扫描状态标记：用于阻止扫描中关闭窗口
static std::atomic_bool g_scanning{ false };

// ListBox 子类过程（用于 Ctrl+C）
static WNDPROC g_ListOldProc = nullptr;
static bool SetClipboardText(HWND owner, const std::wstring& text); // 前置声明
static bool CopySelectedResults(HWND hDlg); // 前置声明

// 帮助函数 —— 初始化数字输入框(限制3位/仅数字)
static void InitIpPartEdit(HWND hEdit) {
    SendMessageW(hEdit, EM_SETLIMITTEXT, 3, 0);
    LONG_PTR style = GetWindowLongPtrW(hEdit, GWL_STYLE);
    style |= ES_NUMBER | ES_CENTER | WS_TABSTOP | ES_AUTOHSCROLL;
    SetWindowLongPtrW(hEdit, GWL_STYLE, style);
}

// 获取编辑框中的数值（0-255），ok=false 表示为空或非数值
static int GetEditU8(HWND hDlg, int id, bool& ok) {
    wchar_t buf[8]{};
    GetDlgItemTextW(hDlg, id, buf, 7);
    if (buf[0] == L'\0') { ok = false; return 0; }
    int v = 0;
    for (const wchar_t* p = buf; *p; ++p) {
        if (*p < L'0' || *p > L'9') { ok = false; return 0; }
        v = v * 10 + (*p - L'0');
        if (v > 999) break;
    }
    ok = (v >= 0 && v <= 255);
    return v;
}

// 当某个分段发生变化时，自动跳转/越界清空
static void OnIpPartChanged(HWND hDlg, int idThis, int idNext) {
    HWND hEdit = GetDlgItem(hDlg, idThis);
    if (!hEdit) return;

    wchar_t buf[8]{};
    GetWindowTextW(hEdit, buf, 7);

    std::wstring digits;
    for (const wchar_t* p = buf; *p; ++p) if (*p >= L'0' && *p <= L'9') digits.push_back(*p);

    if (digits.size() != wcslen(buf)) {
        SetWindowTextW(hEdit, digits.c_str());
        SendMessageW(hEdit, EM_SETSEL, digits.size(), digits.size());
        return;
    }

    if (digits.empty()) return;

    int v = 0;
    for (wchar_t ch : digits) v = v * 10 + (ch - L'0');

    if (v > 255) {
        MessageBeep(MB_ICONWARNING);
        SetWindowTextW(hEdit, L"");
        return;
    }

    if (digits.size() == 3 && idNext != 0) {
        HWND hNext = GetDlgItem(hDlg, idNext);
        if (hNext) {
            SetFocus(hNext);
            SendMessageW(hNext, EM_SETSEL, 0, -1);
        }
    }
}

static LRESULT CALLBACK ListBox_SubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_KEYDOWN) {
        if ((wParam == 'C') && (GetKeyState(VK_CONTROL) & 0x8000)) {
            HWND hDlg = GetParent(hwnd);
            CopySelectedResults(hDlg);
            return 0;
        }
    }
    return CallWindowProcW(g_ListOldProc, hwnd, uMsg, wParam, lParam);
}

static void SetScanningUI(HWND hDlg, bool scanning) {
    g_scanning.store(scanning);

    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_SCAN), !scanning);

    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_IP1), !scanning);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_IP2), !scanning);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_IP3), !scanning);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_START), !scanning);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_END), !scanning);

    HWND hOld = GetDlgItem(hDlg, IDC_EDIT_RANGE);
    if (hOld) EnableWindow(hOld, !scanning);

    if (scanning) {
        SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, L"扫描中...");
        SendDlgItemMessageW(hDlg, IDC_LIST_RESULTS, LB_RESETCONTENT, 0, 0);
    }
}

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
    // 仅处理包含 "Host:" 且包含 "Ports:" 的行
    size_t hostPos = lineA.find("Host:");
    size_t portsPos = lineA.find("Ports:");
    if (hostPos == std::string::npos || portsPos == std::string::npos) return L"";

    // 提取 IP（Host: 后的第一个 token）
    size_t start = hostPos + 5;
    while (start < lineA.size() && lineA[start] == ' ') ++start;
    if (start >= lineA.size()) return L"";
    size_t end = lineA.find(' ', start);
    std::string ipA = (end == std::string::npos) ? lineA.substr(start) : lineA.substr(start, end - start);
    while (!ipA.empty() && (ipA.back() == '\r' || ipA.back() == '\n')) ipA.pop_back();
    if (ipA.empty()) return L"";

    // 默认全部未开启
    bool ssh = false, telnet = false, http = false, rdp = false;

    // 解析 Ports: 后的逗号分隔条目
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
        case 443: http = isOpen || http; break; // HTTPS 也计入 HTTP/HTTPS 列
        case 3389: rdp = isOpen || rdp; break;
        default: break;
        }
    }

    // 构造宽字符 IP
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

// 收集 ListBox 选中项并复制到剪贴板
static bool CopySelectedResults(HWND hDlg) {
    HWND hList = GetDlgItem(hDlg, IDC_LIST_RESULTS);
    if (!hList) return false;

    std::vector<int> selIdx;
    int selCount = (int)SendMessageW(hList, LB_GETSELCOUNT, 0, 0);
    if (selCount != LB_ERR && selCount > 0) {
        selIdx.resize(selCount);
        selCount = (int)SendMessageW(hList, LB_GETSELITEMS, (WPARAM)selIdx.size(), (LPARAM)selIdx.data());
        selIdx.resize((std::max)(0, selCount));
    } else {
        int cur = (int)SendMessageW(hList, LB_GETCURSEL, 0, 0);
        if (cur != LB_ERR) selIdx.push_back(cur);
    }

    if (selIdx.empty()) { MessageBeep(MB_ICONWARNING); return false; }

    std::wstring out; out.reserve(256);
    for (size_t i = 0; i < selIdx.size(); ++i) {
        int idx = selIdx[i];
        int len = (int)SendMessageW(hList, LB_GETTEXTLEN, idx, 0);
        if (len <= 0) continue;
        std::wstring line(len, L'\0');
        SendMessageW(hList, LB_GETTEXT, idx, (LPARAM)line.data());
        out.append(line);
        if (i + 1 < selIdx.size()) out.append(L"\r\n");
    }

    if (out.empty()) return false;
    if (!SetClipboardText(hDlg, out)) {
        MessageBoxW(hDlg, L"复制到剪贴板失败。", L"错误", MB_ICONERROR);
        return false;
    }
    return true;
}

static DWORD WINAPI ScanThreadProc(LPVOID param) {
    std::unique_ptr<ScanTaskArgs> args(reinterpret_cast<ScanTaskArgs*>(param));
    HWND hDlg = args->hDlg;
    const std::wstring& range = args->range;

    // 端口扫描：-n -p 22,23,80,443,3389 -oG -
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

// 根据像素列起点设置 ListBox 的制表位（LB_SETTABSTOPS 以对话框基准平均字符宽为单位）
static void SetListTabStopsByPixels(HWND hList, const std::vector<int>& colLeftPx) {
    if (!hList || colLeftPx.empty()) return;

    // 对话框的基准平均字符宽（px）
    int baseX = LOWORD(GetDialogBaseUnits());
    if (baseX <= 0) baseX = 8;

    // ListBox 客户区左侧内边距的微调（可按需改 4/5/6）
    const int leftPaddingPx = 6;

    std::vector<int> stops;
    stops.reserve(colLeftPx.size());
    for (int px : colLeftPx) {
        int chars = (leftPaddingPx + px + baseX / 2) / baseX; // 四舍五入
        if (chars < 0) chars = 0;
        stops.push_back(chars);
    }
    SendMessageW(hList, LB_SETTABSTOPS, (WPARAM)stops.size(), (LPARAM)stops.data());
}

// 新增：测量文本像素宽度的辅助函数（用 Header 的字体）
static int MeasureTextWidthPx(HWND hwndRef, HFONT hFont, const wchar_t* text) {
    HDC hdc = GetDC(hwndRef);
    HFONT hOld = nullptr;
    if (hFont) hOld = (HFONT)SelectObject(hdc, hFont);
    SIZE sz{0,0};
    GetTextExtentPoint32W(hdc, text, (int)wcslen(text), &sz);
    if (hOld) SelectObject(hdc, hOld);
    ReleaseDC(hwndRef, hdc);
    return sz.cx;
}

static INT_PTR CALLBACK DlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static int upCount = 0;

    switch (msg) {
    case WM_INITDIALOG: {
        SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, L"就绪");
        upCount = 0;
        g_scanning.store(false);

        // 重建结果列表：确保创建时带 LBS_EXTENDEDSEL | LBS_USETABSTOPS，并在其上方创建 Header（固定表头）
        {
            HWND hListOld = GetDlgItem(hDlg, IDC_LIST_RESULTS);
            if (hListOld) {
                RECT rc{}; GetWindowRect(hListOld, &rc);
                MapWindowPoints(nullptr, hDlg, reinterpret_cast<POINT*>(&rc), 2);
                DWORD exStyle = (DWORD)GetWindowLongPtrW(hListOld, GWL_EXSTYLE);
                HFONT hFont = (HFONT)SendMessageW(hListOld, WM_GETFONT, 0, 0);

                // 先创建 Header 控件
                int totalW = rc.right - rc.left;
                HWND hHeader = CreateWindowExW(
                    0, WC_HEADERW, L"", WS_CHILD | WS_VISIBLE | HDS_BUTTONS | HDS_HORZ,
                    rc.left, rc.top, totalW, 24, hDlg, (HMENU)(INT_PTR)IDC_HEADER_RESULTS, GetModuleHandleW(nullptr), nullptr);

                // 新增：让表头与列表使用同一字体，避免度量不一致
                if (hHeader && hFont) {
                    SendMessageW(hHeader, WM_SETFONT, (WPARAM)hFont, TRUE);
                }

                int headerH = 0;
                if (hHeader) {
                    RECT hr{}; GetWindowRect(hHeader, &hr);
                    headerH = hr.bottom - hr.top;
                    if (headerH < 22) headerH = 22; // 兜底高度
                } else {
                    headerH = 0; // 若创建失败，就不挤压列表
                }

                // 计算列宽（像素）
                int svcW = 80; // 每个服务列 80px
                int svcCount = 4;
                int ipW = totalW - svcW * svcCount;
                if (ipW < 120) { ipW = 120; svcW = (totalW - ipW) / svcCount; if (svcW < 60) svcW = 60; }

                // 配置表头列（按文本测量，保证 HTTP/HTTPS 不截断，且与 ListBox tab stops 对齐）
                if (hHeader) {
                    // 列标题文本
                    const wchar_t* tIP = L"IP";
                    const wchar_t* tSSH = L"SSH";
                    const wchar_t* tRDP = L"RDP";
                    const wchar_t* tTEL = L"TELNET";
                    const wchar_t* tHTTP = L"HTTP/HTTPS";

                    // 以 Header 字体测量标题宽度，并加上按钮/内边距余量
                    const int pad = 20; // 标题两侧留白
                    int wSSH = MeasureTextWidthPx(hHeader, hFont, tSSH) + pad;   if (wSSH < 48)  wSSH = 48;
                    int wRDP = MeasureTextWidthPx(hHeader, hFont, tRDP) + pad;   if (wRDP < 48)  wRDP = 48;
                    int wTEL = MeasureTextWidthPx(hHeader, hFont, tTEL) + pad;   if (wTEL < 72)  wTEL = 72;
                    int wHHT = MeasureTextWidthPx(hHeader, hFont, tHTTP) + pad;  if (wHHT < 110) wHHT = 110; // 关键：确保 HTTP/HTTPS 完整显示

                    // 预留垂直滚动条宽度，以免最后一列被“吃掉”
                    int vscrollW = GetSystemMetrics(SM_CXVSCROLL);
                    int totalViewW = totalW - vscrollW; if (totalViewW < 100) totalViewW = totalW;

                    // 计算 IP 列宽（剩余全给 IP；不足则从服务列按比例回收）
                    int svcSum = wSSH + wRDP + wTEL + wHHT;
                    int ipW = totalViewW - svcSum;
                    const int ipMin = 140;
                    if (ipW < ipMin) {
                        int deficit = ipMin - ipW;
                        ipW = ipMin;
                        // 平均从4个服务列收缩，但不低于各自最小
                        int d = (deficit + 3) / 4;
                        wSSH = max(48,  wSSH - d);
                        wRDP = max(48,  wRDP - d);
                        wTEL = max(72,  wTEL - d);
                        wHHT = max(110, wHHT - d);
                    }

                    struct { const wchar_t* text; int width; } cols[] = {
                        { tIP, ipW }, { tSSH, wSSH }, { tRDP, wRDP }, { tTEL, wTEL }, { tHTTP, wHHT },
                    };
                    for (int i = 0; i < 5; ++i) {
                        HDITEMW hd{};
                        hd.mask = HDI_TEXT | HDI_WIDTH | HDI_FORMAT;
                        hd.pszText = const_cast<LPWSTR>(cols[i].text);
                        hd.cxy = cols[i].width;
                        hd.fmt = HDF_LEFT | HDF_STRING;
                        Header_InsertItem(hHeader, i, &hd);
                    }

                    // 设置 ListBox 的制表位：用服务列左边界构造 tabStops
                    if (HWND hList = GetDlgItem(hDlg, IDC_LIST_RESULTS)) {
                        std::vector<int> tabLeftPx;
                        tabLeftPx.reserve(4);
                        int left = ipW;
                        tabLeftPx.push_back(left);           left += wSSH;
                        tabLeftPx.push_back(left);           left += wRDP;
                        tabLeftPx.push_back(left);           left += wTEL;
                        tabLeftPx.push_back(left); // HTTP/HTTPS 列左边界
                        SetListTabStopsByPixels(hList, tabLeftPx);
                    }
                }

                // 重新创建 ListBox（下移 header 高度）
                RECT rcList = rc;
                rcList.top += headerH;
                DestroyWindow(hListOld);

                DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WS_VSCROLL
                            | LBS_NOTIFY | LBS_EXTENDEDSEL | LBS_USETABSTOPS;
                HWND hList = CreateWindowExW(
                    exStyle, L"LISTBOX", L"", style,
                    rcList.left, rcList.top, rcList.right - rcList.left, rcList.bottom - rcList.top,
                    hDlg, (HMENU)(INT_PTR)IDC_LIST_RESULTS, GetModuleHandleW(nullptr), nullptr);
                if (hList && hFont) SendMessageW(hList, WM_SETFONT, (WPARAM)hFont, TRUE);

                // 子类化以支持 Ctrl+C
                if (hList) {
                    g_ListOldProc = (WNDPROC)SetWindowLongPtrW(hList, GWLP_WNDPROC, (LONG_PTR)ListBox_SubclassProc);
                }
            }
        }

        // 动态重建输入：用旧的 IDC_EDIT_RANGE 的矩形放置 5 个输入框 + 箭头（沿用现有逻辑）
        HWND hOld = GetDlgItem(hDlg, IDC_EDIT_RANGE);
        if (hOld) {
            RECT rc{}; GetWindowRect(hOld, &rc);
            MapWindowPoints(nullptr, hDlg, reinterpret_cast<POINT*>(&rc), 2);
            DWORD exStyle = (DWORD)GetWindowLongPtrW(hOld, GWL_EXSTYLE);
            HFONT hFont = (HFONT)SendMessageW(hOld, WM_GETFONT, 0, 0);
            ShowWindow(hOld, SW_HIDE);

            int totalW = rc.right - rc.left;
            int h = rc.bottom - rc.top;
            int gap = 6;
            int arrowW = 18;
            int edits = 5;
            int editW = (totalW - arrowW - gap * (edits)) / edits;
            if (editW < 32) editW = 32;

            int x = rc.left;
            auto mkEdit = [&](int id) -> HWND {
                HWND hE = CreateWindowExW(
                    exStyle, L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL | ES_CENTER | ES_NUMBER,
                    x, rc.top, editW, h,
                    hDlg, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
                if (hE && hFont) SendMessageW(hE, WM_SETFONT, (WPARAM)hFont, TRUE);
                InitIpPartEdit(hE);
                x += editW + gap;
                return hE;
            };

            HWND hIP1 = mkEdit(IDC_EDIT_IP1);
            HWND hIP2 = mkEdit(IDC_EDIT_IP2);
            HWND hIP3 = mkEdit(IDC_EDIT_IP3);
            HWND hStart = mkEdit(IDC_EDIT_START);

            HWND hArrow = CreateWindowExW(
                exStyle, L"STATIC", L"→", WS_CHILD | WS_VISIBLE | SS_CENTER,
                x - gap, rc.top, arrowW, h, hDlg, (HMENU)(INT_PTR)IDC_STATIC_ARROW, GetModuleHandleW(nullptr), nullptr);
            if (hArrow && hFont) SendMessageW(hArrow, WM_SETFONT, (WPARAM)hFont, TRUE);
            x += arrowW + gap;

            HWND hEnd = mkEdit(IDC_EDIT_END);

            SetWindowTextW(hIP1, L"192");
            SetWindowTextW(hIP2, L"168");
            SetWindowTextW(hIP3, L"1");
            SetWindowTextW(hStart, L"1");
            SetWindowTextW(hEnd, L"254");
        }

        return TRUE;
    }

    case WM_COMMAND: {
        WORD id = LOWORD(wParam);
        WORD code = HIWORD(wParam);

        if (id == IDC_BUTTON_SCAN && code == BN_CLICKED) {
            bool ok1 = false, ok2 = false, ok3 = false, okS = false, okE = false;
            int a = GetEditU8(hDlg, IDC_EDIT_IP1, ok1);
            int b = GetEditU8(hDlg, IDC_EDIT_IP2, ok2);
            int c = GetEditU8(hDlg, IDC_EDIT_IP3, ok3);
            int s = GetEditU8(hDlg, IDC_EDIT_START, okS);
            int e = GetEditU8(hDlg, IDC_EDIT_END, okE);

            if (!(ok1 && ok2 && ok3 && okS && okE)) {
                MessageBoxW(hDlg, L"请输入完整且有效的IP段（每段0-255）。", L"提示", MB_ICONINFORMATION);
                return TRUE;
            }
            if (s > e) {
                MessageBoxW(hDlg, L"起始地址不能大于结束地址。", L"提示", MB_ICONINFORMATION);
                return TRUE;
            }

            std::wstringstream rng;
            rng << a << L"." << b << L"." << c << L"." << s << L"-" << e;

            if (GetFileAttributesW(NMAP_PATH) == INVALID_FILE_ATTRIBUTES) {
                MessageBoxW(hDlg, L"未找到 nmap.exe，请检查路径：\nC:\\Program Files (x86)\\Nmap\\nmap.exe", L"错误", MB_ICONERROR);
                return TRUE;
            }

            SetScanningUI(hDlg, true);
            upCount = 0;

            auto* args = new ScanTaskArgs{ hDlg, rng.str() };
            HANDLE hTh = CreateThread(nullptr, 0, ScanThreadProc, args, 0, nullptr);
            if (!hTh) {
                delete args;
                SetScanningUI(hDlg, false);
                MessageBoxW(hDlg, L"创建扫描线程失败。", L"错误", MB_ICONERROR);
            } else {
                CloseHandle(hTh);
            }
            return TRUE;
        }

        if (id == IDC_LIST_RESULTS && code == LBN_DBLCLK) {
            CopySelectedResults(hDlg);
            return TRUE;
        }
        break;
    }

    case WM_CONTEXTMENU: {
        HWND hList = GetDlgItem(hDlg, IDC_LIST_RESULTS);
        if ((HWND)wParam == hList) {
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, IDM_COPYSEL, L"复制选中项\tCtrl+C");
            int selCount = (int)SendMessageW(hList, LB_GETSELCOUNT, 0, 0);
            bool hasSel = (selCount == LB_ERR) ? (SendMessageW(hList, LB_GETCURSEL, 0, 0) != LB_ERR) : (selCount > 0);
            EnableMenuItem(hMenu, IDM_COPYSEL, MF_BYCOMMAND | (hasSel ? MF_ENABLED : MF_GRAYED));
            POINT pt;
            if ((short)LOWORD(lParam) == -1 && (short)HIWORD(lParam) == -1) {
                RECT rc{};
                GetWindowRect(hList, &rc);
                pt.x = (rc.left + rc.right) / 2; pt.y = (rc.top + rc.bottom) / 2;
            } else { pt.x = GET_X_LPARAM(lParam); pt.y = GET_Y_LPARAM(lParam); }
            UINT cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hDlg, nullptr);
            DestroyMenu(hMenu);
            if (cmd == IDM_COPYSEL) { CopySelectedResults(hDlg); }
            return TRUE;
        }
        break;
    }

    case WM_APP_STATUS: {
        std::unique_ptr<std::wstring> text(reinterpret_cast<std::wstring*>(lParam));
        SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, text ? text->c_str() : L"");
        return TRUE;
    }

    case WM_APP_ADD_IP: {
        std::unique_ptr<std::wstring> display(reinterpret_cast<std::wstring*>(lParam));
        if (display && !display->empty()) {
            SendDlgItemMessageW(hDlg, IDC_LIST_RESULTS, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(display->c_str()));
            ++upCount;
            std::wstringstream ss; ss << L"扫描中... 已发现主机 " << upCount << L" 台";
            SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, ss.str().c_str());
        }
        return TRUE;
    }

    case WM_APP_DONE: {
        SetScanningUI(hDlg, false);
        std::wstringstream ss; ss << L"扫描完成。主机共 " << upCount << L" 台";
        SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, ss.str().c_str());
        return TRUE;
    }

    case WM_CLOSE:
        if (g_scanning.load()) {
            MessageBoxW(hDlg, L"扫描进行中，请稍候完成或取消后再关闭。", L"提示", MB_ICONINFORMATION);
            return TRUE;
        }
        EndDialog(hDlg, 0);
        return TRUE;
    }
    return FALSE;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    // 初始化公共控件（Header 等）
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    return (int)DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_MAIN), nullptr, DlgProc, 0);
}

// 复制字符串到剪贴板（实现）
static bool SetClipboardText(HWND owner, const std::wstring& text) {
    if (!OpenClipboard(owner)) return false;
    if (!EmptyClipboard()) { CloseClipboard(); return false; }

    const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hMem) { CloseClipboard(); return false; }

    void* p = GlobalLock(hMem);
    if (!p) { GlobalFree(hMem); CloseClipboard(); return false; }
    memcpy(p, text.c_str(), bytes);
    GlobalUnlock(hMem);

    if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }
    CloseClipboard();
    return true;
}