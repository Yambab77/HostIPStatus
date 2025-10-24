#ifndef UNICODE
#define UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <windowsx.h> // GET_X_LPARAM/GET_Y_LPARAM
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

// 右键菜单命令ID（新增）
#define IDM_COPYSEL     40001

struct ScanTaskArgs {
    HWND hDlg;
    std::wstring range;
};

// 扫描状态标记：用于阻止扫描中关闭窗口
static std::atomic_bool g_scanning{ false };

// ListBox 子类过程（用于 Ctrl+C，新增）
static WNDPROC g_ListOldProc = nullptr;
static bool CopySelectedResults(HWND hDlg); // 前置声明

// 新增：帮助函数 —— 初始化数字输入框(限制3位/仅数字)
static void InitIpPartEdit(HWND hEdit) {
    // 限制最多3字符
    SendMessageW(hEdit, EM_SETLIMITTEXT, 3, 0);
    // 仅数字
    LONG_PTR style = GetWindowLongPtrW(hEdit, GWL_STYLE);
    style |= ES_NUMBER | ES_CENTER | WS_TABSTOP | ES_AUTOHSCROLL;
    SetWindowLongPtrW(hEdit, GWL_STYLE, style);
}

// 新增：获取编辑框中的数值（0-255），ok=false 表示为空或非数值
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

// 新增：当某个分段发生变化时，自动跳转/越界清空
static void OnIpPartChanged(HWND hDlg, int idThis, int idNext) {
    HWND hEdit = GetDlgItem(hDlg, idThis);
    if (!hEdit) return;

    wchar_t buf[8]{};
    GetWindowTextW(hEdit, buf, 7);

    // 过滤非数字（防御性，ES_NUMBER通常已限制）
    std::wstring digits;
    for (const wchar_t* p = buf; *p; ++p) if (*p >= L'0' && *p <= L'9') digits.push_back(*p);

    if (digits.size() != wcslen(buf)) {
        SetWindowTextW(hEdit, digits.c_str());
        SendMessageW(hEdit, EM_SETSEL, digits.size(), digits.size());
        return;
    }

    if (digits.empty()) return;

    // 解析数值
    int v = 0;
    for (wchar_t ch : digits) v = v * 10 + (ch - L'0');

    if (v > 255) {
        // 超过255：清空并提示
        MessageBeep(MB_ICONWARNING);
        SetWindowTextW(hEdit, L"");
        return;
    }

    // 输入满3位且有效：跳至下一个输入框并全选
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

    // 启/禁用新的五个输入框
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_IP1), !scanning);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_IP2), !scanning);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_IP3), !scanning);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_START), !scanning);
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_END), !scanning);

    // 兼容：旧文本框若仍存在也禁用
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
        delete msg; // 防止窗口已销毁时的内存泄漏
    }
}

static void PostAddIp(HWND hDlg, const std::wstring& ip) {
    auto msg = new std::wstring(ip);
    if (!PostMessageW(hDlg, WM_APP_ADD_IP, 0, reinterpret_cast<LPARAM>(msg))) {
        delete msg; // 防止窗口已销毁时的内存泄漏
    }
}

// 解析 nmap -oG 的一行，若为存活主机行则返回 IP，否则返回空
static std::wstring ParseGrepableUpIp(const std::string& lineA) {
    if (lineA.find("Status: Up") == std::string::npos) return L"";

    size_t hostPos = lineA.find("Host:");
    if (hostPos == std::string::npos) return L"";

    size_t start = hostPos + 5;
    while (start < lineA.size() && lineA[start] == ' ') ++start;
    if (start >= lineA.size()) return L"";

    size_t end = lineA.find(' ', start);
    std::string ipA = (end == std::string::npos) ? lineA.substr(start) : lineA.substr(start, end - start);

    // 去掉可能的\r\n
    while (!ipA.empty() && (ipA.back() == '\r' || ipA.back() == '\n')) ipA.pop_back();

    if (ipA.empty()) return L"";

    // 转宽字符（按系统ACP）
    int wlen = MultiByteToWideChar(CP_ACP, 0, ipA.c_str(), (int)ipA.size(), nullptr, 0);
    if (wlen <= 0) return L"";
    std::wstring wip;
    wip.resize(wlen);
    MultiByteToWideChar(CP_ACP, 0, ipA.c_str(), (int)ipA.size(), &wip[0], wlen);
    return wip;
}

// 复制字符串到剪贴板（新增）
static bool SetClipboardText(HWND owner, const std::wstring& text) {
    if (!OpenClipboard(owner)) return false;
    if (!EmptyClipboard()) { CloseClipboard(); return false; }

    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
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

// 收集 ListBox 选中项并复制到剪贴板（新增）
static bool CopySelectedResults(HWND hDlg) {
    HWND hList = GetDlgItem(hDlg, IDC_LIST_RESULTS);
    if (!hList) return false;

    std::vector<int> selIdx;
    int selCount = (int)SendMessageW(hList, LB_GETSELCOUNT, 0, 0);
    if (selCount != LB_ERR && selCount > 0) {
        selIdx.resize(selCount);
        selCount = (int)SendMessageW(hList, LB_GETSELITEMS, (WPARAM)selIdx.size(), (LPARAM)selIdx.data());
        selIdx.resize((std::max)(0, selCount)); // 避免与 windows.h 的 max 宏冲突
    }
    else {
        int cur = (int)SendMessageW(hList, LB_GETCURSEL, 0, 0);
        if (cur != LB_ERR) selIdx.push_back(cur);
    }

    if (selIdx.empty()) {
        MessageBeep(MB_ICONWARNING);
        return false;
    }

    std::wstring out;
    out.reserve(256);
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

    // 构造命令行："nmap.exe" -sn -n <range> -oG -
    std::wstring cmdLine = L"\"";
    cmdLine += NMAP_PATH;
    cmdLine += L"\" -sn -n ";
    cmdLine += range;
    cmdLine += L" -oG -";

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        PostStatus(hDlg, L"创建管道失败。");
        PostMessageW(hDlg, WM_APP_DONE, 0, 0);
        return 1;
    }
    // 读端不继承
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi{};
    // CreateProcess 需要可写缓冲区
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    BOOL ok = CreateProcessW(
        nullptr,
        cmdBuf.data(),
        nullptr, nullptr,
        TRUE, // 继承句柄
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi
    );

    if (!ok) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        PostStatus(hDlg, L"启动 nmap 失败，请确认路径与权限。");
        PostMessageW(hDlg, WM_APP_DONE, 0, 0);
        return 2;
    }

    CloseHandle(hWrite); // 父进程关闭写端，准备读

    std::string acc;
    char buf[4096];
    DWORD bytesRead = 0;

    while (ReadFile(hRead, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0) {
        acc.append(buf, buf + bytesRead);
        // 逐行处理
        size_t pos = 0;
        while (true) {
            size_t nl = acc.find('\n', pos);
            if (nl == std::string::npos) {
                // 保留未完成行
                acc.erase(0, pos);
                break;
            }
            std::string line = acc.substr(pos, nl - pos + 1);
            pos = nl + 1;

            // 尝试解析存活IP
            std::wstring ip = ParseGrepableUpIp(line);
            if (!ip.empty()) {
                PostAddIp(hDlg, ip);
            }
        }
    }

    CloseHandle(hRead);

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    PostMessageW(hDlg, WM_APP_DONE, 0, 0);
    return 0;
}

static INT_PTR CALLBACK DlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static int upCount = 0;

    switch (msg) {
    case WM_INITDIALOG: {
        SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, L"就绪");
        upCount = 0;
        g_scanning.store(false);

        // 重建结果列表：确保创建时带 LBS_EXTENDEDSEL（支持鼠标拖动/Shift/Ctrl 多选）
        {
            HWND hListOld = GetDlgItem(hDlg, IDC_LIST_RESULTS);
            if (hListOld) {
                RECT rc{}; GetWindowRect(hListOld, &rc);
                MapWindowPoints(nullptr, hDlg, reinterpret_cast<POINT*>(&rc), 2);
                DWORD exStyle = (DWORD)GetWindowLongPtrW(hListOld, GWL_EXSTYLE);
                HFONT hFont = (HFONT)SendMessageW(hListOld, WM_GETFONT, 0, 0);
                DestroyWindow(hListOld);

                DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER
                            | WS_VSCROLL | LBS_NOTIFY | LBS_EXTENDEDSEL;
                HWND hList = CreateWindowExW(
                    exStyle, L"LISTBOX", L"", style,
                    rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
                    hDlg, (HMENU)(INT_PTR)IDC_LIST_RESULTS, GetModuleHandleW(nullptr), nullptr);
                if (hList && hFont) SendMessageW(hList, WM_SETFONT, (WPARAM)hFont, TRUE);

                // 子类化以支持 Ctrl+C
                if (hList) {
                    g_ListOldProc = (WNDPROC)SetWindowLongPtrW(hList, GWLP_WNDPROC, (LONG_PTR)ListBox_SubclassProc);
                }
            }
        }

        // 动态重建输入：用旧的 IDC_EDIT_RANGE 的矩形放置 5 个输入框 + 箭头（保持你现有逻辑）
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

        // 扫描按钮
        if (id == IDC_BUTTON_SCAN && code == BN_CLICKED) {
            // 读取并校验五个输入
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

            // 构造范围：A.B.C.start-end
            std::wstringstream rng;
            rng << a << L"." << b << L"." << c << L"." << s << L"-" << e;

            SetScanningUI(hDlg, true);
            upCount = 0;

            auto* args = new ScanTaskArgs{ hDlg, rng.str() };
            HANDLE hTh = CreateThread(nullptr, 0, ScanThreadProc, args, 0, nullptr);
            if (!hTh) {
                delete args;
                SetScanningUI(hDlg, false);
                MessageBoxW(hDlg, L"创建扫描线程失败。", L"错误", MB_ICONERROR);
            }
            else {
                CloseHandle(hTh);
            }
            return TRUE;
        }

        // 五个输入框的自动跳转/越界清空
        if (code == EN_CHANGE) {
            if (id == IDC_EDIT_IP1) OnIpPartChanged(hDlg, IDC_EDIT_IP1, IDC_EDIT_IP2);
            else if (id == IDC_EDIT_IP2) OnIpPartChanged(hDlg, IDC_EDIT_IP2, IDC_EDIT_IP3);
            else if (id == IDC_EDIT_IP3) OnIpPartChanged(hDlg, IDC_EDIT_IP3, IDC_EDIT_START);
            else if (id == IDC_EDIT_START) OnIpPartChanged(hDlg, IDC_EDIT_START, IDC_EDIT_END);
            else if (id == IDC_EDIT_END) OnIpPartChanged(hDlg, IDC_EDIT_END, 0);
        }

        // 双击复制当前项
        if (id == IDC_LIST_RESULTS && code == LBN_DBLCLK) {
            CopySelectedResults(hDlg);
            return TRUE;
        }
        break;
    }

                   // 右键菜单：复制选中项
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
            }
            else { pt.x = GET_X_LPARAM(lParam); pt.y = GET_Y_LPARAM(lParam); }
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
        std::unique_ptr<std::wstring> ip(reinterpret_cast<std::wstring*>(lParam));
        if (ip && !ip->empty()) {
            SendDlgItemMessageW(hDlg, IDC_LIST_RESULTS, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(ip->c_str()));
            ++upCount;
            std::wstringstream ss; ss << L"扫描中... 已发现存活主机 " << upCount << L" 台";
            SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, ss.str().c_str());
        }
        return TRUE;
    }

    case WM_APP_DONE: {
        SetScanningUI(hDlg, false);
        std::wstringstream ss; ss << L"扫描完成。存活主机共 " << upCount << L" 台";
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
    return (int)DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_MAIN), nullptr, DlgProc, 0);
}