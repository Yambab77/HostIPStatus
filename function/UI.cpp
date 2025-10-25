#ifndef UNICODE
#define UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

// ȷ������ GetAdaptersAddresses ��������Vista+��
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <sdkddkver.h>

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <atomic>
#include <algorithm>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")

#include "../Resource.h"
#include "AppMessages.h"
#include "ClipboardUtil.h"
#include "Scan.h"

// ɨ��״̬��ǣ�������ֹɨ���йرմ���
static std::atomic_bool g_scanning{ false };

// ListBox ������̣����� Ctrl+C��
static WNDPROC g_ListOldProc = nullptr;

// �����ļ�ǰ��������̬��������
static WNDPROC g_IpEditOldProc = nullptr;

// ������̣��� IP ��������ﰴ�� '.' ʱ������һ�������
static LRESULT CALLBACK IpEdit_SubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_KEYDOWN:
        if (wParam == VK_DECIMAL || wParam == VK_OEM_PERIOD) { // С���� '.' �������� '.'
            LONG_PTR nextId = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
            if (nextId) {
                HWND hDlg = GetParent(hwnd);
                if (HWND hNext = GetDlgItem(hDlg, (int)nextId)) {
                    SetFocus(hNext);
                    SendMessageW(hNext, EM_SETSEL, 0, -1);
                }
            }
            return 0; // �̵�����
        }
        break;
    case WM_CHAR:
        if (wParam == L'.' || wParam == L'��' || wParam == L'��') { // ������ȫ�Ǳ��
            LONG_PTR nextId = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
            if (nextId) {
                HWND hDlg = GetParent(hwnd);
                if (HWND hNext = GetDlgItem(hDlg, (int)nextId)) {
                    SetFocus(hNext);
                    SendMessageW(hNext, EM_SETSEL, 0, -1);
                }
            }
            return 0; // �̵��ַ�
        }
        break;
    }
    return CallWindowProcW(g_IpEditOldProc, hwnd, msg, wParam, lParam);
}

// �������� ���� ��ʼ�����������(����3λ/������)
static void InitIpPartEdit(HWND hEdit) {
    SendMessageW(hEdit, EM_SETLIMITTEXT, 3, 0);
    LONG_PTR style = GetWindowLongPtrW(hEdit, GWL_STYLE);
    style |= ES_NUMBER | ES_CENTER | WS_TABSTOP | ES_AUTOHSCROLL;
    SetWindowLongPtrW(hEdit, GWL_STYLE, style);
}

// ��ȡ�༭���е���ֵ��0-255����ok=false ��ʾ����Ϊ�ջ����ֵ
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

// ��ĳ���ֶη����仯ʱ���Զ���ת/Խ����գ���ǰδ�󶨵� EN_CHANGE���ɰ�����룩
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

static bool CopySelectedResults(HWND hDlg) {
    HWND hList = GetDlgItem(hDlg, IDC_LIST_RESULTS);
    if (!hList) return false;

    std::vector<int> selIdx;
    int selCount = (int)SendMessageW(hList, LB_GETSELCOUNT, 0, 0);
    if (selCount != LB_ERR && selCount > 0) {
        selIdx.resize(selCount);
        selCount = (int)SendMessageW(hList, LB_GETSELITEMS, (WPARAM)selIdx.size(), (LPARAM)selIdx.data());
        selIdx.resize((std::max)(0, selCount));
    }
    else {
        int cur = (int)SendMessageW(hList, LB_GETCURSEL, 0, 0);
        if (cur != LB_ERR) selIdx.push_back(cur);
    }

    if (selIdx.empty()) { MessageBeep(MB_ICONWARNING); return false; }

    std::wstring out; out.reserve(256);
    for (size_t i = 0; i < selIdx.size(); ++i) {
        int idx = selIdx[i];
        int len = (int)SendMessageW(hList, LB_GETTEXTLEN, idx, 0);
        if (len <= 0) continue;
        std::vector<wchar_t> buf((size_t)len + 1);
        SendMessageW(hList, LB_GETTEXT, idx, (LPARAM)buf.data());
        out.append(buf.data()); // ������'\0'��β�Ļ�����
        if (i + 1 < selIdx.size()) out.append(L"\r\n");
    }

    if (out.empty()) return false;
    if (!SetClipboardText(hDlg, out)) {
        MessageBoxW(hDlg, L"���Ƶ�������ʧ�ܡ�", L"����", MB_ICONERROR);
        return false;
    }
    return true;
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
        SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, L"ɨ����...");
        SendDlgItemMessageW(hDlg, IDC_LIST_RESULTS, LB_RESETCONTENT, 0, 0);
    }
}

// ����������������� ListBox ���Ʊ�λ��׼ȷ���㵽 DLU�������б�ǰ���壩
// adjustPx ��Ϊ������������ϸ����� Header �Ķ��루����Ϊ��������Ϊ����
static void SetListTabStopsByPixels(HWND hList, const std::vector<int>& colLeftPx, int adjustPx) {
    if (!hList || colLeftPx.empty()) return;

    HFONT hFont = (HFONT)SendMessageW(hList, WM_GETFONT, 0, 0);
    HDC hdc = GetDC(hList);
    HFONT hOld = nullptr;
    if (hFont) hOld = (HFONT)SelectObject(hdc, hFont);

    TEXTMETRICW tm{};
    if (!GetTextMetricsW(hdc, &tm) || tm.tmAveCharWidth <= 0) {
        int baseX = LOWORD(GetDialogBaseUnits());
        tm.tmAveCharWidth = (baseX > 0) ? baseX : 8;
    }
    if (hOld) SelectObject(hdc, hOld);
    ReleaseDC(hList, hdc);

    std::vector<int> stops;
    stops.reserve(colLeftPx.size());
    for (int px : colLeftPx) {
        int pxAdj = px + adjustPx;       // ϸ������������/����
        if (pxAdj < 0) pxAdj = 0;
        int dlu = MulDiv(pxAdj, 4, tm.tmAveCharWidth); // ���� -> ˮƽ DLU
        if (dlu < 0) dlu = 0;
        stops.push_back(dlu);
    }

    SendMessageW(hList, LB_SETTABSTOPS, (WPARAM)stops.size(), (LPARAM)stops.data());
}

// �����ı����ؿ�ȣ��� Header �����壩
static int MeasureTextWidthPx(HWND hwndRef, HFONT hFont, const wchar_t* text) {
    HDC hdc = GetDC(hwndRef);
    HFONT hOld = nullptr;
    if (hFont) hOld = (HFONT)SelectObject(hdc, hFont);
    SIZE sz{ 0,0 };
    GetTextExtentPoint32W(hdc, text, (int)wcslen(text), &sz);
    if (hOld) SelectObject(hdc, hOld);
    ReleaseDC(hwndRef, hdc);
    return sz.cx;
}

// ��ȡ���� IPv4 ��ǰ���Σ�����˽�����Σ���ʧ�ܷ��� false
static bool GetLocalIPv4First3(int& o1, int& o2, int& o3) {
    // ���� "a.b.c.d"
    auto parseIPv4A = [](const char* s, BYTE& a, BYTE& b, BYTE& c, BYTE& d) -> bool {
        if (!s || !*s) return false;
        unsigned long v[4] = { 0,0,0,0 };
        char ch = 0;
        if (sscanf_s(s, "%lu.%lu.%lu.%lu%c", &v[0], &v[1], &v[2], &v[3], &ch, 1) < 4) return false;
        for (int i = 0; i < 4; ++i) if (v[i] > 255) return false;
        a = (BYTE)v[0]; b = (BYTE)v[1]; c = (BYTE)v[2]; d = (BYTE)v[3];
        return true;
    };
    auto isPrivate = [](BYTE a, BYTE b) {
        if (a == 10) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 192 && b == 168) return true;
        return false;
    };

    ULONG size = 0;
    // Ԥ��ѯ����
    DWORD dw = GetAdaptersInfo(nullptr, &size);
    if (dw != ERROR_BUFFER_OVERFLOW || size == 0) return false;

    std::vector<BYTE> buf(size);
    IP_ADAPTER_INFO* pInfo = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
    if (GetAdaptersInfo(pInfo, &size) != NO_ERROR) return false;

    int best[3] = { -1,-1,-1 };

    for (IP_ADAPTER_INFO* p = pInfo; p; p = p->Next) {
        if (p->Type == MIB_IF_TYPE_LOOPBACK) continue;

        // ���������������� IPv4 ��ַ
        for (IP_ADDR_STRING* ip = &p->IpAddressList; ip; ip = ip->Next) {
            const char* s = ip->IpAddress.String;
            if (!s || !*s || strcmp(s, "0.0.0.0") == 0) continue;

            BYTE a, b, c, d;
            if (!parseIPv4A(s, a, b, c, d)) continue;
            if (a == 127 || (a == 169 && b == 254)) continue; // �����ػ��� APIPA

            if (isPrivate(a, b)) {
                o1 = a; o2 = b; o3 = c; return true; // ˽�е�ֱַ�ӷ���
            }
            if (best[0] < 0) { best[0] = a; best[1] = b; best[2] = c; }
        }
    }

    if (best[0] >= 0) { o1 = best[0]; o2 = best[1]; o3 = best[2]; return true; }
    return false;
}

INT_PTR CALLBACK DlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static int upCount = 0;

    switch (msg) {
    case WM_INITDIALOG: {
        SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, L"����");
        upCount = 0;
        g_scanning.store(false);

        // �ؽ�����б�ȷ������ʱ�� LBS_EXTENDEDSEL | LBS_USETABSTOPS���������Ϸ����� Header���̶���ͷ��
        {
            HWND hListOld = GetDlgItem(hDlg, IDC_LIST_RESULTS);
            if (hListOld) {
                RECT rc{}; GetWindowRect(hListOld, &rc);
                MapWindowPoints(nullptr, hDlg, reinterpret_cast<POINT*>(&rc), 2);
                DWORD exStyle = (DWORD)GetWindowLongPtrW(hListOld, GWL_EXSTYLE);
                HFONT hFontOld = (HFONT)SendMessageW(hListOld, WM_GETFONT, 0, 0);

                // ���� Header �ؼ�
                int totalW = rc.right - rc.left;
                HWND hHeader = CreateWindowExW(
                    0, WC_HEADERW, L"", WS_CHILD | WS_VISIBLE | HDS_BUTTONS | HDS_HORZ,
                    rc.left, rc.top, totalW, 24, hDlg, (HMENU)(INT_PTR)IDC_HEADER_RESULTS, GetModuleHandleW(nullptr), nullptr);

                if (hHeader && hFontOld) {
                    SendMessageW(hHeader, WM_SETFONT, (WPARAM)hFontOld, TRUE);
                }

                int headerH = 0;
                if (hHeader) {
                    RECT hr{}; GetWindowRect(hHeader, &hr);
                    headerH = hr.bottom - hr.top;
                    if (headerH < 22) headerH = 22;
                }

                // ���ñ�ͷ�в������� ListBox ���Ʊ�λ
                std::vector<int> tabLeftPx;
                {
                    const wchar_t* tIP   = L"IP";
                    const wchar_t* tHOST = L"������";
                    const wchar_t* tSSH  = L"SSH";
                    const wchar_t* tRDP  = L"RDP";
                    const wchar_t* tTEL  = L"TELNET";
                    const wchar_t* tHTTP = L"HTTP/HTTPS";

                    const int pad = 20;
                    int wHOST = MeasureTextWidthPx(hHeader, hFontOld, tHOST) + pad; if (wHOST < 160) wHOST = 160;
                    int wSSH  = MeasureTextWidthPx(hHeader, hFontOld, tSSH)  + pad; if (wSSH  < 48)  wSSH  = 48;
                    int wRDP  = MeasureTextWidthPx(hHeader, hFontOld, tRDP)  + pad; if (wRDP  < 48)  wRDP  = 48;
                    int wTEL  = MeasureTextWidthPx(hHeader, hFontOld, tTEL)  + pad; if (wTEL  < 72)  wTEL  = 72;
                    int wHHT  = MeasureTextWidthPx(hHeader, hFontOld, tHTTP) + pad; if (wHHT  < 110) wHHT  = 110;

                    int vscrollW = GetSystemMetrics(SM_CXVSCROLL);
                    int totalViewW = (rc.right - rc.left) - vscrollW; if (totalViewW < 100) totalViewW = (rc.right - rc.left);

                    // ���ڷ� IP �а��� Host + 4 ��������
                    int svcSum = wHOST + wSSH + wRDP + wTEL + wHHT;
                    int ipW = totalViewW - svcSum;
                    const int ipMin   = 140;
                    const int hostMin = 120; // ���ײ�Ҫ̫խ
                    if (ipW < ipMin) {
                        int deficit = ipMin - ipW;
                        ipW = ipMin;
                        // ��ȱ�ھ�̯�� 5 ���� IP �У������ڸ�����Сֵ��
                        int d = (deficit + 4) / 5;
                        wHOST = (std::max)(hostMin, wHOST - d);
                        wSSH  = (std::max)(48,     wSSH  - d);
                        wRDP  = (std::max)(48,     wRDP  - d);
                        wTEL  = (std::max)(72,     wTEL  - d);
                        wHHT  = (std::max)(110,    wHHT  - d);
                    }

                    struct { const wchar_t* text; int width; } cols[] = {
                        { tIP,   ipW },
                        { tHOST, wHOST },
                        { tSSH,  wSSH },
                        { tRDP,  wRDP },
                        { tTEL,  wTEL },
                        { tHTTP, wHHT },
                    };
                    if (hHeader) {
                        for (int i = 0; i < 6; ++i) {
                            HDITEMW hd{};
                            hd.mask = HDI_TEXT | HDI_WIDTH | HDI_FORMAT;
                            hd.pszText = const_cast<LPWSTR>(cols[i].text);
                            hd.cxy = cols[i].width;
                            hd.fmt = HDF_LEFT | HDF_STRING;
                            Header_InsertItem(hHeader, i, &hd);
                        }
                    }

                    // Ϊ�� ListBox ��������߽�����λ�ã����� IP ���Ʊ�λǰ������ÿ���ڶ�Ӧ tab stop��
                    tabLeftPx.reserve(5);
                    int left = ipW;
                    tabLeftPx.push_back(left); left += wHOST; // ������
                    tabLeftPx.push_back(left); left += wSSH;  // SSH
                    tabLeftPx.push_back(left); left += wRDP;  // RDP
                    tabLeftPx.push_back(left); left += wTEL;  // TELNET
                    tabLeftPx.push_back(left);               // HTTP/HTTPS
                }

                // ���´��� ListBox������ header �߶ȣ�
                RECT rcList = rc;
                rcList.top += headerH;
                DestroyWindow(hListOld);

                DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WS_VSCROLL
                    | LBS_NOTIFY | LBS_EXTENDEDSEL | LBS_USETABSTOPS;
                HWND hListNew = CreateWindowExW(
                    exStyle, L"LISTBOX", L"", style,
                    rcList.left, rcList.top, rcList.right - rcList.left, rcList.bottom - rcList.top,
                    hDlg, (HMENU)(INT_PTR)IDC_LIST_RESULTS, GetModuleHandleW(nullptr), nullptr);

                if (hListNew) {
                    HFONT hUseFont = hFontOld;
                    if (!hUseFont) hUseFont = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
                    if (hUseFont) SendMessageW(hListNew, WM_SETFONT, (WPARAM)hUseFont, TRUE);

                    SetListTabStopsByPixels(hListNew, tabLeftPx, -30); // ���״̬������� 30px��
                    g_ListOldProc = (WNDPROC)SetWindowLongPtrW(hListNew, GWLP_WNDPROC, (LONG_PTR)ListBox_SubclassProc);
                }
            }
        }

        // ��̬�ؽ����룺�þɵ� IDC_EDIT_RANGE �ľ��η��� 5 ������� + ��ͷ
        if (HWND hOld = GetDlgItem(hDlg, IDC_EDIT_RANGE)) {
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
                exStyle, L"STATIC", L"��", WS_CHILD | WS_VISIBLE | SS_CENTER,
                x - gap, rc.top, arrowW, h, hDlg, (HMENU)(INT_PTR)IDC_STATIC_ARROW, GetModuleHandleW(nullptr), nullptr);
            if (hArrow && hFont) SendMessageW(hArrow, WM_SETFONT, (WPARAM)hFont, TRUE);
            x += arrowW + gap;

            HWND hEnd = mkEdit(IDC_EDIT_END);

            // �ñ��� IPv4 ��ǰ������ΪĬ��ֵ��ʧ������˵� 192.168.1
            int ip1 = 192, ip2 = 168, ip3 = 1;
            GetLocalIPv4First3(ip1, ip2, ip3);

            wchar_t buf1[8], buf2[8], buf3[8];
            swprintf_s(buf1, L"%d", ip1);
            swprintf_s(buf2, L"%d", ip2);
            swprintf_s(buf3, L"%d", ip3);

            SetWindowTextW(hIP1, buf1);
            SetWindowTextW(hIP2, buf2);
            SetWindowTextW(hIP3, buf3);
            SetWindowTextW(hStart, L"1");
            SetWindowTextW(hEnd, L"254");

            // Ϊÿ����������á���һ���ؼ����� ID
            SetWindowLongPtrW(hIP1,  GWLP_USERDATA, (LONG_PTR)IDC_EDIT_IP2);
            SetWindowLongPtrW(hIP2,  GWLP_USERDATA, (LONG_PTR)IDC_EDIT_IP3);
            SetWindowLongPtrW(hIP3,  GWLP_USERDATA, (LONG_PTR)IDC_EDIT_START);
            SetWindowLongPtrW(hStart,GWLP_USERDATA, (LONG_PTR)IDC_EDIT_END);
            SetWindowLongPtrW(hEnd,  GWLP_USERDATA, (LONG_PTR)0); // ���һ��û����һ��

            // �ҽ�������̣���һ�α���ԭʼ���̣�����ֱ�����ã�
            if (!g_IpEditOldProc) {
                g_IpEditOldProc = (WNDPROC)SetWindowLongPtrW(hIP1,   GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
                SetWindowLongPtrW(hIP2,   GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
                SetWindowLongPtrW(hIP3,   GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
                SetWindowLongPtrW(hStart, GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
                SetWindowLongPtrW(hEnd,   GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
            } else {
                SetWindowLongPtrW(hIP1,   GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
                SetWindowLongPtrW(hIP2,   GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
                SetWindowLongPtrW(hIP3,   GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
                SetWindowLongPtrW(hStart, GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
                SetWindowLongPtrW(hEnd,   GWLP_WNDPROC, (LONG_PTR)IpEdit_SubclassProc);
            }
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
                MessageBoxW(hDlg, L"��������������Ч��IP�Σ�ÿ��0-255����", L"��ʾ", MB_ICONINFORMATION);
                return TRUE;
            }
            if (s > e) {
                MessageBoxW(hDlg, L"��ʼ��ַ���ܴ��ڽ�����ַ��", L"��ʾ", MB_ICONINFORMATION);
                return TRUE;
            }

            std::wstringstream rng;
            rng << a << L"." << b << L"." << c << L"." << s << L"-" << e;

            if (!CheckNmapExists()) {
                MessageBoxW(hDlg, L"δ�ҵ� nmap.exe������·����\nC:\\Program Files (x86)\\Nmap\\nmap.exe", L"����", MB_ICONERROR);
                return TRUE;
            }

            SetScanningUI(hDlg, true);
            upCount = 0;

            if (!StartScan(hDlg, rng.str())) {
                SetScanningUI(hDlg, false);
                MessageBoxW(hDlg, L"����ɨ���߳�ʧ�ܡ�", L"����", MB_ICONERROR);
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
            AppendMenuW(hMenu, MF_STRING, IDM_COPYSEL, L"����ѡ����\tCtrl+C");
            int selCount = (int)SendMessageW(hList, LB_GETSELCOUNT, 0, 0);
            bool hasSel = (selCount == LB_ERR) ? (SendMessageW(hList, LB_GETCURSEL, 0, 0) != LB_ERR) : (selCount > 0);
            EnableMenuItem(hMenu, IDM_COPYSEL, MF_BYCOMMAND | (hasSel ? MF_ENABLED : MF_GRAYED));
            POINT pt;
            if ((short)LOWORD(lParam) == -1 && (short)HIWORD(lParam) == -1) {
                RECT rc{}; GetWindowRect(hList, &rc);
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
        std::unique_ptr<std::wstring> display(reinterpret_cast<std::wstring*>(lParam));
        if (display && !display->empty()) {
            // �����ݣ��ϰ汾ֻ�� 4 �� '\t'��IP + 4 ���񣩣����ﲹһ����������������
            size_t tabCount = 0;
            for (wchar_t ch : *display) if (ch == L'\t') ++tabCount;
            if (tabCount == 4) {
                size_t p = display->find(L'\t');
                if (p != std::wstring::npos) display->insert(p + 1, L"\t"); // �� IP ������������
            }

            SendDlgItemMessageW(hDlg, IDC_LIST_RESULTS, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(display->c_str()));
            ++upCount;
            std::wstringstream ss; ss << L"ɨ����... �ѷ������� " << upCount << L" ̨";
            SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, ss.str().c_str());
        }
        return TRUE;
    }

    case WM_APP_DONE: {
        SetScanningUI(hDlg, false);
        std::wstringstream ss; ss << L"ɨ����ɡ������� " << upCount << L" ̨";
        SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, ss.str().c_str());
        return TRUE;
    }

    case WM_CLOSE:
        if (g_scanning.load()) {
            MessageBoxW(hDlg, L"ɨ������У����Ժ���ɻ�ȡ�����ٹرա�", L"��ʾ", MB_ICONINFORMATION);
            return TRUE;
        }
        EndDialog(hDlg, 0);
        return TRUE;
    }
    return FALSE;
}