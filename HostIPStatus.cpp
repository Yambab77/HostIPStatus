#ifndef UNICODE
#define UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <commctrl.h>
#pragma comment(lib, "Comctl32.lib")

#include "resource.h"
#include "function/UI.h"

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);
    return (int)DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_MAIN), nullptr, DlgProc, 0);
}
