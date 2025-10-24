#pragma once
#include <windows.h>
#include <string>

bool SetClipboardText(HWND owner, const std::wstring& text);
