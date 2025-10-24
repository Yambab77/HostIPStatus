#pragma once
#include <windows.h>
#include <string>

// 检查 nmap.exe 是否存在于默认路径
bool CheckNmapExists();

// 启动扫描线程；失败返回 false（线程未创建）
bool StartScan(HWND hDlg, const std::wstring& range);
