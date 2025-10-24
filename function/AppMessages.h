#pragma once
#include <windows.h>

// 自定义消息
#ifndef WM_APP_ADD_IP
#define WM_APP_ADD_IP   (WM_APP + 1)
#endif
#ifndef WM_APP_STATUS
#define WM_APP_STATUS   (WM_APP + 2)
#endif
#ifndef WM_APP_DONE
#define WM_APP_DONE     (WM_APP + 3)
#endif

// 右键菜单命令ID
#ifndef IDM_COPYSEL
#define IDM_COPYSEL     40001
#endif
