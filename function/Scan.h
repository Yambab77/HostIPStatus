#pragma once
#include <windows.h>
#include <string>

// ��� nmap.exe �Ƿ������Ĭ��·��
bool CheckNmapExists();

// ����ɨ���̣߳�ʧ�ܷ��� false���߳�δ������
bool StartScan(HWND hDlg, const std::wstring& range);
