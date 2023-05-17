#ifndef GETPROCADDRESS_H
#define GETPROCADDRESS_H

#include<windows.h>
#include<TlHelp32.h>
#include<tchar.h>

HINSTANCE GetModuleHandleEx(HANDLE hTargetProc, const TCHAR* lpModuleName);
void* GetProcAddressEx(HANDLE hTargetProc, const TCHAR* lpModuleName, const char* lpProcName);

#endif
