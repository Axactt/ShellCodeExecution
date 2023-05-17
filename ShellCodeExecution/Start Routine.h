#pragma once
#include"GetProcAddress.h"
#include<vector>
#include<iostream>

enum LAUNCH_METHOD
{
	LM_NtCreateThreadEx,
	LM_HiJackThread,
	LM_SetWindowsHookEx,
	LM_QueueUserAPC

};

#ifdef _WIN64
using f_Routine = UINT_PTR(__fastcall*)(void* pArg); //!on x64 _fastcall is ignoed and universal MS _x64 ABI is used
#else
using f_Routine = UINT_PTR(__stdcall*)(void* pArg);
#endif
DWORD StartRoutine(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, LAUNCH_METHOD Method, DWORD& LastWin32Error, UINT_PTR& Out);

//! creating function prototype for NtCreateThreadEx
//todo to understand all of the parameter of NtCreateThreadEx funtion
//! hTargetProc is handle to the TargetProcess where Dll is to be Injected
//! pRoutine is the address of LOadLibrary Routine Found using GetprocessAddresEx function
//! pRoutine cast To LPTHREAD_START_ROUTINE parameter 
//! which is basically::userFunction lpStartAddres(or base-address) to call from  new created Thread
//! [in] lpStartAddress ==> "A pointer to the application - defined function of type LPTHREAD_START_ROUTINE to be executed by the thread and represents the starting address of the thread in the remote process.The function must exist in the remote process."(LPTHREAD_START_ROUTINE).In our case it is address of load-libraryfunction buffer 
//! pArg:: Is actually parameter to the new thread function created(LoadLiBRary buffer) which in our case is the buffer- address in target Proces where we copied our to_be_injected DLL path
//! So Basicallly pArg is the parameter passed to the Thread_function(here LoadLibrary buffer) . Which in turn  is a user-defined value that is samea as passed as the fourth parameter to CreateThread() function, and simply passed as - is to the thread function(Here LOadLibrary).This value typically points to some data structure containing information that allows the thread to do its job.(Here path to dll as written  buffer in target process)

using f_NtCreateThreadEx = NTSTATUS(__stdcall*)(HANDLE* _Out_ pThreadHandleOut, ACCESS_MASK DesiredAccess, void* pAttr, HANDLE _In_ hTargetProc, void* _In_ pRoutine, void* _In_ pArg, ULONG Flags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, void* pAttrListOut);

//! structure1 for use with setwindowsHookex
struct HookData
{
	HHOOK m_hHook;
	HWND m_hWnd;
};

//! structure2 for use with Setwindowshookex
struct EnumWindowsCallBack_Data
{
	std::vector<HookData> m_HookData;
	DWORD m_PID;
	HOOKPROC m_pHook;
	HINSTANCE m_hModule;
};

#define SR_REMOTE_TIMEOUT 5000

#define SR_ERR_SUCCESS 0X000000000
#define SR_ERROR_INVALID_LAUNCH_METHOD 0X00000001

#define SR_NTCTE_ERR_NTCTE_MISSING		0x10000001
#define SR_NTCTE_ERR_CANT_ALLOC_MEM		0x10000002
#define SR_NTCTE_ERR_WPM_FAIL			0x10000003
#define SR_NTCTE_ERR_NTCTE_FAIL			0x10000004
#define SR_NTCTE_ERR_RPM_FAIL			0x10000005
#define SR_NTCTE_ERR_TIMEOUT			0x10000006

#define SR_HT_ERR_TH32_FAIL			0x20000001
#define SR_HT_ERR_T32FIRST_FAIL		0x20000002
#define SR_HT_ERR_NO_THREADS		0x20000003
#define SR_HT_ERR_OPEN_THREAD_FAIL	0x20000004
#define SR_HT_ERR_CANT_ALLOC_MEM	0x20000005
#define SR_HT_ERR_SUSPEND_FAIL		0x20000006
#define SR_HT_ERR_GET_CONTEXT_FAIL	0x20000007
#define SR_HT_ERR_WPM_FAIL			0x20000008
#define SR_HT_ERR_SET_CONTEXT_FAIL	0x20000009
#define SR_HT_ERR_RESUME_FAIL		0x2000000A
#define SR_HT_ERR_TIMEOUT			0x2000000B

#define SR_SWHEX_ERR_CANT_ALLOC_MEM 0x30000001
#define SR_SWHEX_ERR_CNHEX_MISSING	0x30000002
#define SR_SWHEX_ERR_WPM_FAIL		0x30000003
#define SR_SWHEX_ERR_ENUM_WND_FAIL	0x30000004
#define SR_SWHEX_ERR_NO_WINDOWS		0x30000005
#define SR_SWHEX_ERR_TIMEOUT		0x30000006

#define SR_QUAPC_ERR_CANT_ALLOC_MEM	0x40000001
#define SR_QUAPC_ERR_WPM_FAIL		0x40000002
#define SR_QUAPC_ERR_TH32_FAIL		0x40000003
#define SR_QUAPC_ERR_T32FIRST_FAIL	0x40000004
#define SR_QUAPC_ERR_NO_APC_THREAD	0x40000005

#define NT_FAIL(status)  (status<0)