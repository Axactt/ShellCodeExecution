#include "Start Routine.h"

DWORD SR_NtCreateThreadEx(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& RemoteRet);

DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& RemoteRet);

DWORD SR_SetWindowsHookEx(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& RemoteRet);

DWORD SR_QueueUserApc(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& RemoteRet);

//! StartRoutine is s a wrapper which forwards execution to  other wrapper methods shown above
//! The selection is doen by switch block using enum LAUNCH_METHOD as parameter
DWORD StartRoutine(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, LAUNCH_METHOD Method, DWORD& Lastwin32Error, UINT_PTR& RemoteRet)
{
	DWORD dwRet = 0;
	//! autocomplete switch block by putting "tab" while typing switch
	//! Then in switch bracket after typing enum Name press "Enter". will create all cases for enum
	switch (Method)
	{
	case LM_NtCreateThreadEx:
		dwRet = SR_NtCreateThreadEx(hTargetProc, pRoutine, pArg, Lastwin32Error, RemoteRet);
		break;
	case LM_HiJackThread:
		dwRet = SR_HijackThread(hTargetProc, pRoutine, pArg, Lastwin32Error, RemoteRet);
		break;
	case LM_SetWindowsHookEx:
		dwRet = SR_SetWindowsHookEx(hTargetProc, pRoutine, pArg, Lastwin32Error, RemoteRet);
		break;
	case LM_QueueUserAPC:
		dwRet = SR_QueueUserApc(hTargetProc, pRoutine, pArg, Lastwin32Error, RemoteRet);
		break;
	default:
		dwRet = SR_ERROR_INVALID_LAUNCH_METHOD;
		break;
	}

	return dwRet;
}

DWORD SR_NtCreateThreadEx(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& RemoteRet)
{
	auto p_NtCreateThreadEx = reinterpret_cast<f_NtCreateThreadEx>(GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx"));
	if (!p_NtCreateThreadEx)
	{
		lastWin32Error = GetLastError();
		return SR_NTCTE_ERR_NTCTE_MISSING;
	}
	//! A buffer of 4096 bytes is created to carry out temporary operations and copy of local variables
	void* pMem = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		lastWin32Error = GetLastError();
		return SR_NTCTE_ERR_CANT_ALLOC_MEM;

	}
#ifdef _WIN64 //!This preprocessor macro will change execution method as per build version x64 or x86

	BYTE ShellCode[] =
	{
		//! Buffer to save pArg address which is lpparameter (dllpath buffer) to newly created thread function
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // addrs: -0x10-> argument/returned value 
		//! Buffer  pRoutine address which is LPTHREAD_START_ROUTINE parameter ie base address of function to be executed by newly created thread(here LoadLibrary address-buffer by wpm)
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //addrs: -0x08 -> pRoutine

		0x48,0x8b,0xc1,                           //adrs: + 0x00 -> mov rax,rcx
		0x48,0x8b,0x08,                           //addrs: +0x03 -> mov rcx,[rax]

		0x48,0x83,0xec,0x28,                     //addrs: +0x06 -> sub rsp,0x28
		0xff,0x50,0x08,                          //addrs: +0x0a -> call qword ptr[rax+0x08]
		0x48,0x83,0xc4,0x28,                      //addrs: +0x0d -> add rsp,0x28

		0x48,0x8d,0x0d,0xd8,0xff,0xff,0xff,   //addrs: +0x11 -> lea rcx,[pShellCode_start]
		0x48,0x89,0x01,                        // addrs: +0x18 -> mov [rcx],rax
		0x48,0x31,0xc0,                            // addrs: +0x1b -> xor rax, rax
		0xc3                                      // addrs: +0x1e -> ret
    };  // SIZE = 0X1F (+ ADD AVOVE FUNC 0X10)

	*reinterpret_cast<void**>(ShellCode + 0x0000) = pArg;
	*reinterpret_cast<f_Routine**>(ShellCode + 0x08) = pRoutine;
	//! offset to actual code after buffer to save address
	DWORD FuncOffset = 0x10;
	//!Writing the ShellCode memory to pMem allocated buffer using wpm
	BOOL bRet = WriteProcessMemory(hTargetProc, pMem, ShellCode, sizeof(ShellCode), nullptr);
	if (!bRet)
	{
		lastWin32Error = GetLastError();
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
		return SR_NTCTE_ERR_WPM_FAIL;
	}

	//! pRemoteArg is assigned the buffer of ShellCode whcih is pMem
	void* pRemoteArg = pMem;
	//! pRemoteFunc is assigned address of actual function implementation in ShellCode buffer(offset 0x10)
	void* pRemoteFunc = reinterpret_cast<BYTE*>(pMem) + FuncOffset;
	//? a handle is assigned to created threaad which processes buffer of ShellCode for function pRemoteFunc with its lpParameter assigned as pRemoteArg
	//! This assigned handle shall be used in function WaitForSingleObject() to check if created thread has been changed to  Signalled state(which means exited/terminated for thread)
	HANDLE hThread = nullptr;

	NTSTATUS ntRet = p_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, pRemoteFunc, pRemoteArg, 0, 0, 0, 0, nullptr);
	if (NT_FAIL(ntRet) || !hThread)
	{
		lastWin32Error = ntRet;//GetLstError does not work on undocumented Nt functions
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
		return SR_NTCTE_ERR_NTCTE_FAIL;
	}
	//!WaitForSingleObject function checks if the thread has finished executing within Timeout specified
	//! The check for thread-exit/finish is done by checking if result is WAIT_OBJECT_0
	DWORD dwWaitRet = WaitForSingleObject(hThread, SR_REMOTE_TIMEOUT);
	if (dwWaitRet != WAIT_OBJECT_0)
	{
		lastWin32Error = GetLastError();
		//!If thread doesn't become signaled(finished) we will treminate the thread
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_TIMEOUT;
	}

	CloseHandle(hThread);
	//! Returned address from shelcode execution is copied back to start of ShellCode(offset 0x0) at the instruction addrs:+0x18
	//! This returned address is read back from  allocated buffer pMem into the RemoteRet address to give value returned by pRoutine execution of ShellCode
	bRet = ReadProcessMemory(hTargetProc, pMem, &RemoteRet, sizeof(RemoteRet), nullptr);
	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
	if (!bRet)
	{
		lastWin32Error = GetLastError();
		return SR_NTCTE_ERR_RPM_FAIL;
	}

#else
	//? If not win64 then shellcoding is not used??
	HANDLE hThread = nullptr;

	NTSTATUS ntRet = p_NtCreateThreadEx(_Out_ & hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, pRoutine, pArg, 0, 0, 0, 0, nullptr);
	if (NT_FAIL(ntRet) || !hThread)
	{
		lastWin32Error = ntRet;
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
		return SR_NTCTE_ERR_NTCTE_FAIL;
	}
	//! This assigned handle shall be used in function WaitForSingleObject() to check if created thread has been changed to  Signalled state(which means exited/terminated for thread)
	DWORD dwWaitRet = WaitForSingleObject(hThread, SR_REMOTE_TIMEOUT);
	if (dwWaitRet != WAIT_OBJECT_0)
	{
		lastWin32Error = GetLastError();
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	}
	//! To retrieve returned value from the  thread's function we use GetExitCodeThread()
	DWORD dwRemoteRet = 0;
	BOOL bRet = GetExitCodeThread(hThread, &dwRemoteRet);
	if (!bRet)
	{
		lastWin32Error = GetLastError();
		CloseHandle(hThread);
		return SR_NTCTE_ERR_RPM_FAIL;

	}

	//? as we see above that the second parmeter of GetExitCodeThread function gives return value
	//? Of function executed by thread but it is in DWORd, so to get a baseAddress of DLL injection function, like LoadLibrary can't be used in x64 as will give only low 4 bytes
	//! So as GetExitCode gives only DWORD(32bit value) return of function can't be used in x64
	RemoteRet = dwRemoteRet;
	CloseHandle(hThread);
	return 0;

#endif

	return SR_ERR_SUCCESS;
}

DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& Out)
{
	return 0;
}

DWORD SR_SetWindowsHookEx(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& Out)
{
	return 0;
}

DWORD SR_QueueUserApc(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& Out)
{
	return 0;
}
