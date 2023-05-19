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
	//! first all threads are being enumerated CreateToolHelp32snapshot()
	THREADENTRY32 TE32{ 0 };
	TE32.dwSize = sizeof(TE32);
	//! returns open handle of snapshot of all threads in the process
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		lastWin32Error = GetLastError();
		return SR_HT_ERR_TH32_FAIL;
	}

	DWORD dwTargetPID = GetProcessId(hTargetProc); // Get traget process id
	DWORD dwThreadId{};

	//!Thread32first function retrieves information about the first thread in as per handle of all thread snapshot and stores in THREADENTRY32 structure
	BOOL bRet = Thread32First(hSnap, &TE32);
	if (!bRet)
	{
		lastWin32Error = GetLastError();
		CloseHandle(hSnap);
		return SR_HT_ERR_T32FIRST_FAIL;

	}
	do
	{
		//! Trying to find a thread in targeted process id using open snapshot of threads
		//! When the threadowner processid matches the target process id 
		if (TE32.th32OwnerProcessID == dwTargetPID)
		{
			dwThreadId = TE32.th32ThreadID;
			break;
		}
	//!if the thread owner processId does not match the targetProcess id we search next thread
	
		bRet = Thread32Next(hSnap, &TE32);

	} while (bRet);
	if (!dwThreadId)
	{
		return SR_HT_ERR_NO_THREADS;
	}
	 //! open handle to the thread as per deesired security access righhts
	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, dwThreadId);
	
	if (!hThread) //Error checking if open thread fails
	{
		lastWin32Error = GetLastError();
		return SR_HT_ERR_OPEN_THREAD_FAIL;

	}

	//! SuspendThread returns previous suspendcount if succeeding
	if (SuspendThread(hThread) == (DWORD)-1) //! SuspendThread error check
	{
		lastWin32Error = GetLastError();
		CloseHandle(hThread);
		return SR_HT_ERR_SUSPEND_FAIL;

	}

	//! Get Context information of thread whcih was suspended from CONTEXT structutre
	//! The value of ContextFlags field of structure determines the output captured by _CONTEXT structure in GetThreadContext() function
	CONTEXT OldContext{};
	//todo to know why not CONTEXT_ALL flag is used to capture the suspended thread all of the context
	OldContext.ContextFlags = CONTEXT_CONTROL; //! Copies the thread context as CONTEXT_CONTROL flag
	if (!GetThreadContext(hThread, &OldContext)) //! function returns non-zero if succeeeds
	{
		lastWin32Error = GetLastError();
		ResumeThread(hThread); // Resume thread back if GetThreadContext fails
		CloseHandle(hThread);
		return SR_HT_ERR_SUSPEND_FAIL;

	}

	void* pCodeCave = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //! to be able to readwrite aND EXECEUTE on the page
	if (!pCodeCave)
	{
		lastWin32Error = GetLastError();
		ResumeThread(hThread);
		CloseHandle(hThread);

		return SR_HT_ERR_CANT_ALLOC_MEM;

	}
	return 0;
}
// sTEPS TO GENERATE THE SHELLCODE FOR	execution of change of context of suspendedd thread to our code

#ifdef _WIN64

BYTE ShellCode[] = 
{
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,   //!adrs- 0x08 -> returned value from shell execution

0x48,0x83,0xec,0x08,   //!adrs +0x00   -> sub rsp,0x08 ; fixed_stack_allocation to push RipValue after shell code execution

0xc7,0x04, 0x24,0x00,0x00,0x00,0x00, //! adrs +0x04(start+0x07) -> mov [rsp],RipLowPart; 
0xc7,0x44, 0x24,0x04,0x00,0x00,0x00,0x00, //! adrs+ 0x0b(+0x0f) -> mov [rsp+0x04],RipHighPart

0x50,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,//! adrs+0x13 -> push r(a/c/d/)x / r(8-11):: save all volatile registers on the stack

0x9C, //! adrs + 0x1E	 -> pushfq :: save the rflags register on stack

0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//! adrs + 0x1F (+ 0x21)	-> mov rax, pRoutine:: will save the address of the routine to be executed in RAX register

0x48,0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//! adrs+ 0x29 (+ 0x2B)-> mov rcx, pArg:: This will save the address of the argument(first parameter) to pRoutine in RCX register for call

0x48,0x83,0xEC,0x20,//!adrs + 0x33 -> sub rsp, 0x20:: again  stach_fixed_allocation_size generated for home/shadow space as per MS x64 ABI
0xFF,0xD0, //! adrs + 0x37	-> call rax:: pRoutine address saved in rax(at adrs+0x1f) called 

//?Sort of epilog for the routine called up by rax i.e pRoutine

0x48, 0x83, 0xC4, 0x20,	//! addrs + 0x39 -> add rsp, 0x20:: function epilogue: deallocation of the fixed part of stack
0x48, 0x8D, 0x0D, 0xB4, 0xFF, 0xFF, 0xFF,//! addrs+ 0x3D	-> lea rcx, [pCodecave] :: This instruction saves the start of shellcode adrs into rcx . So RCX now contains shellcode begin adrs
0x48, 0x89, 0x01, //! adrs + 0x44	-> mov [rcx], rax :: Save the return value of pRoutine executed in the address pointed to be RCX. Which is start address of ShellCode
0x9D, //! adrs + 0x47	 -> popfq :: Unwinding of data for function epilogue return.Pops off the Rflags from stack and restores rFlags register
0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,//!adrs + 0x48-> pop r(11-8) / r(d/c/a)x :: Restore value of volatile registers pushed onto stack and increment stack pointer

0xC6, 0x05, 0xA9, 0xFF, 0xFF, 0xFF, 0x00,//! addrs + 0x53	-> mov byte ptr[$ - 0x57], 0

0xC3 //! addrss + 0x5A	 -> ret :: pops of the value of address saved onto the stack into RIP and and Increment the Stack poinet by 64bit or 8 bytes
}; // SIZE = addrss+0x5B (start_shellCode+ 0x08)

DWORD FuncOffset = 0x08; 



#else

#endif










DWORD SR_SetWindowsHookEx(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& Out)
{
	return 0;
}

DWORD SR_QueueUserApc(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& Out)
{
	return 0;
}
