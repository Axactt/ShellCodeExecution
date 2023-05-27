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

DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& RemoteRet)
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

	// sTEPS TO GENERATE THE SHELLCODE FOR	execution of change of context of suspendedd thread to our code

#ifdef _WIN64

	BYTE ShellCode[] =
	{
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,   //!adrs- 0x08 -> returned value from shell execution

	0x48,0x83,0xec,0x08,   //!adrs +0x00   -> sub rsp,0x08 ; fixed_stack_allocation to push RipValue after shell code execution

	0xc7,0x04, 0x24,0x00,0x00,0x00,0x00, //! adrs +0x04 (start+0x07) -> mov [rsp],RipLowPart; 
	0xc7,0x44, 0x24,0x04,0x00,0x00,0x00,0x00, //! adrs+ 0x0b (+0x0f) -> mov [rsp+0x04],RipHighPart

	0x50,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,//! adrs+0x13 -> push r(a/c/d/)x / r(8-11):: save all volatile registers on the stack

	0x9C, //! adrs + 0x1E	 -> pushfq :: save the rflags register on stack

	0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//! adrs + 0x1F  (+ 0x21)	-> mov rax, pRoutine:: will save the address of the routine to be executed in RAX register

	0x48,0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//! adrs+ 0x29  (+ 0x2B)-> mov rcx, pArg:: This will save the address of the argument(first parameter) to pRoutine in RCX register for call

	0x48,0x83,0xEC,0x20,//!adrs + 0x33 -> sub rsp, 0x20:: again  stach_fixed_allocation_size generated for home/shadow space as per MS x64 ABI

	0xFF,0xD0, //! adrs + 0x37	-> call rax:: pRoutine address saved in rax(at adrs+0x1f) called 

	//?Sort of epilog for the routine called up by rax i.e pRoutine

	0x48, 0x83, 0xC4, 0x20,	//! addrs + 0x39 -> add rsp, 0x20:: function epilogue: deallocation of the fixed part of stack

	//?:: This instruction saves the start of shellcode adrs into rcx . So RCX now contains shellcode begin adrress 
	//? .PIC with RIP relative addressing used  to load the shellcode beginning address in rcx using LEA
	0x48, 0x8D, 0x0D, 0xB4, 0xFF, 0xFF, 0xFF,//! addrs+ 0x3D	-> lea rcx, [pCodecave] 

	//todo after following  instruction executed in shellcode; ReadProcessMemory can be used on ShellCode-start address to get pRoutine function Result Value
	0x48, 0x89, 0x01, //! adrs + 0x44	-> mov [rcx], rax :: Save the return value of pRoutine executed in the address pointed to be RCX. Which is start address of ShellCode


	0x9D, //! adrs + 0x47	 -> popfq :: Unwinding of data for function epilogue return.Pops off the Rflags from stack and restores rFlags register


	0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,//!adrs + 0x48-> pop r(11-8) / r(d/c/a)x :: Restore value of volatile registers pushed onto stack and increment stack pointer

	0xC6, 0x05, 0xA9, 0xFF, 0xFF, 0xFF, 0x00,//??  addrs + 0x53	-> mov byte ptr[$ - 0x57], 0 Sort of Check-Byte Routine in shellcode to confirm later That Shellcode execution has finished

	0xC3 //! addrss + 0x5A	 -> ret :: pops of the value of address saved onto the stack into RIP and and Increment the Stack poinet by 64bit or 8 bytes
	}; // SIZE = addrss+0x5B (start_shellCode+ 0x08)

	//? Initially we have kept all memory references of loaction addresses inside Shellcode to be 0x00
	//? The following code writes up the loaction with desired value like OLDRIP, pRoutine, pARG etc


	DWORD FuncOffset = 0x08;  //! Shellcode_start_addrs + 0x08
	DWORD CheckByteOffset = 0x03 + FuncOffset;

	DWORD dwLoRIP = (DWORD)(OldContext.Rip & 0xffffffff);//! Getting Low 32 bit part of Old Rip from Old thread Context
	DWORD dwHiRIP = (DWORD)(((OldContext.Rip) >> 0x20) & 0xffffffff);//! Getting High 32 bits part of Old Rip from Old thread Context

	//! writing value of old Rip at the earlier designated position in ShellCode.
	//! So RIP can be used while returning back in shellcode using RET isnatruction
	*reinterpret_cast<DWORD*>(ShellCode + FuncOffset + 0x07) = dwLoRIP;
	*reinterpret_cast<DWORD*>(ShellCode + FuncOffset + 0x0f) = dwHiRIP;

	//!writing value of PRoutine(desired func for execution) and pArg(parameter desired func)\

	*reinterpret_cast<void**>(ShellCode + FuncOffset + 0x21) = pRoutine;
	*reinterpret_cast<void**>(ShellCode + FuncOffset + 0x2b) = pArg;

//!Update instruction pointer into Oldcontext to start executing at addrs OR shellcode+0x08
	
OldContext.Rip = reinterpret_cast<UINT_PTR>(pCodeCave) + FuncOffset;


#else

	//! shelllCode for x86 or 32 bit execution
	BYTE ShellCode[] =
	{
		0x00, 0x00, 0x00, 0x00,					// - 0x04 (pCodecave)	-> returned value	;buffer to store returned value (eax)

		0x83, 0xEC, 0x04,							// + 0x00				-> sub esp, 0x04							;prepare stack for ret
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	// + 0x03 (+ 0x06)		-> mov [esp], OldEip						;store old eip as return address

		0x50, 0x51, 0x52,							// + 0x0A				-> psuh e(a/c/d)							;save e(a/c/d)x
		0x9C,										// + 0x0D				-> pushfd									;save flags register

		0xB9, 0x00, 0x00, 0x00, 0x00,				// + 0x0E (+ 0x0F)		-> mov ecx, pArg							;load pArg into ecx
		0xB8, 0x00, 0x00, 0x00, 0x00,				// + 0x13 (+ 0x14)		-> mov eax, pRoutine

		0x51,										// + 0x18				-> push ecx									;push pArg
		0xFF, 0xD0,									// + 0x19				-> call eax									;call target function

		0xA3, 0x00, 0x00, 0x00, 0x00,				// + 0x1B (+ 0x1C)		-> mov dword ptr[pCodecave], eax			;store returned value

		0x9D,										// + 0x20				-> popfd									;restore flags register
		0x5A, 0x59, 0x58,							// + 0x21				-> pop e(d/c/a)								;restore e(d/c/a)x

		0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,	// + 0x24 (+ 0x26) -> mov byte ptr[pCodecave + 0x06], 0x00		                                            ;set checkbyte to 0

		0xC3										// + 0x2B				-> ret										;return to OldEip
	}; // SIZE = 0x2C (+ 0x04)

	//? Writing values of oldrip, proutine, parg, pCodeCave external variables in shellcode same as done for x64 portion
	DWORD FuncOffset = 0x04; //! This is reference or Datum from Shellcode start for all addreess calculations
	DWORD CheckByteOffset = 0x02 + FuncOffset; 

	*reinterpret_cast<DWORD*>(ShellCode + FuncOffset + 0x06) = OldContext.Eip;

	*reinterpret_cast<void**>(ShellCode + FuncOffset + 0x0f) = pArg;
	*reinterpret_cast<void**>(ShellCode + FuncOffset + 0x14) = pRoutine;

	*reinterpret_cast<void**>(ShellCode + FuncOffset + 0x1c) = pCodeCave;
	*reinterpret_cast<BYTE**>(ShellCode + FuncOffset + 0x26) = reinterpret_cast<BYTE*>(pCodeCave) + CheckByteOffset;

	OldContext.Eip = reinterpret_cast<DWORD>(pCodeCave) + FuncOffset;

#endif
	//! Will write shellcode to the codeCave using WPM
	if (!WriteProcessMemory(hTargetProc, pCodeCave, ShellCode, sizeof(ShellCode), nullptr))
	{
		lastWin32Error = GetLastError();

		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);
		return SR_HT_ERR_SET_CONTEXT_FAIL;
	}

	//! Newly open handle hThread used to setContecxt to New updtaed ontext after shell code execution. Named a s OldContext but is actually new because Intruction pointer have already been updated by now
	
	if (!SetThreadContext(hThread, &OldContext))
	{
		lastWin32Error = GetLastError();

		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);

		return SR_HT_ERR_SET_CONTEXT_FAIL;

	}
	 //! Check if ResumeThread fails and gives error value
	if (ResumeThread(hThread) == (DWORD)-1)
	{
		lastWin32Error = GetLastError();

		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);
		return SR_HT_ERR_RESUME_FAIL;

	}

	CloseHandle(hThread);
	 //todo following is a check for successful shellcode execution , To be chaneged to better check
	DWORD Timer = GetTickCount(); //! Setting a value of timer in code at this point of execution
	BYTE CheckByte = 1;
	
	//! here we are setting a value of CheckByte different from Zero;
	//! zero value will be set on Successful execution of shellcode completion
	do
	{
		ReadProcessMemory(hTargetProc, reinterpret_cast<BYTE*>(pCodeCave) + CheckByteOffset, &CheckByte, 1, nullptr);

		if (GetTickCount() - Timer > SR_REMOTE_TIMEOUT)
		{
			return SR_HT_ERR_TIMEOUT;

		}
		Sleep(10);
	} while (CheckByte != 0);

	// Read out the bytes from pCodeCave to RemoeRet buffer address 
	ReadProcessMemory(hTargetProc, pCodeCave, &RemoteRet, sizeof(RemoteRet), nullptr);

	VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);

	return SR_ERR_SUCCESS;

}



DWORD SR_SetWindowsHookEx(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& RemoteRet)
{
	void* pCodeCave = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pCodeCave)
	{
		lastWin32Error = GetLastError();
		return SR_SWHEX_ERR_CANT_ALLOC_MEM;
	}

	//Entering a hoook in hook chain. 
  // to make sure all hooks in chain get executed
	void* pCallNextHookEx = GetProcAddressEx(hTargetProc, TEXT("user32.dll"), "CallNextHookEx");
	if (!pCallNextHookEx)
	{
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);
		
		lastWin32Error = GetLastError();
		
		return SR_SWHEX_ERR_CNHEX_MISSING;

	}
#ifdef _WIN64
	BYTE ShellCode[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// - 0x18	-> pArg / returned value / rax	;buffer
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// - 0x10	-> pRoutine						;pointer to target function
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// - 0x08	-> CallNextHookEx				;pointer to CallNextHookEx

		0x55,											// + 0x00	-> push rbp						;save important registers
		0x54,											// + 0x01	-> push rsp
		0x53,											// + 0x02	-> push rbx

		0x48, 0x8D, 0x1D, 0xDE, 0xFF, 0xFF, 0xFF,	// + 0x03	-> lea rbx, [pArg]; load pointer into rbx (as Position-Independent-Code RIP relative addressing is used this will load address of rip+0xff ffffDE into RBX) which is start of shellcode

		0x48, 0x83, 0xEC, 0x20,							// + 0x0A	-> sub rsp, 0x20				;reserve stack
		0x4D, 0x8B, 0xC8,								// + 0x0E	-> mov r9,r8	;set up arguments for CallNextHookEx
		0x4C, 0x8B, 0xC2,								// + 0x11	-> mov r8, rdx
		0x48, 0x8B, 0xD1,								// + 0x14	-> mov rdx,rcx
		0xFF, 0x53, 0x10,								// + 0x17	-> call [rbx + 0x10]			;call CallNextHookEx
		0x48, 0x83, 0xC4, 0x20,							// + 0x1A	-> add rsp, 0x20				;update stack

		0x48, 0x8B, 0xC8,								// + 0x1E	-> mov rcx, rax					;copy retval into rcx

		0xEB, 0x00,										// + 0x21	-> jmp $ + 0x02					;jmp to next instruction
		0xC6, 0x05, 0xF8, 0xFF, 0xFF, 0xFF, 0x18,		// + 0x23	-> mov byte ptr[$ - 0x01], 0x1A	;hotpatch jmp above to skip shellcode:: This to ensure shellcode only execute once

		0x48, 0x87, 0x0B,								// + 0x2A	-> xchg [rbx], rcx				;store CallNextHookEx retval, load pArg
		0x48, 0x83, 0xEC, 0x20,							// + 0x2D	-> sub rsp, 0x20				;reserve stack
		0xFF, 0x53, 0x08,								// + 0x31	-> call [rbx + 0x08]			;call pRoutine
		0x48, 0x83, 0xC4, 0x20,							// + 0x34	-> add rsp, 0x20				;update stack

		0x48, 0x87, 0x03,								// + 0x38	-> xchg [rbx], rax				;store pRoutine retval, restore CallNextHookEx retval

		0x5B,											// + 0x3B	-> pop rbx						;restore important registers
		0x5C,											// + 0x3C	-> pop rsp
		0x5D,											// + 0x3D	-> pop rbp

		0xC3											// + 0x3E	-> ret							;return
	}; // SIZE = 0x3F (+ 0x18)

	DWORD CodeOffset = 0x18;
	DWORD CheckByteOffset = 0x22 + CodeOffset;

	*reinterpret_cast<void**>(ShellCode + 0x00) = pArg;
	*reinterpret_cast<void**>(ShellCode + 0x08) = pRoutine;
	*reinterpret_cast<void**>(ShellCode + 0x10) = pCallNextHookEx;

#else
	BYTE ShellCode[] =
	{
		0x00, 0x00, 0x00, 0x00,			// - 0x08				-> pArg						;pointer to argument
		0x00, 0x00, 0x00, 0x00,			// - 0x04				-> pRoutine					;pointer to target function

		0x55,							// + 0x00				-> push ebp					;x86 stack frame creation
		0x8B, 0xEC,						// + 0x01				-> mov ebp, esp

		0xFF, 0x75, 0x10,				// + 0x03				-> push [ebp + 0x10]		;push CallNextHookEx arguments
		0xFF, 0x75, 0x0C,				// + 0x06				-> push [ebp + 0x0C] 
		0xFF, 0x75, 0x08, 				// + 0x09				-> push [ebp + 0x08]
		0x6A, 0x00,						// + 0x0C				-> push 0x00
		0xE8, 0x00, 0x00, 0x00, 0x00,	// + 0x0E (+ 0x0F)		-> call CallNextHookEx		;call CallNextHookEx

		0xEB, 0x00,						// + 0x13				-> jmp $ + 0x02				;jmp to next instruction

		0x50,							// + 0x15				-> push eax					;save eax (CallNextHookEx retval)
		0x53,							// + 0x16				-> push ebx					;save ebx (non volatile)

		0xBB, 0x00, 0x00, 0x00, 0x00,	// + 0x17 (+ 0x18)		-> mov ebx, pArg			;move pArg (pCodecave) into ebx
		0xC6, 0x43, 0x1C, 0x14,			// + 0x1C				-> mov [ebx + 0x1C], 0x17	;hotpatch jmp above to skip shellcode

		0xFF, 0x33,						// + 0x20				-> push [ebx]				;push pArg (__stdcall)

		0xFF, 0x53, 0x04,				// + 0x22				-> call [ebx + 0x04]		;call target function

		0x89, 0x03,						// + 0x25				-> mov [ebx], eax			;store returned value

		0x5B,							// + 0x27				-> pop ebx					;restore old ebx
		0x58,							// + 0x28				-> pop eax					;restore eax (CallNextHookEx retval)

		0x5D,							// + 0x29				-> pop ebp					;restore ebp
		0xC2, 0x0C, 0x00				// + 0x2A				-> ret 0x000C				;return
}; // SIZE = 0x3D (+ 0x08)

	DWORD CodeOffset = 0x08;
	DWORD CheckByteOffset = 0x14 + CodeOffset;

	*reinterpret_cast<void**>(ShellCode + 0x00) = pArg;
	*reinterpret_cast<void**> (ShellCode + 0x04) = pRoutine;

	//! writing relative address of control instructions for pCallNextHookex relative to next eip
	//! In x86 all memory and Data references are not PIC, So RIP relative addressing cannot be used with lea instruction
	*reinterpret_cast<DWORD*>(ShellCode + 0x0F + CodeOffset) = reinterpret_cast<DWORD>(pCallNextHookEx) - ((reinterpret_cast<DWORD>(pCodeCave) + 0x0e + CodeOffset) + 5);

	*reinterpret_cast<void**>(ShellCode + 0x18 + CodeOffset) = pCodeCave; 
#endif
	if (!WriteProcessMemory(hTargetProc, pCodeCave, ShellCode, sizeof(ShellCode), nullptr))
	{
		lastWin32Error = GetLastError();
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);

		return SR_SWHEX_ERR_WPM_FAIL;

	}

	static EnumWindowsCallBack_Data data; //! Made static so that lambda can capture it and pass it back to EnumwindowsCallBackProc

	data.m_pHook = reinterpret_cast<HOOKPROC>(reinterpret_cast<BYTE*>(pCodeCave) + CodeOffset);
	data.m_PID = GetProcessId(hTargetProc);
	data.m_hModule = GetModuleHandle(TEXT("user32.dll"));

	//!An application - defined callback function used with the EnumWindows or 
	//! EnumDesktopWindows function.It receives top - level window handles.The 
	//? WNDENUMPROC type defines a pointer to this callback function.
	//! so as Lambda can be given a type of std::function,it can be defined as Callback
	//! To continue enumeration, the callback function must return TRUE; 
	//! to stop enumeration, it must return FALSE. BOOL CALLBACK EnumWindowsProc

	WNDENUMPROC EnumWindowsCallBack = [](HWND hWnd, LPARAM)-> BOOL
	{
		DWORD winPID = 0;
		DWORD winTID = GetWindowThreadProcessId(hWnd, &winPID);
		if (winPID == data.m_PID)
		{
			TCHAR szWindow[MAX_PATH]{ 0 };
			if (IsWindowVisible(hWnd) && GetWindowText(hWnd, szWindow, MAX_PATH))
			{
				if (GetClassName(hWnd, szWindow, MAX_PATH) && _tcscmp(szWindow, TEXT("ConsoleWindowClass")))
				{
					HHOOK hHook = SetWindowsHookEx(WH_CALLWNDPROC, data.m_pHook, data.m_hModule, winTID);
					if (hHook)
					{
						data.m_HookData.push_back({ hHook,hWnd });
					}
				}
			}
		}
		return TRUE;
	};

	//!Enumerates all top-level windows on the screen by passing the handle to each 
	//! window, in turn, to an application-defined callback function. EnumWindows continues 
	//! until the last top-level window is enumerated or the callback function returns FALSE
	if (!EnumWindows(EnumWindowsCallBack, reinterpret_cast<LPARAM>(&data)))
	{
		lastWin32Error = GetLastError();
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);
		return SR_SWHEX_ERR_ENUM_WND_FAIL;
	}

	if (data.m_HookData.empty())
	{
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);
		return SR_SWHEX_ERR_NO_WINDOWS;

	}

	//!Retrieves a handle to the foreground window (the window with which the user is currently working)
	HWND hForeGroundWnd = GetForegroundWindow();

	for (auto i : data.m_HookData)
	{
		//!Brings the thread that created the specified window into the foregroundand activates the window.Keyboard input is directed to the window, and various visual cues are changed for the user.
		//! The system assigns a slightly //higher priority to the thread that created the foreground window than it does to other threads.
		
		SetForegroundWindow(i.m_hWnd);
		SendMessage(i.m_hWnd, WM_KEYDOWN, VK_SPACE, 0);
		Sleep(10);
		SendMessageA(i.m_hWnd, WM_IME_KEYUP, VK_SPACE, 0);
		UnhookWindowsHookEx(i.m_hHook);

	}
	//! Restore original foreground window as it was earlier
	SetForegroundWindow(hForeGroundWnd);

	DWORD Timer = GetTickCount();
	BYTE CheckByte = 0;

	do
	{
		//! checkByte to check if code ahs been executed in shellcodde
		ReadProcessMemory(hTargetProc, reinterpret_cast<BYTE*>(pCodeCave) + CheckByteOffset, &CheckByte, 1, nullptr);
		//! Check for a time-out during code execution
		if (GetTickCount() - Timer > SR_REMOTE_TIMEOUT)
		{
			return SR_SWHEX_ERR_TIMEOUT;
		}
		Sleep(10);
	} while (!CheckByte);

	ReadProcessMemory(hTargetProc, pCodeCave, &RemoteRet, sizeof(RemoteRet), nullptr);

	VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);

	return SR_ERR_SUCCESS;

	return 0;
}

DWORD SR_QueueUserApc(HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& Out)
{
	//!  sleepEx waitable object funtion to put thread in alertable wait mode
	//! This is required to queue an user mode apc to the thread 
	//! which calls the QueueUserApc function which is current thread here
	//! We will inject shellcode to targetprocess and queue shellcode as APC 
	//! to inject and execute shellcode in alertabel wait thread of the target process

	//? pCodeCave allocates memory in target Process for copying up of ShellCode excutable bytes
	void* pCodeCave = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pCodeCave)
	{
		lastWin32Error = GetLastError();
		return SR_QUAPC_ERR_CANT_ALLOC_MEM;

	}
	//! GENERATE AND ASSIGN SHELLCODE AT ALOCATED pcodeCave memory in targetProcess
#ifdef _WIN64
	BYTE ShellCode[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// - 0x18	-> returned value							;buffer to store returned value
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// - 0x10	-> pArg										;buffer to store argument
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// - 0x08	-> pRoutine									;pointer to the rouinte to call

		0xEB, 0x00,											// + 0x00	-> jmp $+0x02								;jump to the next instruction

		0x48, 0x8B, 0x41, 0x10,								// + 0x02	-> mov rax, [rcx + 0x10]					;move pRoutine into rax
		0x48, 0x8B, 0x49, 0x08,								// + 0x06	-> mov rcx, [rcx + 0x08]					;move pArg into rcx

		0x48, 0x83, 0xEC, 0x28,								// + 0x0A	-> sub rsp, 0x28							;reserve stack
		0xFF, 0xD0,											// + 0x0E	-> call rax									;call pRoutine
		0x48, 0x83, 0xC4, 0x28,								// + 0x10	-> add rsp, 0x28							;update stack

		0x48, 0x85, 0xC0,									// + 0x14	-> test rax, rax							;check if rax indicates success/failure
		0x74, 0x11,											// + 0x17	-> je pCodecave + 0x2A						;jmp to ret if routine failed

		0x48, 0x8D, 0x0D, 0xC8, 0xFF, 0xFF, 0xFF,			// + 0x19	-> lea rcx, [pCodecave]						;load pointer to codecave into rcx
		0x48, 0x89, 0x01,									// + 0x20	-> mov [rcx], rax							;store returned value

		0xC6, 0x05, 0xD7, 0xFF, 0xFF, 0xFF, 0x28,			// + 0x23	-> mov byte ptr[pCodecave + 0x18], 0x28		;hot patch jump to skip shellcode

		0xC3												// + 0x2A	-> ret										;return
	}; // SIZE = 0x2B (+ 0x10)

	DWORD CodeOffset = 0x18;
	*reinterpret_cast<void**>(ShellCode + 0x08) = pArg;
	*reinterpret_cast<void**>(ShellCode + 0x10) = pRoutine;

#else
	BYTE ShellCode[] =
	{
		0x00, 0x00, 0x00, 0x00, // - 0x0C	-> returned value					;buffer to store returned value
		0x00, 0x00, 0x00, 0x00, // - 0x08	-> pArg								;buffer to store argument
		0x00, 0x00, 0x00, 0x00, // - 0x04	-> pRoutine							;pointer to the routine to call

		0x55,					// + 0x00	-> push ebp							;x86 stack frame creation
		0x8B, 0xEC,				// + 0x01	-> mov ebp, esp

		0xEB, 0x00,				// + 0x03	-> jmp pCodecave + 0x05 (+ 0x0C)	;jump to next instruction

		0x53,					// + 0x05	-> push ebx							;save ebx
		0x8B, 0x5D, 0x08,		// + 0x06	-> mov ebx, [ebp + 0x08]			;move pCodecave into ebx (non volatile)

		0xFF, 0x73, 0x04,		// + 0x09	-> push [ebx + 0x04]				;push pArg on stack
		0xFF, 0x53, 0x08,		// + 0x0C	-> call dword ptr[ebx + 0x08]		;call pRoutine

		0x85, 0xC0,				// + 0x0F	-> test eax, eax					;check if eax indicates success/failure
		0x74, 0x06,				// + 0x11	-> je pCodecave + 0x19 (+ 0x0C)		;jmp to cleanup if routine failed

		0x89, 0x03,				// + 0x13	-> mov [ebx], eax					;store returned value
		0xC6, 0x43, 0x10, 0x15, // + 0x15	-> mov byte ptr [ebx + 0x10], 0x15	;hot patch jump to skip shellcode

		0x5B,					// + 0x19	-> pop ebx							;restore old ebx

		0x5D,					// + 0x1A	-> pop ebp							;restore ebp
		0xC2, 0x04, 0x00		// + 0x1B	-> ret 0x0004						;return
	}; // SIZE = 0x1E (+ 0x0C)

	DWORD CodeOffset = 0x0c;
	*reinterpret_cast<void**>(ShellCode + 0x04) = pArg;
	*reinterpret_cast<void**>(ShellCode + 0x08) = pRoutine;

#endif

	BOOL bRet = WriteProcessMemory(hTargetProc, pCodeCave, ShellCode, sizeof(ShellCode), nullptr);
	if (!bRet)
	{
		lastWin32Error = GetLastError();
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);
		return SR_QUAPC_ERR_WPM_FAIL;

	}
	//! Create a snapshot of all threads in the target proc
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE) //! error checka as createtool32snapshot returns Invalid_handle_valus
	{
		lastWin32Error = GetLastError();
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);
		return SR_QUAPC_ERR_TH32_FAIL;

	}

	DWORD TargetPID = GetProcessId(hTargetProc); // Copy of the target process id
	bool APCqueued = false;
	//! Creating a callback apc function to be called by QueueUserApc function
	PAPCFUNC pShellCode = reinterpret_cast<PAPCFUNC>(reinterpret_cast<BYTE*>(pCodeCave) + CodeOffset);
	THREADENTRY32 TE32{ 0 };
	TE32.dwSize = sizeof(TE32);

	bRet = Thread32First(hSnap, &TE32);
	if (!bRet)
	{
		lastWin32Error = GetLastError();
		CloseHandle(hSnap);
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE);
		return SR_QUAPC_ERR_T32FIRST_FAIL;

	}

	//??Opens Thread handle n Queues an Apc whcih is ShellCode to all the threads in TargetProcess id
	do
	{
		if (TE32.th32OwnerProcessID == TargetPID) //todo why  Check for ownerprocessId again as we already took snapshot in context of target process id
		{
			HANDLE  hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, TE32.th32ThreadID);
			if (hThread)
			{
				if (QueueUserAPC(pShellCode, hThread, reinterpret_cast<ULONG_PTR>(pCodeCave)))
				{
					// If suuccessful then apc queued state is set to true
					APCqueued = true;

				}
				else
				{
					lastWin32Error = GetLastError();
				}

				CloseHandle(hThread);

			}

		}

		bRet = Thread32Next(hSnap, &TE32);


	} while (bRet);

	CloseHandle(hSnap);

	if (!APCqueued)
	{
		VirtualFreeEx(hTargetProc, pCodeCave, 0, MEM_RELEASE); //! pCodeCave is allocated memory addrs for shellcode in Target process
		return SR_QUAPC_ERR_NO_APC_THREAD;

	}
	else
	{
		lastWin32Error = 0;
	}
	DWORD Timer = GetTickCount();
	Out = 0; //! output buffer to readProcesMemory passed as an l-value non-cont refernce UINT_PTR& out argument to function

	do
	{
		ReadProcessMemory(hTargetProc, pCodeCave, &Out, sizeof(Out), nullptr);
		if (GetTickCount() - Timer > SR_REMOTE_TIMEOUT)
		{
			return SR_SWHEX_ERR_TIMEOUT;
		}
		Sleep(10);
	} while (!Out);

	return SR_ERR_SUCCESS;
}
