#include"Start Routine.h"

#define DLL_PATH_X86  TEXT("E:\\GameMod\\crackme\\earlier crackmes assorted\\HelloWorld Dll\\hello-world-x86.dll")
#define DLL_PATH_X64  TEXT("E:\\GameMod\\crackme\\earlier crackmes assorted\\HelloWorld Dll\\hello-world-x64.dll")

//? use of conditional macros to define different versions on basis of build configurations x86 or x64
//? _WIN64 IS USED TO DEFINE and choose THE build version of x64 build

#define PROCESS_NAME_X86 TEXT("Test Console - X86.exe")
#define PROCESS_NAME_X64 TEXT("learngamehacking1.exe")

#define LOAD_LIBRARY_NAME_A  "LoadLibraryA"
#define LOAD_LIBRARY_NAME_W  "LoadLibraryW"

#ifdef UNICODE
#define LOAD_LIBRARY_NAME LOAD_LIBRARY_NAME_W
#else
#define LOAD_LIBRARY_NAME LOAD_LIBRARY_NAME_A
#endif


#ifdef _WIN64
#define DLL_PATH           DLL_PATH_X64
#define PROCESS_NAME       PROCESS_NAME_X64
#else 
#define DLL_PATH           DLL_PATH_X86
#define PROCESS_NAME       PROCESS_NAME_X86
#endif

HANDLE GetProcessByName(const TCHAR* szProcName, DWORD dwDeisredAccess = PROCESS_ALL_ACCESS)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return nullptr;
	}
	PROCESSENTRY32  PE32{ 0 };
	PE32.dwSize = sizeof(PE32);
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{
		if (!_tcsicmp(PE32.szExeFile, szProcName))
			break;
		bRet = Process32Next(hSnap, &PE32);
	}
	CloseHandle(hSnap);
	if (!bRet)
		return nullptr;
	return OpenProcess(dwDeisredAccess, FALSE, PE32.th32ProcessID);
}

bool Injectdll(const TCHAR* szProcess, const TCHAR* szPath, LAUNCH_METHOD Method)
{
	HANDLE hProc = GetProcessByName(szProcess);
	if (!hProc)
	{
		DWORD dwError = GetLastError();
		printf("OpenProcess failed: 0x%08x\n", dwError);

		return false;
	}

	//!Creating dll-path by virtual allocating memeory
	//? len is calculated to take care whether in unicode or ansi style
	auto len = _tcslen(szPath) * sizeof(TCHAR);
	//!Allocate virtualmemory for size of dll path name
	void* pArg = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pArg)
	{
		DWORD dwError = GetLastError();
		printf("VirtualallocEx failed to allcate dllPath name: 0x%08x\n", dwError);
		//? If virtualallocEx failed close the handle opened by Openprocess
		CloseHandle(hProc);
		return false;
	}
	//! write the Dll path to the allocated virtual memory before by writeprocessmemory
	BOOL bRet = WriteProcessMemory(hProc, pArg, szPath, len, nullptr);
	if (!bRet)
	{
		DWORD dwError = GetLastError();
		printf("Writeprocessmemory failed : 0x%08x\n", dwError);
		//? If WPM failed release the memory allocated using VirtualFreeEx
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return false;

	}
	//! Finding LOadLibrary address using our custom GetprocAddressEx function(pe-headr parsing)
	f_Routine* p_LoadLibrary = reinterpret_cast<f_Routine*>(GetProcAddressEx(hProc, TEXT("kernel32.dll"), LOAD_LIBRARY_NAME));
	if (!p_LoadLibrary)
	{
		printf("Can't find LoadLibrary\n");
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return false;

	}
	UINT_PTR hDllOut = 0;
	DWORD last_error = 0;
	DWORD dwError = StartRoutine(hProc, p_LoadLibrary, pArg, Method, last_error, hDllOut);

	//todo to understand why deallocation can be done only in case when method is not LM_OueueUserApc
	//? why deallocation at LM_QUEUEuserApc corrupts the stack and crashing of other threads
	if (Method != LM_QueueUserAPC) 
	{

		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
	}
	CloseHandle(hProc);

	if (dwError) //! dwError are the error codes defined as macro earlier
	{
		printf("StartRoutine failed: 0x%08x\n", dwError);
		printf("     LastWin32Error: 0x%08x\n", last_error);
		return false;
	}
	printf("Success LoadLibrary returned 0x%p\n", reinterpret_cast<void*>(hDllOut));
	return true;
}

int main()
{
	bool bRet = Injectdll(PROCESS_NAME, DLL_PATH, LM_NtCreateThreadEx);
	//!To log various error function is returning bool true value on success and std::cin.get() is used to stop till keyboard input.
	if (!bRet)
	{
		printf("Press enter to exit.\n");

		std::cin.get(); //! To wait untill a keyboard input is given by user
	}

	return 0;
}