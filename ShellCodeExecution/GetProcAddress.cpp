#include "GetProcAddress.h"

HINSTANCE GetModuleHandleEx(HANDLE hTargetProc, const TCHAR* lpModuleName)
{
	MODULEENTRY32	me32{};
	me32.dwSize = sizeof(me32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE) 
	{
		while (GetLastError() == ERROR_BAD_LENGTH) 
		{
			hSnap= CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
			if (hSnap != INVALID_HANDLE_VALUE)
				break;
		}
	}

	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	BOOL bRet = Module32First(hSnap, &me32);
	do
	{
		if (!_tcsicmp(lpModuleName, me32.szModule))
			break;
		bRet = Module32Next(hSnap, &me32);
	} while (bRet);
	CloseHandle(hSnap);
	if (!bRet)
	{

		return NULL;

	}

	return me32.hModule;
}

//! custom get_process_address function by parsing PE file IMAGE_EXPORT_DIRECTORY structure
void* GetProcAddressEx(HANDLE hTargetProc, const TCHAR* lpModuleName, const char* lpProcName)
{
	BYTE* modBase = reinterpret_cast<BYTE*>(GetModuleHandleEx(hTargetProc, lpModuleName));
	if (!modBase)
		return nullptr;
	BYTE* pe_header = new BYTE[0X1000]; //! pe_header as a target buffer
	if (!pe_header)
		return nullptr;

	//! Copytarget_process address_space memory details to allocated pe_header buffer

	if (!ReadProcessMemory(hTargetProc, modBase, pe_header, 0x1000, nullptr))
	{
		delete[] pe_header; //! on failure of readProcessMemory deallocate the buffer
		return nullptr;

	}
	//! Fields of pe_header and nt_header can be accessed as mapped memory has been copied
	auto* pNT = reinterpret_cast<IMAGE_NT_HEADERS*>(pe_header + reinterpret_cast<IMAGE_DOS_HEADER*>(pe_header)->e_lfanew);
	auto* pOrigExportEntry = &(pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]); //todo RVA OF image_directory_entry_export 

	if (!pOrigExportEntry->Size)
	{
		delete[] pe_header;
		return nullptr;
	}
  //!Allocating new memory for export_data_directory to be copied
	BYTE* bufferred_export_data = new BYTE[pOrigExportEntry->Size];

	if (!bufferred_export_data)
	{
		delete[] pe_header;
		return nullptr;
	}
	//!ReadProcessMemory to read the export_directory and copy it to our buffer
	if (!(ReadProcessMemory(hTargetProc, modBase + pOrigExportEntry->VirtualAddress, bufferred_export_data, pOrigExportEntry->Size, nullptr)))
	{
		//!deallocation on failure
		delete[] bufferred_export_data;
		delete[] pe_header;
		return nullptr;
	}
	//? Subtracting the base address of "buffered/copied" image_directory_entry_export 
	//? with the RVA of actual/original  export_directory_table to get local modBase
	BYTE* localBase = bufferred_export_data - pOrigExportEntry->VirtualAddress;
	
	//! Now cast the export_data as new buffered/copied Image_Export_Directory
	PIMAGE_EXPORT_DIRECTORY pBufferedExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(bufferred_export_data);

	//!Lambda for creating auto-forward refs for forwarded exports
	auto ForwardRefs = [&](DWORD FuncRVA)->void*
	{
		char pFullExportName[MAX_PATH + 1]{ 0 };
		size_t nameLength = strlen(reinterpret_cast<char*>(localBase + FuncRVA));
		if (!nameLength)
			return nullptr;
		memcpy(pFullExportName, reinterpret_cast<char*>(localBase + FuncRVA), nameLength);
		//strchr Returns pointer to first occurrence of character '.'
		char* pFuncName = strchr(pFullExportName, '.');
		*(pFuncName++) = 0;
		if (*pFuncName == '#')
			pFuncName = reinterpret_cast<char*>(LOWORD(atoi(++pFuncName)));
#ifdef UNICODE
		TCHAR  ModNameW[MAX_PATH + 1]{ 0 };
		size_t Sizeout = 0;
		mbstowcs_s(&Sizeout, ModNameW, pFullExportName, MAX_PATH);

		return GetProcAddressEx(hTargetProc, ModNameW, pFuncName);
#else
		return GetProcAddressEx(hTargetProc, pFullExportName, pFuncName);

#endif

	};

	if ((reinterpret_cast<UINT_PTR>(lpProcName) & 0xffffff) <= MAXWORD )
	{
		//? why one is subtracted from here still has to be verified
		WORD Base = LOWORD(pBufferedExportDir->Base - 1);
		//! If LPPROCNAME does not contain function names but instead contain Base-indexedordinals
		//! Then as these ordinals are not zero indexed, 
		WORD Ordinal = LOWORD(lpProcName) - Base;
		DWORD FuncRva = reinterpret_cast<DWORD*>(localBase + pBufferedExportDir->AddressOfFunctions)[Ordinal];
		delete[]bufferred_export_data;
		delete[]pe_header;

		if (!FuncRva)
			return nullptr;
		//! Check if the RVA in AddressOffunctions is having value greater than size in exportdirectory
		//! In that condition it is Rva forwarded to some other Dll so use Lambda to create the function name 
		if (FuncRva >= pOrigExportEntry->VirtualAddress && FuncRva < (pOrigExportEntry->VirtualAddress + pOrigExportEntry->Size))
		{
			return ForwardRefs(FuncRva);
		}
		//!If not forwarder ref than return the actual Virtual address of the exported functions
		return modBase + FuncRva;
	}

	DWORD max = pBufferedExportDir->NumberOfNames - 1;
	DWORD min = 0;
	DWORD FuncRva = 0;

	//!As the names are arranged in lexicological order, binary  serch implemented as learncpp
	while (min <= max)
	{
		DWORD mid = (min + max) / 2;
		DWORD CurrNameRva = reinterpret_cast<DWORD*>(localBase + pBufferedExportDir->AddressOfNames)[mid]; //! Find current index of the procedure 
		char* szName = reinterpret_cast<char*>(localBase + CurrNameRva);

		int cmp = strcmp(szName, lpProcName);
		if (cmp < 0)
			min = mid + 1;
		else if (cmp > 0)
			max = mid - 1;
		else
		{
			//!Same procedure index is used to loop in ordinalTable to find based ordinal for AddressOfFunctions array
			WORD ordinal = reinterpret_cast<WORD*>(localBase + pBufferedExportDir->AddressOfNameOrdinals)[mid]; 
			FuncRva = reinterpret_cast<DWORD*>(localBase + pBufferedExportDir->AddressOfFunctions)[ordinal];
			break;

		}
	}
	
	delete[] bufferred_export_data;
	delete[] pe_header;

	if (!FuncRva)
		return nullptr;
	//! Check if the RVA in AddressOffunctions is having value greater than size in exportdirectory
		//! In that condition it is Rva forwarded to some other Dll so use Lambda to create the function name 
	if (FuncRva >= pOrigExportEntry->VirtualAddress && FuncRva < (pOrigExportEntry->VirtualAddress + pOrigExportEntry->Size))
	{
		return ForwardRefs(FuncRva);
	}
	//!If not forwarder ref than return the actual Virtual address of the exported functions
	return modBase + FuncRva;
}
