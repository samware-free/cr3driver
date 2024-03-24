
#include "check.h"
#include "Func.h"
#include "xor.h"
#include <TlHelp32.h>
#include <winternl.h>
#include <intrin.h>
#include "CallStack-Spoofer.h"
uintptr_t virtualaddy;
uintptr_t base_address;
int process_id;
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)



#define code_rDTB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x91, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x92, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x93, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_get_guarded_region CTL_CODE(FILE_DEVICE_UNKNOWN, 0x94, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_move CTL_CODE(FILE_DEVICE_UNKNOWN, 0x95, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_spoof CTL_CODE(FILE_DEVICE_UNKNOWN, 0x96, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_unlock CTL_CODE(FILE_DEVICE_UNKNOWN, 0x97, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_security 0x76



static bool EAC = false;
typedef struct _readwrite {
	INT32 security;
	INT32 process_id;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN write;
	BOOLEAN EAC;
} rw, * prw;

typedef struct _MOUSE_REQUEST
{
	BOOLEAN click;
	BOOLEAN status;
	LONG dx;
	LONG dy;

} MOUSE_REQUEST, * PMOUSE_REQUEST;
typedef struct _dtb {
	INT32 security;
	INT32 process_id;
	bool* operation;
} dtb, * dtbl;
typedef struct _ba {
	INT32 security;
	INT32 process_id;
	ULONGLONG* address;
} ba, * pba;
struct comms_t {
	std::uint32_t key;

	struct {
		void* handle;
	}window;
};
typedef struct _hide {
	comms_t* a;
} hide, * hidea;
typedef struct _ga {
	INT32 security;
	ULONGLONG* address;
} ga, * pga;
typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;
typedef struct _cr {
  
    INT32 process_id;
} ca, * cra;



namespace mem {
	HANDLE driver_handle;
	INT32 process_id;

	bool find_driver() {
		SPOOF_FUNC;
		int	id[4];
		__cpuid(id, 1);
		wchar_t buffer[1];

		wsprintfW(buffer, L"\\\\.\\\%08X", id[0]);

		//	MessageBoxW(0, buffer, buffer, 0);

		driver_handle = CreateFileW(buffer, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (!driver_handle || (driver_handle == INVALID_HANDLE_VALUE))
			return false;

		return true;
	}

	void read_physical(PVOID address, PVOID buffer, DWORD size) {
		SPOOF_FUNC;
		_readwrite arguments = { 0 };

		arguments.security = code_security;
		arguments.address = (ULONGLONG)address - 201934901;
		arguments.buffer = (ULONGLONG)buffer - 21489184;
		arguments.size = size - 218949184;
		arguments.process_id = process_id - 214891894;
		arguments.write = FALSE;
		if (EAC)
			arguments.EAC = TRUE;
		else
			arguments.EAC = FALSE;

		DeviceIoControl(driver_handle, code_rw, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
		
	}

	void write_physical(PVOID address, PVOID buffer, DWORD size) {
		SPOOF_FUNC;
		_readwrite arguments = { 0 };

		arguments.security = code_security;
		arguments.address = (ULONGLONG)address - 201934901;
		arguments.buffer = (ULONGLONG)buffer - 21489184;
		arguments.size = size - 218949184;
		arguments.process_id = process_id - 214891894;
		arguments.write = TRUE;
		if (EAC)
			arguments.EAC = TRUE;
		else
			arguments.EAC = FALSE;

		DeviceIoControl(driver_handle, code_rw, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	bool CR3() {
		bool ret = false;
		_dtb arguments = { 0 };
		arguments.security = code_security;
		arguments.process_id = process_id;
		arguments.operation = (bool*)&ret;
		if (EAC)
		{
			DeviceIoControl(driver_handle, code_rDTB, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
		}
		else
		{
			return true;
		}

		return ret;
	}

	uintptr_t find_image() {
		SPOOF_FUNC;
		uintptr_t image_address = { NULL };
		_ba arguments = { NULL };

		arguments.security = code_security;
		arguments.process_id = process_id;
		arguments.address = (ULONGLONG*)&image_address;

		DeviceIoControl(driver_handle, code_ba, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

		return image_address;
	}
	

	INT32 find_process(LPCTSTR process_name) {
		SPOOF_FUNC;
		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, process_name)) {
					CloseHandle(hsnap);
					process_id = pt.th32ProcessID;
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);
		return process_id;
	}

}

bool IsProcessRunning(const wchar_t* processName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_wcsicmp(pe32.szExeFile, processName) == 0) {
				CloseHandle(hSnapshot);
				return true;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return false;
}


template <typename T>
T read(uint64_t address) {
	SPOOF_FUNC;
	
	T buffer{ };
	mem::read_physical((PVOID)address, &buffer, sizeof(T));
	
	return buffer;
}

template <typename T>
T write(uint64_t address, T buffer) {
	SPOOF_FUNC;
	mem::write_physical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}

__forceinline auto query_bigpools() -> PSYSTEM_BIGPOOL_INFORMATION
{
	SPOOF_FUNC;

	DWORD length = 0;
	DWORD size = 0;
	LPVOID heap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0);
	heap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heap, 0xFF);
	NTSTATUS ntLastStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x42, heap, 0x30, &length);
	heap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heap, length + 0x1F);
	size = length;
	ntLastStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x42, heap, size, &length);

	return reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(heap);
}
__forceinline auto retrieve_guarded() -> uintptr_t
{
	SPOOF_FUNC;
	auto pool_information = query_bigpools();
	uintptr_t guarded = 0;

	if (pool_information)
	{
		auto count = pool_information->Count;
		for (auto i = 0ul; i < count; i++)
		{
			SYSTEM_BIGPOOL_ENTRY* allocation_entry = &pool_information->AllocatedInfo[i];
			const auto virtual_address = (PVOID)((uintptr_t)allocation_entry->VirtualAddress & ~1ull);
			if (allocation_entry->NonPaged && allocation_entry->SizeInBytes == 0x200000)
				if (guarded == 0 && allocation_entry->TagUlong == 'TnoC')
					guarded = reinterpret_cast<uintptr_t>(virtual_address);
		}
	}

	return guarded;
}

__forceinline auto retrieve_guarded1() -> uintptr_t
{
	SPOOF_FUNC;
	auto pool_information = query_bigpools();
	uintptr_t guarded = 0;

	if (pool_information)
	{
		auto count = pool_information->Count;
		for (auto i = 0ul; i < count; i++)
		{
			SYSTEM_BIGPOOL_ENTRY* allocation_entry = &pool_information->AllocatedInfo[i];
			const auto virtual_address = (PVOID)((uintptr_t)allocation_entry->VirtualAddress & ~1ull);

			if (allocation_entry->TagUlong == 'TnoC') {
				auto world = read<uintptr_t>(reinterpret_cast<uintptr_t>(virtual_address) + 0x60);
				if (world) {
					auto world1 = reinterpret_cast<uintptr_t>(virtual_address) + (world & 0xFFFFFF);

					if (world1) {
						if (world1 - reinterpret_cast<uintptr_t>(virtual_address) == 0x19130) {
							guarded = reinterpret_cast<uintptr_t>(virtual_address);

						}
					}

				}
			}


		}
	}
	printf(_("guarded %p\n"), guarded);
	return guarded;
}
