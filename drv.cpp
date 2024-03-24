#include <ntifs.h>
#include <windef.h>
#include <strsafe.h>
#include "main.h"
#include <ntifs.h>
#include <intrin.h>


#include "m/shared.h"
#include <cstdint>
#include "m/utils.h"
#include <ntdef.h>
#include "CR3.h"

struct comms_t {
	std::uint32_t key;

	struct {
		void* handle;
	}window;
};

UNICODE_STRING name, link;

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


bool locked = false;

#define code_rDTB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x91, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x92, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x93, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_get_guarded_region CTL_CODE(FILE_DEVICE_UNKNOWN, 0x94, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_move CTL_CODE(FILE_DEVICE_UNKNOWN, 0x95, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_spoof CTL_CODE(FILE_DEVICE_UNKNOWN, 0x96, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_unlock CTL_CODE(FILE_DEVICE_UNKNOWN, 0x97, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_security 0x76
#define win_1803 17134
#define win_1809 17763
#define win_1903 18362
#define win_1909 18363
#define win_2004 19041
#define win_20H2 19569
#define win_21H1 20180

#define PAGE_OFFSET_SIZE 12
static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;

typedef struct _rw {
	INT32 security;
	INT32 process_id;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN write;
	BOOLEAN EAC;
} rw, * prw;

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
typedef struct _ga {
	INT32 security;
	ULONGLONG* address;
} ga, * pga;
typedef struct _mu {
	float y;
	float x;
} mu, * mua;
typedef struct _spoof {
	float y;
	float x;
} spoof, * spoofa;
typedef struct _MOUSE_REQUEST
{
	BOOLEAN click;
	BOOLEAN status;
	LONG dx;
	LONG dy;

} MOUSE_REQUEST, * PMOUSE_REQUEST;
typedef struct _unlock {
	int a;
} unlock, *  unlocka;
NTSTATUS read(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
	MM_COPY_ADDRESS to_read = { 0 };
	to_read.PhysicalAddress.QuadPart = (LONGLONG)target_address;
	return MmCopyMemory(buffer, to_read, size, MM_COPY_MEMORY_PHYSICAL, bytes_read);
}

NTSTATUS write(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read)
{
	if (!target_address)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = LONGLONG(target_address);

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(pmapped_mem, buffer, size);

	*bytes_read = size;
	MmUnmapIoSpace(pmapped_mem, size);
	return STATUS_SUCCESS;
}

INT32 get_winver() {
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);
	switch (ver.dwBuildNumber)
	{
	case win_1803:
		return 0x0278;
		break;
	case win_1809:
		return 0x0278;
		break;
	case win_1903:
		return 0x0280;
		break;
	case win_1909:
		return 0x0280;
		break;
	case win_2004:
		return 0x0388;
		break;
	case win_20H2:
		return 0x0388;
		break;
	case win_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


uintptr_t eac_cr3 = 0;
PEPROCESS saved_process = 0;
bool is_cr3_invalid(uintptr_t cr3)
{
	return (cr3 >> 0x38) == 0x40;
}
uintptr_t get_process_cr3(PEPROCESS pprocess)
{
	if (!pprocess) return 0;
	uintptr_t process_dirbase = *(uintptr_t*)((PUCHAR)pprocess + 0x28);
	if (process_dirbase == 0)
	{
		ULONG user_diroffset = get_winver();
		process_dirbase = *(uintptr_t*)((PUCHAR)pprocess + user_diroffset);
	}

	return process_dirbase;
}

UINT64 translate_linearBE(UINT64 directoryTableBase, UINT64 virtualAddress) {
	directoryTableBase &= ~0xf;

	UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
	UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
	UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
	UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	UINT64 pdpe = 0;
	read(PVOID(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	UINT64 pde = 0;
	read(PVOID((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	UINT64 pteAddr = 0;
	read(PVOID((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	read(PVOID((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}

ULONG64 find_min(INT32 g, SIZE_T f) {
	INT32 h = (INT32)f;
	ULONG64 result = 0;

	result = (((g) < (h)) ? (g) : (h));

	return result;
}
EXTERN_C int _fltused = 0;
NTSTATUS frw(prw x) {

	if (x->security != code_security)
		return STATUS_UNSUCCESSFUL;

	if (!x->process_id)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)(x->process_id + 214891894), &process);
	if (!process)
		return STATUS_UNSUCCESSFUL;

	SIZE_T total_size = (x->size + 218949184);

	INT64 physical_address;
	if (x->EAC)
	{
		physical_address = physical::translate_linear(physical::m_stored_dtb, (ULONG64)(x->address + 201934901));
	}
	else
	{
		if (!process) return 0;
		uintptr_t process_dirbase = *(uintptr_t*)((PUCHAR)process + 0x28);
		if (process_dirbase == 0)
		{
			ULONG user_diroffset = get_winver();
			process_dirbase = *(uintptr_t*)((PUCHAR)process + user_diroffset);
		}

		physical_address = translate_linearBE(process_dirbase, (ULONG64)(x->address + 201934901));
	}

	if (!physical_address)
		return STATUS_UNSUCCESSFUL;

	ULONG64 final_size = find_min(PAGE_SIZE - (physical_address & 0xFFF), total_size);
	SIZE_T bytes_trough = NULL;

	if (x->write) {
		write(PVOID(physical_address), (PVOID)((ULONG64)(x->buffer + 21489184)), final_size, &bytes_trough);
	}
	else {
		read(PVOID(physical_address), (PVOID)((ULONG64)(x->buffer + 21489184)), final_size, &bytes_trough);
	}

	return STATUS_SUCCESS;
}

NTSTATUS fba(pba x) {

	if (x->security != code_security)
		return STATUS_UNSUCCESSFUL;

	if (!x->process_id)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)x->process_id, &process);
	if (!process)
		return STATUS_UNSUCCESSFUL;

	ULONGLONG image_base = (ULONGLONG)PsGetProcessSectionBaseAddress(process);
	if (!image_base)
		return STATUS_UNSUCCESSFUL;

	RtlCopyMemory(x->address, &image_base, sizeof(image_base));
	ObDereferenceObject(process);

	return STATUS_SUCCESS;
}

NTSTATUS resolve_dtb(dtbl x)
{
	dtb data = { 0 };

	if (x->security != code_security)
	{
		printf("invalid S code.\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (!x->process_id)
	{
		printf("invalid process_id.\n");
		return STATUS_UNSUCCESSFUL;
	}

	PEPROCESS process = 0;
	PsLookupProcessByProcessId((HANDLE)x->process_id, &process);
	if (!process)
	{
		printf("invalid process.\n");
		return STATUS_UNSUCCESSFUL;
	}
	

	physical::m_stored_dtb = pml4::dirbase_from_base_address((void*)PsGetProcessSectionBaseAddress(process));

	printf("cr3: %llx\n", physical::m_stored_dtb);

	ObDereferenceObject(process);
	ULONGLONG ret = 1;
	RtlCopyMemory(x->operation, &ret, sizeof(ret));
	return STATUS_SUCCESS;
}


NTSTATUS fget_guarded_region(pga x) {
	if (x->security != code_security)
		return STATUS_UNSUCCESSFUL;

	ULONG infoLen = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemBigPoolInformation, &infoLen, 0, &infoLen);
	PSYSTEM_BIGPOOL_INFORMATION pPoolInfo = 0;

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (pPoolInfo)
			ExFreePool(pPoolInfo);

		pPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, infoLen);
		status = ZwQuerySystemInformation(SystemBigPoolInformation, pPoolInfo, infoLen, &infoLen);
	}

	if (pPoolInfo)
	{
		for (unsigned int i = 0; i < pPoolInfo->Count; i++)
		{
			SYSTEM_BIGPOOL_ENTRY* Entry = &pPoolInfo->AllocatedInfo[i];
			PVOID VirtualAddress;
			VirtualAddress = (PVOID)((uintptr_t)Entry->VirtualAddress & ~1ull);
			SIZE_T SizeInBytes = Entry->SizeInBytes;
			BOOLEAN NonPaged = Entry->NonPaged;

			if (NonPaged && SizeInBytes == 0x200000)
			{
				if (Entry->TagUlong == 'TnoC') {

					RtlCopyMemory((void*)x->address, &VirtualAddress, sizeof(VirtualAddress));

					return STATUS_SUCCESS;
				}
			}
		}

		ExFreePool(pPoolInfo);
	}

	return STATUS_SUCCESS;
}


extern "C" {
	NTSYSCALLAPI
		NTSTATUS
		ObReferenceObjectByName(
			__in PUNICODE_STRING ObjectName,
			__in ULONG Attributes,
			__in_opt PACCESS_STATE AccessState,
			__in_opt ACCESS_MASK DesiredAccess,
			__in POBJECT_TYPE ObjectType,
			__in KPROCESSOR_MODE AccessMode,
			__inout_opt PVOID ParseContext,
			__out PVOID* Object
		);
}
extern "C" POBJECT_TYPE * IoDriverObjectType;


NTSTATUS io_controller(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	NTSTATUS status = { };
	ULONG bytes = { };
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

	if (code == code_rw) {
		if (size == sizeof(_rw)) {
			prw req = (prw)(irp->AssociatedIrp.SystemBuffer);

			status = frw(req);
			bytes = sizeof(_rw);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == code_rDTB)//Get Bypass EAC CR3 Bypass
	{
		if (size == sizeof(_dtb)) {
			dtbl req = (dtbl)(irp->AssociatedIrp.SystemBuffer);

			status = resolve_dtb(req);
			bytes = sizeof(_dtb);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == code_get_guarded_region) {
		if (size == sizeof(_ga)) {
			pga req = (pga)(irp->AssociatedIrp.SystemBuffer);

			status = fget_guarded_region(req);
			bytes = sizeof(_ga);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == code_ba) {
		if (size == sizeof(_ba)) {
			pba req = (pba)(irp->AssociatedIrp.SystemBuffer);
			status = fba(req);
			bytes = sizeof(_ba);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}

	}
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS unsupported_dispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return irp->IoStatus.Status;
}

NTSTATUS dispatch_handler(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	switch (stack->MajorFunction) {
	case IRP_MJ_CREATE:
		break;
	case IRP_MJ_CLOSE:
		break;
	default:
		break;
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

void unload_drv(PDRIVER_OBJECT drv_obj) {
	NTSTATUS status = { };

	status = IoDeleteSymbolicLink(&link);

	if (!NT_SUCCESS(status))
		return;

	IoDeleteDevice(drv_obj->DeviceObject);
}

extern NTSTATUS entryaa();



wchar_t								DEVICE_NAME[260];
wchar_t								LINK_NAME[260];
WCHAR				randStr[128];


NTSTATUS initialize_driver(PDRIVER_OBJECT drv_obj, PUNICODE_STRING path) {
	UNREFERENCED_PARAMETER(path);

	NTSTATUS status = { };
	PDEVICE_OBJECT device_obj = { };
	int	id[4];
	__cpuid(id, 1);
	wchar_t buffer[1];

	StringCchPrintfW(randStr, sizeof(randStr), L"%08X", id[0]);


	StringCchPrintfW(DEVICE_NAME, sizeof(DEVICE_NAME), L"\\Device\\%s", randStr);
	StringCchPrintfW(LINK_NAME, sizeof(LINK_NAME), L"\\DosDevices\\%s", randStr);

	RtlInitUnicodeString(&name, DEVICE_NAME);
	RtlInitUnicodeString(&link, LINK_NAME);


	status = IoCreateDevice(drv_obj, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj);

	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&link, &name);

	if (!NT_SUCCESS(status))
		return status;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv_obj->MajorFunction[i] = &unsupported_dispatch;

	device_obj->Flags |= DO_BUFFERED_IO;

	drv_obj->MajorFunction[IRP_MJ_CREATE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_CLOSE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &io_controller;
	drv_obj->DriverUnload = &unload_drv;

	device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);;

	return IoCreateDriver(NULL, &initialize_driver);
}
