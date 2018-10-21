#include <ntddk.h>
#include <ntimage.h>
#include <ntdef.h>
#include "hash.h"
#include "xde.h"
#include "main.h"

typedef struct _BYTECODE
{
	BYTE *pAddress;
	SIZE_T size;
} BYTECODE, *PBYTECODE;

typedef struct _OFFSETS
{
	BYTE threadsProcess;
	BYTE CID;
	BYTE imageFilename;
	BYTE crossThreadFlags;
	unsigned  PID;
	unsigned PPID;

	unsigned pecreatetimeoff;
	unsigned peexittimeoff;
} OFFSETS, *POFFSETS;

#define JMP_SIZE 5
#define SIG_SIZE 20
#define HASHTABLE_SIZE 256
#define MAINTAG1 'NIAM'

// NOTICE: WinDbg gives offsets in BYTEs, we use DWORDS.
OFFSETS offsets;
// The beginning of the SwapContext function is stored here.
BYTE *pSwapContext = NULL;
// The trampoline function which executes the replaced code and
// passes control to the hooked function.
BYTECODE trampoline;
// Inline assembler does not support structures, so this points
// directly to the pCode of the _BYTECODE structure.
BYTE *pTrampoline = NULL;
// The hashtable where we store the data.
PHASHTABLE pHashTable = NULL;
DWORD num = 0;

extern  USHORT  *NtBuildNumber;

const WCHAR deviceLinkBuffer[]  = L"\\DosDevices\\SwapContextDrv";
const WCHAR deviceNameBuffer[]  = L"\\Device\\SwapContextDrv";

PDEVICE_OBJECT g_HookDevice;

ULONG gNameOffset = 0x174;
PsLookupThreadByThreadId(
        IN PVOID UniqueThreadId,
        OUT PETHREAD *ppEthread
);
KIRQL			OldIrql;
KSPIN_LOCK		DpcSpinLock;

ULONG GetLocationOfProcessName(PEPROCESS CurrentProc)
{
    ULONG ul_offset;

	for(ul_offset = 0; ul_offset < PAGE_SIZE; ul_offset++) // This will fail if EPROCESS
												           // grows bigger than PAGE_SIZE
	{
		if( !strncmp( "System", (PCHAR) CurrentProc + ul_offset, strlen("System")))
		{
			return ul_offset;
		}
	}

	return (ULONG) 0;
}

// This function returns an MDL to an nonpaged virtual memory area.
// 
// IN pVirtualAddress Virtual address to the start of the memory area.
// IN length Length of the memory area in bytes.
//
// OUT PMDL Mdl to the nonpaged virtual memory area.
//
PMDL GetMdlForNonPagedMemory(PVOID pVirtualAddress, SIZE_T length)
{
	PMDL pMdl;

	if (length >= (PAGE_SIZE * (65535 - sizeof(MDL)) / sizeof(ULONG_PTR)))
	{
		DbgPrint("Size parameter passed to IoAllocateMdl is too big!\n");
		return NULL;
	}

	pMdl = IoAllocateMdl((PVOID)pVirtualAddress, length, FALSE, FALSE, NULL);
	if (NULL == pMdl)
	{
		DbgPrint("IoAllocateMdl returned NULL!\n");
		return NULL;
	}

	MmBuildMdlForNonPagedPool(pMdl);

	return pMdl;
}

// This function returns an MDL to a paged virtual memory area while
// making sure the pages are not paged out to the disk.
// 
// IN pVirtualAddress Virtual address to the start of the memory area.
// IN length Length of the memory area in bytes.
// IN operation Desired mode of operation.
//
// OUT PMDL Mdl to the locked and nonpaged memory area.
//
PMDL GetMdlForPagedMemory(PVOID pVirtualAddress, SIZE_T length, LOCK_OPERATION operation)
{
	PMDL pMdl;

	if (length >= (PAGE_SIZE * (65535 - sizeof(MDL)) / sizeof(ULONG_PTR)))
	{
		DbgPrint("Size parameter passed to IoAllocateMdl is too big!\n");
		return NULL;
	}

	pMdl = IoAllocateMdl((PVOID)pVirtualAddress, length, FALSE, FALSE, NULL);
	if (NULL == pMdl)
	{
		DbgPrint("IoAllocateMdl returned NULL!\n");
		return NULL;
	}

	// Make sure the memory is not paged on the disk.
	try
	{
		MmProbeAndLockPages(pMdl, KernelMode, operation);
	}
	except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("MmProbeAndLockPages caused an exception!\n");
		IoFreeMdl(pMdl);
		return NULL;
	}

	return pMdl;
}



// This function writes the given data to the given non-paged kernel memory location.
// It makes sure that no other instance can access it in any way until we have finished
// our job.
//
// IN pDestination Pointer to the kernel memory where we want to write.
// IN pSource Pointer to the data we want to write.
// IN length Length of data we want to write in bytes.
//
// OUT NTSTATUS return code.
//
NTSTATUS WriteKernelMemory(BYTE *pDestination, BYTE *pSource, SIZE_T length)
{
	KSPIN_LOCK spinLock;
	KLOCK_QUEUE_HANDLE lockHandle;
	PMDL pMdl;
	PVOID pAddress;

	pMdl = GetMdlForNonPagedMemory(pDestination, length);
	if (NULL == pMdl)
	{
		DbgPrint("GetMdlForSafeKernelMemoryArea returned NULL!\n");
		return STATUS_UNSUCCESSFUL;
	}

	pAddress = MmGetSystemAddressForMdlSafe(pMdl, HighPagePriority);

	if (pAddress == NULL)
	{
		IoFreeMdl(pMdl);
		DbgPrint("MmGetSystemAddressForMdlSafe returned NULL!\n");
		return STATUS_UNSUCCESSFUL;
	}

	KeInitializeSpinLock(&spinLock);
	// Only supported on XP and later. For Windows 2000 compatibility you can
	// use the older, less efficient and less reliable KeAcquireSpinLock function.
	KeAcquireInStackQueuedSpinLock (&spinLock, &lockHandle);
	// We have the spinlock, so we can safely overwrite the kernel memory.
	RtlCopyMemory(pAddress, pSource, length);
	KeReleaseInStackQueuedSpinLock(&lockHandle);

	IoFreeMdl(pMdl);

	return STATUS_SUCCESS;
}

void __stdcall ProcessData(DWORD *pEthread)
{
	DWORD	*pEprocess	= (DWORD *)*(pEthread + offsets.threadsProcess);
	DWORD	*pCid		= (DWORD *)(pEthread+offsets.CID);
	DWORD	key			= 0;
	DATA	data		= {0};
	
	data.processID = 0x0;
	data.threadID = 0x0;
	data.imageName = "NONE";

	key = (DWORD)pEthread;
	
	if (pCid != NULL)
	{
		data.processID = *pCid;
		data.threadID = *(pCid + 0x1);
	}
	
	if (pEprocess != NULL)
	{
		data.imageName = (BYTE *)(pEprocess+offsets.imageFilename);
		data.xlow = *(DWORD *)(pEprocess+offsets.peexittimeoff);
		data.xhigh = *(DWORD *)(pEprocess+offsets.peexittimeoff+4);
	}
	if (*(pEthread + offsets.crossThreadFlags) & 1)
	{
		KeAcquireSpinLock(&DpcSpinLock,&OldIrql);
		Remove(key, pHashTable);
		KeReleaseSpinLock(&DpcSpinLock,OldIrql);
	}
	else
	{
		KeAcquireSpinLock(&DpcSpinLock,&OldIrql);
		Insert(key, &data, pHashTable);
		KeReleaseSpinLock(&DpcSpinLock,OldIrql);
	}
}

void __declspec(naked) DetourFunction()
{
	__asm 
	{
		// Save parameters we will overwrite. We save all data to play it safe.
		pushad
		pushfd
		// Disable interrupts. Assume single processor machine.
		// cli
		// EDI holds the thread whose context we will switch out.
		push edi//edi寄存器中存放的是要切换出去的线程
		call ProcessData
		// ESI holds the thread whose context we will switch in.
		push esi
		call ProcessData
		// Enable interrupts.
		// sti
		// Restore the saved state.
		popfd
		popad

		// Jump to the trampoline function.
		jmp dword ptr pTrampoline//弹簧床
	}
}



BYTE * GetSwapAddr()
{
    BYTE		*res = 0;
    NTSTATUS	Status;
    PETHREAD	Thread;

    if (*NtBuildNumber <= 2195)
        Status = PsLookupThreadByThreadId((PVOID)4, &Thread);
    else
        Status = PsLookupThreadByThreadId((PVOID)8, &Thread);

    if (NT_SUCCESS(Status))
    {
        if (MmIsAddressValid(Thread))
            res = (BYTE *)(*(ULONG *)((BYTE *)(Thread)+0x28));
        if (MmIsAddressValid(res+8))
            res = (BYTE *)(*(ULONG *)(res+8));
        else
            res = 0;
    }

    return res;
}
ULONG GetFunctionAddr( IN PCWSTR FunctionName)
{
		UNICODE_STRING UniCodeFunctionName;
		
		RtlInitUnicodeString( &UniCodeFunctionName, FunctionName );
		return (ULONG)MmGetSystemRoutineAddress( &UniCodeFunctionName );    
		
}
VOID DoFindSwap(IN PVOID pContext)
	{
		NTSTATUS ret;
		PSYSTEM_MODULE_INFORMATION  module = NULL;
		ULONG n=0;
		void  *buf    = NULL;
		ULONG ntosknlBase;
		ULONG ntosknlEndAddr;
		ULONG curAddr;

		ULONG code1_sp1=0xc626c90a,code2_sp1=0x9c022d46,code3_sp1=0xbb830b8b,code4_sp1=0x00000994;


		ULONG code1,code2,code3,code4;
		ULONG i;
		
		NtQuerySystemInformation=(NTQUERYSYSTEMINFORMATION)GetFunctionAddr(L"NtQuerySystemInformation");
		if (!NtQuerySystemInformation) 
		{
			DbgPrint("Find NtQuerySystemInformation faild!");
			goto Ret;
		}
		ret=NtQuerySystemInformation(SystemModuleInformation,&n,0,&n);
		if (NULL==( buf=ExAllocatePoolWithTag(NonPagedPool, n, 'PAWS')))
		{
			DbgPrint("ExAllocatePool() failed\n" );
			goto Ret;
		}
		ret=NtQuerySystemInformation(SystemModuleInformation,buf,n,NULL);
		if (!NT_SUCCESS(ret))	{
			DbgPrint("NtQuerySystemInformation faild!");
			goto Ret;
		} 
		module=(PSYSTEM_MODULE_INFORMATION)((PULONG)buf+1);
		ntosknlEndAddr=(ULONG)module->Base+(ULONG)module->Size;
		ntosknlBase=(ULONG)module->Base;
		curAddr=ntosknlBase;
		ExFreePool(buf);

		code1 = code1_sp1;
		code2 = code2_sp1;
		code3 = code3_sp1;
		code4 = code4_sp1;
	
		for (i=curAddr;i<=ntosknlEndAddr;i++)
		{
			if (*((ULONG *)i)==code1) 
			{
				if (*((ULONG *)(i+4))==code2) 
				{
					if (*((ULONG *)(i+8))==code3) 
					{
						if (*((ULONG *)(i+12))==code4) 
						{
								
								pSwapContext=(BYTE *)i;
								break;
									
						}
					}
				}
			}
		}
Ret:
	PsTerminateSystemThread(STATUS_SUCCESS);
	}

void FindSwapAddr()
{
		HANDLE	hThread		= NULL;
		PVOID	objtowait	= 0;

		NTSTATUS dwStatus = 
			PsCreateSystemThread(
			&hThread,
	              0,
		       NULL,
			(HANDLE)0,
	              NULL,
		       DoFindSwap,
			NULL
			);
		if ((KeGetCurrentIrql())!=PASSIVE_LEVEL)
		{
			KfRaiseIrql(PASSIVE_LEVEL);
		
		}
		if ((KeGetCurrentIrql())!=PASSIVE_LEVEL)
		{
			return;
		}
		
		ObReferenceObjectByHandle(
			hThread,
			THREAD_ALL_ACCESS,
			NULL,
			KernelMode,
			&objtowait,
			NULL
			); 

		KeWaitForSingleObject(objtowait,Executive,KernelMode,FALSE,NULL); //NULL表示无限期等待.
		return;

}

NTSTATUS InstallSwapContextHook()
{
	NTSTATUS rc;
	int length = 0;
	int totalLength = 0;
	struct xde_instr instr;
	BYTE *pJmpCode = NULL;
	long displacement = 0;

	__asm
    {
			push    eax
			mov        eax, CR0
			and        eax, 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
    }

	// Disassemble the code to get how many bytes we have to replace.
	// We use XDE v1.01 by Z0MBie (http://z0mbie.host.sk/).
	while (totalLength < 5)
	{
		length = xde_disasm(pSwapContext + totalLength, &instr);
		if (length == 0)
		{
			DbgPrint("xde_disasm returned 0!\n");
			return STATUS_UNSUCCESSFUL;
		}
		totalLength += length;
	}
	
	DbgPrint("Hook will replace the first %d bytes.\n", totalLength);

	// Allocate the required bytes for the trampoline function.
	//pTrampoline:是保存原来的被替换的指令+JMP指令
	pTrampoline = trampoline.pAddress = ExAllocatePoolWithTag(NonPagedPool, totalLength + 5, MAINTAG1);
	if (trampoline.pAddress == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag returned NULL!\n");
		return STATUS_UNSUCCESSFUL;
	} 

	DbgPrint("Trampoline is at 0x%x\n", pTrampoline);

	// This tells how many bytes we replaced from the original function.
	//备份原来的指令
	trampoline.size = totalLength;
	RtlCopyMemory(trampoline.pAddress, pSwapContext, totalLength);

	// We are using JMP rel32 instruction to jump to the rest of the
	// swapcontext function, so we first calculate the 32bit displacement
	// and then create the five byte JMP instruction.
	//在备份完原来的指令后，在后面构造一个跳回去的jmp指令
	//displacement是跳回去的偏移
	displacement = (pSwapContext + totalLength) - (trampoline.pAddress + totalLength + JMP_SIZE);
	pJmpCode = trampoline.pAddress + totalLength;

	//直接的jmp分3种 
	//Short Jump（短跳转）机器码 EB rel8 
	//只能跳转到256字节的范围内 
	//Near Jump（近跳转）机器码 E9 rel16/32 
	//可跳至同一个段的范围内的地址 
	//Far Jump（远跳转）机器码EA ptr 16:16/32 
	//可跳至任意地址，使用48位/32位全指针 
	*pJmpCode = 0xe9;
	RtlCopyMemory(pJmpCode+1, &displacement, 4);
	//执行这个时候，被替换的指令备份就已经完成
	//接下来，就应该生成一个jmp指令，覆盖原来的指令

	// Allocate the required bytes for the jmp code to the detour function.
	pJmpCode = ExAllocatePoolWithTag(NonPagedPool, totalLength, MAINTAG1);
	if (pJmpCode == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag returned NULL!\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Initialize the jmp-code with NOPs.
	RtlFillMemory(pJmpCode, totalLength, 0x90);
	
	// We are using JMP rel32 instruction to jump to our hook function,
	// so we first calculate the 32bit displacement and then create the
	// five byte JMP instruction.
	displacement = ((BYTE *)&DetourFunction) - (pSwapContext + JMP_SIZE);
	*pJmpCode = 0xe9;
	RtlCopyMemory(pJmpCode+1, &displacement, 4);

	//inline hook完成
	rc = WriteKernelMemory(pSwapContext, pJmpCode, totalLength);
	ExFreePoolWithTag(pJmpCode, MAINTAG1);
    __asm
    {
        push    eax
			mov        eax, CR0
			or        eax, NOT 0FFFEFFFFh
			mov        CR0, eax
			pop        eax
    }
	return rc;
}

// This function removes our hook by restoring the bytes we have replaced
// from the original SwapContext function.
//
// OUT NTSTATUS return value.
//
NTSTATUS UninstallSwapContextHook()
{
	return WriteKernelMemory(pSwapContext, trampoline.pAddress, trampoline.size);
}

NTSTATUS OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS rc;
	UNICODE_STRING          deviceLinkUnicodeString;
	PDEVICE_OBJECT			p_NextObj;
	PPROCLIST pTemp = NULL, pt = NULL;
	PThreadData pTempT = NULL, pp = NULL;
	PDriverData pTempD = NULL, pd = NULL;
	PFileList pTempF = NULL, pf = NULL;

	DbgPrint("OnUnload called\n");

	rc = UninstallSwapContextHook();

	if (STATUS_SUCCESS == rc)
	{
		DbgPrint("UninstallSwapContextHook succeeded.\n");
	}
	else
	{
		DbgPrint("UninstallSwapContextHook failed!\n");
	}

	// Show the collected data and release all resources.
	//DumpTable(pHashTable);
	KeAcquireSpinLock(&DpcSpinLock,&OldIrql);
	DestroyTable(pHashTable);
	KeReleaseSpinLock(&DpcSpinLock,OldIrql);
	//num = 0;
	ExFreePoolWithTag(pTrampoline, MAINTAG1);

    // Delete the symbolic link for our device
	//
	RtlInitUnicodeString( &deviceLinkUnicodeString, deviceLinkBuffer );
	IoDeleteSymbolicLink( &deviceLinkUnicodeString );
	// Delete the device object
	//
	IoDeleteDevice( DriverObject->DeviceObject );
	//return STATUS_SUCCESS;
	return rc;
}


NTSTATUS DispatchCreate (
		IN PDEVICE_OBJECT	pDevObj,
		IN PIRP				pIrp			)
{

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;	// no bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	
	RTL_OSVERSIONINFOW		osvi;
	NTSTATUS                ntStatus;
	UNICODE_STRING          deviceNameUnicodeString;
    UNICODE_STRING          deviceLinkUnicodeString;   
	RTL_OSVERSIONINFOEXW	VersionInfo;
	ULONGLONG				ConditionMask = 0;

	memset(&VersionInfo,0,sizeof(VersionInfo));

	VER_SET_CONDITION (
           ConditionMask,
            VER_SERVICEPACKMAJOR,
            VER_EQUAL
            );


	DbgPrint("DriverEntry called.\n");

	RtlZeroMemory(&osvi, sizeof(RTL_OSVERSIONINFOW));
	osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);


	// Initialize the OS specific data.
// 	gNameOffset = GetLocationOfProcessName(PsGetCurrentProcess());
// 	if (!gNameOffset)
// 		return STATUS_UNSUCCESSFUL;
	if (STATUS_SUCCESS == RtlGetVersion(&osvi))
	{
		if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1) //Windows XP
		{
			offsets.pecreatetimeoff = 0x070;
			offsets.peexittimeoff = 0x078;
			offsets.CID = 0x7b;
			offsets.threadsProcess = 0x88;
			offsets.crossThreadFlags = 0x92;
			offsets.imageFilename = 0x5d;
		}

		//VersionInfo.wServicePackMajor = 3;
		//if( STATUS_SUCCESS==RtlVerifyVersionInfo(&VersionInfo,VER_SERVICEPACKMAJOR,ConditionMask))//sp3
		//{
		//
		//}
		
		else
		{
			//更多的调试
			DbgPrint("Unsupported OS version!\n");
			return STATUS_UNSUCCESSFUL;
		}
		
	}
	else
	{
		DbgPrint("RtlGetVersion failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	
	RtlInitUnicodeString (&deviceNameUnicodeString,
	                          deviceNameBuffer );
	RtlInitUnicodeString (&deviceLinkUnicodeString, deviceLinkBuffer);

	ntStatus = IoCreateDevice ( DriverObject,
	                                0, // For driver extension
	                                &deviceNameUnicodeString,
	                                FILE_DEVICE_UNKNOWN,
	                                0,
	                                TRUE,
	                                &g_HookDevice );

	if(! NT_SUCCESS(ntStatus))
	{
	        DbgPrint(("Failed to create device!\n"));
	        return ntStatus;
	}
	 
			
	ntStatus = IoCreateSymbolicLink (&deviceLinkUnicodeString,
	                                        &deviceNameUnicodeString );
	if(! NT_SUCCESS(ntStatus)) 
	{
		 IoDeleteDevice(DriverObject->DeviceObject);
	        DbgPrint("Failed to create symbolic link!\n");
	        return ntStatus;
	}

	DriverObject->DriverUnload  = OnUnload;

	pHashTable = InitializeTable(HASHTABLE_SIZE);
	if (pHashTable == NULL)
	{
		DbgPrint("InitializeTable failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	
	//pSwapContext = GetSwapAddr();

	FindSwapAddr();

	if(NULL==pSwapContext)
	{
	 	DbgPrint("SwapContext addr not found!\n");
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		DbgPrint("SwapContext found at 0x%x\n", pSwapContext);

		ntStatus = InstallSwapContextHook();
	}
	
	if (STATUS_SUCCESS == ntStatus)
	{
		DbgPrint("InstallSwapContextHook succeeded.\n");
		DbgPrint("DetourFunction is at 0x%x\n", DetourFunction);
	}
	else
	{
		DbgPrint("InstallSwapContextHook failed!\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
	
}
