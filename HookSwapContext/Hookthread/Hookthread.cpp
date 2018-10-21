#include "ntifs.h"
#include <windef.h>
#include "List.h"

DWORD gThreadsProcessOffset =0x220;    // ETHREAD 在 EPROCESS偏移
/*

+0x218 TopLevelIrp      : Uint4B
+0x21c DeviceToVerify   : Ptr32 _DEVICE_OBJECT
+0x220 ThreadsProcess   : Ptr32 _EPROCESS
*/

ULONG ProcessNameOffset = 0x174;      // 进程对应的文件名 在 EPROCESS偏移
/*
+0x170 Session          : Ptr32 Void
+0x174 ImageFileName    : [16] UChar
+0x184 JobLinks         : _LIST_ENTRY
*/

PProcessList wLastItem = NULL;        
int BeTerminate = 0;                  //1 表示线程必须要停止  3表示线程不是PENDING状态  0表示线程可以正常运行

void _stdcall CollectProcess(PEPROCESS pEPROCESS)  // 搜集EPROCESS
{
	if (!IsAdded(wLastItem, pEPROCESS)) AddItem(&wLastItem, pEPROCESS);
	return;
}

void __stdcall ThreadCollect(PUCHAR pEthread)   //根据ETHREAD得到EPROCESS 并调用CollectProcess来搜集
{
	PEPROCESS pEprocess = *(PEPROCESS *)(pEthread + gThreadsProcessOffset);
	if (pEprocess) CollectProcess(pEprocess);
	return;
}


DWORD outPEthread = 0;
void __stdcall ProcessData(DWORD pInEthread, DWORD pOutEthread)
{
	DWORD pid, eprocess;
	char * pname;
	if (MmIsAddressValid(PVOID(pInEthread+0x220)) )    // 这里以及下面要判断是不是一个真正的 Ethread 结构体 有时好像调用SwapContext传进来的不是 Ethread 结构体 然后就蓝屏 具体没有深究 加个判断就不蓝了~
	{
		eprocess = *(DWORD*)(pInEthread+0x220);
		
		if (MmIsAddressValid(PVOID(eprocess) ) )
		{
			ThreadCollect((PUCHAR)pInEthread);
		}
		
	}
}



PBYTE GoBackAddr = NULL;
PBYTE ChangAddr = NULL;

DWORD CallContextOffset = 0;

__declspec(naked) VOID HookSwap()
{ 

	_asm 
	{
		pushad
			pushfd
			cli
	}

	_asm
	{
		   // EDI 是换出的线程上下文
	     	push edi
			//ESI 是换入的线程上下文
			push esi
			call ProcessData   //搜集进程
	}
	
	_asm 
	{  
		sti
			popfd
			popad
	}
	_asm jmp DWORD PTR[GoBackAddr]
}

/*
得到SwapContext地址的原理是
用PsLookupThreadByThreadId得到Idle System的KTHREAD
res=(PCHAR)(Thread->Tcb.KernelStack);
SwapAddr=*(DWORD *)(res+0x08);
*/
PCHAR GetSwapAddr()
{
	PCHAR res = 0;
	NTSTATUS  Status;
	PETHREAD Thread;
	
	if (*NtBuildNumber <= 2195)
		Status = PsLookupThreadByThreadId((PVOID)4, &(PETHREAD)Thread);
	else
		Status = PsLookupThreadByThreadId((PVOID)8, &(PETHREAD)Thread);
	
	if (NT_SUCCESS(Status))
	{
		if (MmIsAddressValid(Thread))
		{
			res = (PCHAR)(Thread->Tcb.KernelStack);

		}
		if (MmIsAddressValid(res+8))
		{
			_asm
			{
				mov eax,res
					add eax,8
					mov eax,[eax]
					mov res,eax
			}
		}
		else
		{
			res = 0;
			return NULL;
		}
	}
	_asm
	{
		mov eax,res
			sub eax,5
			mov ChangAddr,eax
			mov edx,[eax+1]
			mov CallContextOffset,edx
			add eax,edx
			add eax,5
			mov GoBackAddr,eax
			mov res,eax
	}
	return res;
}



BOOL  HookSwapFunction(BOOL flag)
{	
	if (flag == TRUE)
	{ 
		KIRQL OldIrql=0;
		DWORD NewOffset;//HookSwap-ChangAddr-5;
		_asm
		{
			mov eax,HookSwap
				mov edx,ChangAddr
				sub eax,edx
				sub eax,5
				mov NewOffset,eax
		}

		PAGED_CODE()
			ASSERT(KeGetCurrentIrql()<=DISPATCH_LEVEL);
		KeRaiseIrql(2,&OldIrql);//HIGH_LEVEL
		__asm
		{
			CLI
				MOV   EAX, CR0
				AND   EAX, NOT 10000H  //disable WP bit
				MOV   CR0, EAX
		}
		_asm
		{
			mov eax,ChangAddr
				push NewOffset
				pop dword ptr[eax+1]
				
		}
		
		__asm
		{
			MOV   EAX, CR0
				OR    EAX, 10000H  //enable WP bit
				MOV   CR0, EAX
				STI
		}
		
		
		KeLowerIrql(OldIrql);
		
	}
	//Bug Check 0xD1: DRIVER_IRQL_NOT_LESS_OR_EQUAL
	
	else
	{ 
		KIRQL OldIrql=0;
		KeRaiseIrql(2,&OldIrql);///HIGH_LEVEL
		__asm
		{
			CLI
				MOV   EAX, CR0
				AND   EAX, NOT 10000H  //disable WP bit
				MOV   CR0, EAX
		}
		
		_asm
		{
			mov eax,ChangAddr
				push CallContextOffset
				pop dword ptr[eax+1]
		}
		
		
		__asm
		{
			MOV   EAX, CR0
				OR    EAX, 10000H  //enable WP bit
				MOV   CR0, EAX
				STI
		}
		KeLowerIrql(OldIrql);
		//		DbgPrint("HookSwapFunctionFALSE");//jution
	}
	
}

PEPROCESS processObject (PETHREAD ethread) {
	return  (PEPROCESS)(ethread->Tcb.ApcState.Process);
}



void  klisterUnload(IN PDRIVER_OBJECT pDriverObject)
{
	BeTerminate = 1;
	while(BeTerminate != 3)    // = 3时说明创建的线程不是pending状态且马上会结束 这时候可以UNLOAD   否则线程在PENDING状态UNLOADE 会直接蓝
	{
      
	}
	
	if (GoBackAddr)//PBYTE GoBackAddr = NULL;
		HookSwapFunction(FALSE);	
}

void showProcess()
{

	PProcessList temp;
	DWORD count = 0;
	PUCHAR pFileName;
	 temp = wLastItem;


	while (temp)     //遍历链表
	{	
	    if (temp->pEPROCESS)
		{
			  count++;
			  pFileName = (PUCHAR)((unsigned int)(temp->pEPROCESS) + 0x174);
			  DbgPrint("0x%08X   %s \n",(unsigned int)(temp->pEPROCESS), pFileName);
		}
		temp = PProcessList(temp->NextItem);
	}

	DbgPrint("共有%d个进程", count); 
}


void WorkThread(IN PVOID pContext)
{
	LARGE_INTEGER timeout;
	
	while(true)
	{
		if (MmIsAddressValid(&BeTerminate) )    // 因为BeTerminate是在UNLOAD中设置的 可能驱动卸载后 这个变量不能访问 所以用MmIsAddressValid判断下 
		{
			if(BeTerminate == 0)
			{
				
				//等待单位是 100ns         //-10作用是转换成微秒  //2000000微秒=9秒
				timeout = RtlConvertLongToLargeInteger(-10              *    2000000);   
				
				KeDelayExecutionThread(KernelMode, FALSE, &timeout);
				DbgPrint("搜集到的进程是");				
				showProcess();
			}
			else
			{
			    BeTerminate = 3;
				PsTerminateSystemThread(STATUS_SUCCESS);
				goto __end;
			}
		}
		else
		{
	    	BeTerminate = 3;
			PsTerminateSystemThread(STATUS_SUCCESS);
			goto __end;	
		}
	}
__end:;
}


// 驱动程序加载时调用DriverEntry例程
NTSTATUS DriverEntry(
					 IN PDRIVER_OBJECT  pDriverObject,
					 IN PUNICODE_STRING pRegistryPath
					 )
{
	NTSTATUS dwStAtus; 
	HANDLE hThread; 
	
	pDriverObject->DriverUnload=klisterUnload;
	
	dwStAtus = PsCreateSystemThread(&hThread, 
		(ACCESS_MASK)0, 
		NULL, 
		(HANDLE)0, 
		NULL, 
		WorkThread, 
		NULL 
		); 
		
		
		  GetSwapAddr();
		  if (GoBackAddr){
		  HookSwapFunction(TRUE);
}	
	return STATUS_SUCCESS;
}