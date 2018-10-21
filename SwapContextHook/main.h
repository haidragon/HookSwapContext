
typedef struct _MODULE_ENTRY {
	LIST_ENTRY le_mod;
	DWORD  unknown[4];
	DWORD  base;
	DWORD  driver_start;
	DWORD  unk1;
	UNICODE_STRING driver_Path;
	UNICODE_STRING driver_Name;
	//...
} MODULE_ENTRY, *PMODULE_ENTRY;
#define NUMBER_HASH_BUCKETS 37

typedef struct _OBJECT_DIRECTORY_ENTRY {
    struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
    PVOID Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

NTSTATUS ObOpenObjectByName (IN POBJECT_ATTRIBUTES ObjectAttributes,
                             IN POBJECT_TYPE ObjectType OPTIONAL, 
							 IN KPROCESSOR_MODE AccessMode,
							 IN OUT PACCESS_STATE AccessState OPTIONAL, 
							 IN ACCESS_MASK DesiredAccess OPTIONAL,
                             IN OUT PVOID ParseContext OPTIONAL, 
							 OUT PHANDLE Handle);
NTSTATUS ObQueryNameString(
    IN PVOID  Object,
    OUT POBJECT_NAME_INFORMATION  ObjectNameInfo,
    IN ULONG  Length,
    OUT PULONG  ReturnLength); 

typedef struct _OBJECT_DIRECTORY {
    struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[ NUMBER_HASH_BUCKETS ];
    struct _OBJECT_DIRECTORY_ENTRY **LookupBucket;
    BOOLEAN LookupFound;
    USHORT SymbolicLinkUsageCount;
    struct _DEVICE_MAP *DeviceMap;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef struct _OBJECT_CREATE_INFORMATION { 
   ULONG Attributes; 
   HANDLE RootDirectory; 
   PVOID ParseContext; 
   KPROCESSOR_MODE ProbeMode; 
   ULONG PagedPoolCharge; 
   ULONG NonPagedPoolCharge; 
   ULONG SecurityDescriptorCharge; 
   PSECURITY_DESCRIPTOR SecurityDescriptor; 
   PSECURITY_QUALITY_OF_SERVICE SecurityQos; 
   SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService; 
} OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION; 

typedef struct _OBJECT_DUMP_CONTROL { 
   PVOID Stream; 
   ULONG Detail; 
} OB_DUMP_CONTROL, *POB_DUMP_CONTROL; 

typedef VOID (*OB_DUMP_METHOD)( 
   IN PVOID Object, 
   IN POB_DUMP_CONTROL Control OPTIONAL 
); 

typedef enum _OB_OPEN_REASON { 
   ObCreateHandle, 
   ObOpenHandle, 
   ObDuplicateHandle, 
   ObInheritHandle, 
   ObMaxOpenReason 
} OB_OPEN_REASON; 

typedef VOID (*OB_OPEN_METHOD)( 
   IN OB_OPEN_REASON OpenReason, 
   IN PEPROCESS Process OPTIONAL, 
   IN PVOID Object, 
   IN ACCESS_MASK GrantedAccess, 
   IN ULONG HandleCount 
); 

typedef VOID (*OB_CLOSE_METHOD)( 
   IN PEPROCESS Process OPTIONAL, 
   IN PVOID Object, 
   IN ACCESS_MASK GrantedAccess, 
   IN ULONG ProcessHandleCount, 
   IN ULONG SystemHandleCount 
); 

typedef BOOLEAN (*OB_OKAYTOCLOSE_METHOD)( 
   IN PEPROCESS Process OPTIONAL, 
   IN PVOID Object, 
   IN HANDLE Handle 
); 


typedef VOID (*OB_DELETE_METHOD)( 
   IN PVOID Object 
); 

typedef NTSTATUS (*OB_PARSE_METHOD)( 
	IN PVOID ParseObject, 
	IN PVOID ObjectType, 
	IN OUT PACCESS_STATE AccessState, 
	IN KPROCESSOR_MODE AccessMode, 
	IN ULONG Attributes, 
	IN OUT PUNICODE_STRING CompleteName, 
	IN OUT PUNICODE_STRING RemainingName, 
	IN OUT PVOID Context OPTIONAL, 
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL, 
	OUT PVOID *Object 
); 

typedef NTSTATUS (*OB_SECURITY_METHOD)( 
	IN PVOID Object, 
	IN SECURITY_OPERATION_CODE OperationCode, 
	IN PSECURITY_INFORMATION SecurityInformation, 
	IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor, 
	IN OUT PULONG CapturedLength, 
	IN OUT PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor, 
	IN POOL_TYPE PoolType, 
	IN PGENERIC_MAPPING GenericMapping 
); 

typedef NTSTATUS (*OB_QUERYNAME_METHOD)( 
   IN PVOID Object, 
   IN BOOLEAN HasObjectName, 
   OUT POBJECT_NAME_INFORMATION ObjectNameInfo, 
   IN ULONG Length, 
   OUT PULONG ReturnLength 
); 

typedef struct _OBJECT_TYPE_INITIALIZER { 
   USHORT Length; 
   BOOLEAN UseDefaultObject; 
   BOOLEAN CaseInsensitive; 
   ULONG InvalidAttributes; 
   GENERIC_MAPPING GenericMapping; 
   ULONG ValidAccessMask; 
   BOOLEAN SecurityRequired; 
   BOOLEAN MaintainHandleCount; 
   BOOLEAN MaintainTypeList; 
   POOL_TYPE PoolType; 
   ULONG DefaultPagedPoolCharge; 
   ULONG DefaultNonPagedPoolCharge; 
   OB_DUMP_METHOD DumpProcedure; 
   OB_OPEN_METHOD OpenProcedure; 
   OB_CLOSE_METHOD CloseProcedure; 
   OB_DELETE_METHOD DeleteProcedure; 
   OB_PARSE_METHOD ParseProcedure; 
   OB_SECURITY_METHOD SecurityProcedure; 
   OB_QUERYNAME_METHOD QueryNameProcedure; 
   OB_OKAYTOCLOSE_METHOD OkayToCloseProcedure; 
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER; 

typedef struct _OBJECT_TYPE {
    ERESOURCE Mutex;
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    ULONG Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;
    ULONG Key;
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OBJECT_HEADER { 
   LONG PointerCount; 
   union { 
      LONG HandleCount; 
      PSINGLE_LIST_ENTRY SEntry; 
   }; 
   POBJECT_TYPE Type; 
   UCHAR NameInfoOffset; 
   UCHAR HandleInfoOffset; 
   UCHAR QuotaInfoOffset; 
   UCHAR Flags; 
   union 
   { 
      POBJECT_CREATE_INFORMATION ObjectCreateInfo; 
      PVOID QuotaBlockCharged; 
   }; 
   PSECURITY_DESCRIPTOR SecurityDescriptor; 
   UCHAR Body; 
} OBJECT_HEADER, *POBJECT_HEADER; 
typedef struct _proclist
{
	unsigned int procID;
	unsigned int parntID;
	BYTE imageName[16];
	ANSI_STRING imagePath;
	ANSI_STRING imageDisk;
	int bHide;
	unsigned clow;
	unsigned chigh;
	unsigned xlow;
	unsigned xhigh;
	struct _proclist *next;
}PROCLIST, *PPROCLIST;
typedef enum _ObjectType
{
	Proc = 0,
	Thread,
	Driver,
	File
}ObjectType, *PObjectType;
typedef struct _ThrdContext
{
	POBJECT_TYPE pObj;
	ObjectType type;
	DWORD proccount;
	ULONG64 left;
	ULONG64 right;
} ThrdContext, *PThrdContext;
//extern  PWORD			NtBuildNumber;
//PMODULE_ENTRY gul_PsLoadedModuleList; 

typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
 
     //
     // Link to other blocks
     //
 
     LIST_ENTRY64 List;
 
     //
     // This is a unique tag to identify the owner of the block.
     // If your component only uses one pool tag, use it for this, too.
     //
 
     ULONG           OwnerTag;
 
     //
     // This must be initialized to the size of the data block,
     // including this structure.
     //
 
     ULONG           Size;
 
 } DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;
 typedef struct _KDDEBUGGER_DATA64 {

     DBGKD_DEBUG_DATA_HEADER64 Header;

     //
     // Base address of kernel image
     //

     ULONG64   KernBase;

     //
     // DbgBreakPointWithStatus is a function which takes an argument
     // and hits a breakpoint.  This field contains the address of the
     // breakpoint instruction.  When the debugger sees a breakpoint
     // at this address, it may retrieve the argument from the first
     // argument register, or on x86 the eax register.
     //
 
    ULONG64   BreakpointWithStatus;       // address of breakpoint
 
     //
     // Address of the saved context record during a bugcheck
     //
     // N.B. This is an automatic in KeBugcheckEx's frame, and
     // is only valid after a bugcheck.
     //
 
     ULONG64   SavedContext;
 
     //
     // help for walking stacks with user callbacks:
     //
 
     //
     // The address of the thread structure is provided in the
     // WAIT_STATE_CHANGE packet.  This is the offset from the base of
     // the thread structure to the pointer to the kernel stack frame
     // for the currently active usermode callback.
     //
 
     USHORT  ThCallbackStack;            // offset in thread data
 
     //
     // these values are offsets into that frame:
     //
 
     USHORT  NextCallback;               // saved pointer to next callback frame
     USHORT  FramePointer;               // saved frame pointer
 
     //
     // pad to a quad boundary
     //
     USHORT  PaeEnabled:1;
 
     //
     // Address of the kernel callout routine.
     //
 
     ULONG64   KiCallUserMode;             // kernel routine
 
     //
     // Address of the usermode entry point for callbacks.
     //
 
     ULONG64   KeUserCallbackDispatcher;   // address in ntdll
 
 
     //
     // Addresses of various kernel data structures and lists
     // that are of interest to the kernel debugger.
     //
 
     ULONG64   PsLoadedModuleList;
     ULONG64   PsActiveProcessHead;
     ULONG64   PspCidTable;

     ULONG64   ExpSystemResourcesList;
     ULONG64   ExpPagedPoolDescriptor;
     ULONG64   ExpNumberOfPagedPools;
 
     ULONG64   KeTimeIncrement;
     ULONG64   KeBugCheckCallbackListHead;
     ULONG64   KiBugcheckData;
 
     ULONG64   IopErrorLogListHead;
 
     ULONG64   ObpRootDirectoryObject;
     ULONG64   ObpTypeObjectType;
 
     ULONG64   MmSystemCacheStart;
     ULONG64   MmSystemCacheEnd;
     ULONG64   MmSystemCacheWs;
 
     ULONG64   MmPfnDatabase;
     ULONG64   MmSystemPtesStart;
     ULONG64   MmSystemPtesEnd;
     ULONG64   MmSubsectionBase;
     ULONG64   MmNumberOfPagingFiles;
 
     ULONG64   MmLowestPhysicalPage;
     ULONG64   MmHighestPhysicalPage;
     ULONG64   MmNumberOfPhysicalPages;
 
     ULONG64   MmMaximumNonPagedPoolInBytes;
     ULONG64   MmNonPagedSystemStart;
     ULONG64   MmNonPagedPoolStart;
     ULONG64   MmNonPagedPoolEnd;

     ULONG64   MmPagedPoolStart;
     ULONG64   MmPagedPoolEnd;
     ULONG64   MmPagedPoolInformation;
     ULONG64   MmPageSize;
 
     ULONG64   MmSizeOfPagedPoolInBytes;
 
     ULONG64   MmTotalCommitLimit;
     ULONG64   MmTotalCommittedPages;
     ULONG64   MmSharedCommit;
     ULONG64   MmDriverCommit;
     ULONG64   MmProcessCommit;
     ULONG64   MmPagedPoolCommit;
     ULONG64   MmExtendedCommit;
 
     ULONG64   MmZeroedPageListHead;
     ULONG64   MmFreePageListHead;
     ULONG64   MmStandbyPageListHead;
     ULONG64   MmModifiedPageListHead;
     ULONG64   MmModifiedNoWritePageListHead;
     ULONG64   MmAvailablePages;
     ULONG64   MmResidentAvailablePages;
 
     ULONG64   PoolTrackTable;
     ULONG64   NonPagedPoolDescriptor;
 
     ULONG64   MmHighestUserAddress;
     ULONG64   MmSystemRangeStart;
     ULONG64   MmUserProbeAddress;
 
     ULONG64   KdPrintCircularBuffer;
     ULONG64   KdPrintCircularBufferEnd;
     ULONG64   KdPrintWritePointer;
     ULONG64   KdPrintRolloverCount;
 
     ULONG64   MmLoadedUserImageList;

     // NT 5.1 Addition
 
     ULONG64   NtBuildLab;
     ULONG64   KiNormalSystemCall;
 
     // NT 5.0 QFE addition
 
     ULONG64   KiProcessorBlock;
     ULONG64   MmUnloadedDrivers;
     ULONG64   MmLastUnloadedDriver;
     ULONG64   MmTriageActionTaken;
     ULONG64   MmSpecialPoolTag;
     ULONG64   KernelVerifier;
     ULONG64   MmVerifierData;
     ULONG64   MmAllocatedNonPagedPool;
     ULONG64   MmPeakCommitment;
     ULONG64   MmTotalCommitLimitMaximum;
     ULONG64   CmNtCSDVersion;
 
     // NT 5.1 Addition
 
     ULONG64   MmPhysicalMemoryBlock;
     ULONG64   MmSessionBase;
     ULONG64   MmSessionSize;
    ULONG64   MmSystemParentTablePage;

 } KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;

 typedef struct _DBGKD_GET_VERSION64 {

     USHORT  MajorVersion;
     USHORT  MinorVersion;
     USHORT  ProtocolVersion;
     USHORT  Flags;
     USHORT  MachineType;
 
     //
     // Protocol command support descriptions.
     // These allow the debugger to automatically
     // adapt to different levels of command support
     // in different kernels.
     //
 
     // One beyond highest packet type understood, zero based.
     UCHAR   MaxPacketType;
     // One beyond highest state change understood, zero based.
     UCHAR   MaxStateChange;
     // One beyond highest state manipulate message understood, zero based.
     UCHAR   MaxManipulate;
 
     // Kind of execution environment the kernel is running in,
     // such as a real machine or a simulator.  Written back
     // by the simulation if one exists.
     UCHAR   Simulation;
 
     USHORT  Unused[1];
 
     ULONG64 KernBase;
     ULONG64 PsLoadedModuleList;
 
     //
     // Components may register a debug data block for use by
     // debugger extensions.  This is the address of the list head.
     //
     // There will always be an entry for the debugger.
     //
 
     ULONG64 DebuggerDataList;
 
 } DBGKD_GET_VERSION64, *PDBGKD_GET_VERSION64;

 typedef struct _DriverData
 {
 	ANSI_STRING  name;
	ANSI_STRING  servicename;
	//wchar_t name[256];
	//wchar_t servicename[256];
	ULONG64 address;
	struct _DriverData *next;
 }DriverData, *PDriverData;
 typedef struct _ThreadData
 {
       unsigned int threadID;
	unsigned int processID;
	BYTE imageName[16];
	struct _ThreadData *next;
 	
 } ThreadData, *PThreadData;
 
 typedef struct _FileList
 	{
 		ANSI_STRING filename;
		struct _FileList *next;
 	}FileList, *PFileList;

 //* Structure of an entity ID.
typedef struct TDIEntityID {
	ULONG		tei_entity;
	ULONG		tei_instance;
} TDIEntityID;

//* Structure of an object ID.
typedef struct TDIObjectID {
	TDIEntityID	toi_entity;
	ULONG		toi_class;
	ULONG		toi_type;
	ULONG		toi_id;
} TDIObjectID;

#define	CONTEXT_SIZE				16
//
// QueryInformationEx IOCTL. The return buffer is passed as the OutputBuffer
// in the DeviceIoControl request. This structure is passed as the
// InputBuffer.
//
struct tcp_request_query_information_ex {
	TDIObjectID   ID;                     // object ID to query.
    ULONG_PTR     Context[CONTEXT_SIZE/sizeof(ULONG_PTR)];  // multi-request context. Zeroed
	                                      // for the first request.
};

typedef struct tcp_request_query_information_ex
        TCP_REQUEST_QUERY_INFORMATION_EX,
        *PTCP_REQUEST_QUERY_INFORMATION_EX;

#define	CO_TL_ENTITY				0x400
#define	INFO_CLASS_PROTOCOL			0x200
#define	INFO_TYPE_PROVIDER			0x100

NTSTATUS  PsLookupProcessByProcessId(ULONG ProcessId,PEPROCESS *Process);
	typedef NTSTATUS (*NTQUERYSYSTEMINFORMATION)(
		
		IN ULONG                        SystemInformationClass,
		OUT PVOID                        SystemInformation,
		IN ULONG                        SystemInformationLength,
		OUT PULONG                        ReturnLength OPTIONAL  );
	
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
	typedef enum _SYSTEM_INFORMATION_CLASS     //    Q S
	{
			SystemBasicInformation,                // 00 Y N
			SystemProcessorInformation,            // 01 Y N
			SystemPerformanceInformation,          // 02 Y N
			SystemTimeOfDayInformation,            // 03 Y N
			SystemNotImplemented1,                 // 04 Y N
			SystemProcessesAndThreadsInformation,  // 05 Y N
			SystemCallCounts,                      // 06 Y N
			SystemConfigurationInformation,        // 07 Y N
			SystemProcessorTimes,                  // 08 Y N
			SystemGlobalFlag,                      // 09 Y Y
			SystemNotImplemented2,                 // 10 Y N
			SystemModuleInformation,               // 11 Y N
			SystemLockInformation,                 // 12 Y N
			SystemNotImplemented3,                 // 13 Y N
			SystemNotImplemented4,                 // 14 Y N
			SystemNotImplemented5,                 // 15 Y N
			SystemHandleInformation,               // 16 Y N
			SystemObjectInformation,               // 17 Y N
			SystemPagefileInformation,             // 18 Y N
			SystemInstructionEmulationCounts,      // 19 Y N
			SystemInvalidInfoClass1,               // 20
			SystemCacheInformation,                // 21 Y Y
			SystemPoolTagInformation,              // 22 Y N
			SystemProcessorStatistics,             // 23 Y N
			SystemDpcInformation,                  // 24 Y Y
			SystemNotImplemented6,                 // 25 Y N
			SystemLoadImage,                       // 26 N Y
			SystemUnloadImage,                     // 27 N Y
			SystemTimeAdjustment,                  // 28 Y Y
			SystemNotImplemented7,                 // 29 Y N
			SystemNotImplemented8,                 // 30 Y N
			SystemNotImplemented9,                 // 31 Y N
			SystemCrashDumpInformation,            // 32 Y N
			SystemExceptionInformation,            // 33 Y N
			SystemCrashDumpStateInformation,       // 34 Y Y/N
			SystemKernelDebuggerInformation,       // 35 Y N
			SystemContextSwitchInformation,        // 36 Y N
			SystemRegistryQuotaInformation,        // 37 Y Y
			SystemLoadAndCallImage,                // 38 N Y
			SystemPrioritySeparation,              // 39 N Y
			SystemNotImplemented10,                // 40 Y N
			SystemNotImplemented11,                // 41 Y N
			SystemInvalidInfoClass2,               // 42
			SystemInvalidInfoClass3,               // 43
			SystemTimeZoneInformation,             // 44 Y N
			SystemLookasideInformation,            // 45 Y N
			SystemSetTimeSlipEvent,                // 46 N Y
			SystemCreateSession,                   // 47 N Y
			SystemDeleteSession,                   // 48 N Y
			SystemInvalidInfoClass4,               // 49
			SystemRangeStartInformation,           // 50 Y N
			SystemVerifierInformation,             // 51 Y Y
			SystemAddVerifier,                     // 52 N Y
			SystemSessionProcessesInformation      // 53 Y N
	} SYSTEM_INFORMATION_CLASS;
	
	typedef struct _SYSTEM_MODULE_INFORMATION  // Information Class 11
	{
		ULONG  Reserved[2];
		PVOID  Base;
		ULONG  Size;
		ULONG  Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR   ImageName[256];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _FSRTL_COMMON_FCB_HEADER {

    CSHORT NodeTypeCode;
    CSHORT NodeByteSize;

    //
    //  General flags available to FsRtl.
    //

    UCHAR Flags;

    //
    //  Indicates if fast I/O is possible or if we should be calling
    //  the check for fast I/O routine which is found via the driver
    //  object.
    //

    UCHAR IsFastIoPossible; // really type FAST_IO_POSSIBLE

    //
    //  Second Flags Field
    //

    UCHAR Flags2;

    //
    //  The following reserved field should always be 0
    //

    UCHAR Reserved;

    PERESOURCE Resource;

    PERESOURCE PagingIoResource;

    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER ValidDataLength;

} FSRTL_COMMON_FCB_HEADER;
typedef FSRTL_COMMON_FCB_HEADER *PFSRTL_COMMON_FCB_HEADER;