#ifndef __Process_H__
#define __Process_H__

#include <string>
#include <vector>
#include <Windows.h>
#include <winternl.h>

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

namespace All_SYS{
	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation = 0x0000,
		SystemProcessorInformation = 0x0001,
		SystemPerformanceInformation = 0x0002,
		SystemTimeOfDayInformation = 0x0003,
		SystemPathInformation = 0x0004,
		SystemProcessInformation = 0x0005,
		SystemCallCountInformation = 0x0006,
		SystemDeviceInformation = 0x0007,
		SystemProcessorPerformanceInformation = 0x0008,
		SystemFlagsInformation = 0x0009,
		SystemCallTimeInformation = 0x000A,
		SystemModuleInformation = 0x000B,
		SystemLocksInformation = 0x000C,
		SystemStackTraceInformation = 0x000D,
		SystemPagedPoolInformation = 0x000E,
		SystemNonPagedPoolInformation = 0x000F,
		SystemHandleInformation = 0x0010,
		SystemObjectInformation = 0x0011,
		SystemPageFileInformation = 0x0012,
		SystemVdmInstemulInformation = 0x0013,
		SystemVdmBopInformation = 0x0014,
		SystemFileCacheInformation = 0x0015,
		SystemPoolTagInformation = 0x0016,
		SystemInterruptInformation = 0x0017,
		SystemDpcBehaviorInformation = 0x0018,
		SystemFullMemoryInformation = 0x0019,
		SystemLoadGdiDriverInformation = 0x001A,
		SystemUnloadGdiDriverInformation = 0x001B,
		SystemTimeAdjustmentInformation = 0x001C,
		SystemSummaryMemoryInformation = 0x001D,
		SystemMirrorMemoryInformation = 0x001E,
		SystemPerformanceTraceInformation = 0x001F,
		SystemCrashDumpInformation = 0x0020,
		SystemExceptionInformation = 0x0021,
		SystemCrashDumpStateInformation = 0x0022,
		SystemKernelDebuggerInformation = 0x0023,
		SystemContextSwitchInformation = 0x0024,
		SystemRegistryQuotaInformation = 0x0025,
		SystemExtendServiceTableInformation = 0x0026,
		SystemPrioritySeperation = 0x0027,
		SystemVerifierAddDriverInformation = 0x0028,
		SystemVerifierRemoveDriverInformation = 0x0029,
		SystemProcessorIdleInformation = 0x002A,
		SystemLegacyDriverInformation = 0x002B,
		SystemCurrentTimeZoneInformation = 0x002C,
		SystemLookasideInformation = 0x002D,
		SystemTimeSlipNotification = 0x002E,
		SystemSessionCreate = 0x002F,
		SystemSessionDetach = 0x0030,
		SystemSessionInformation = 0x0031,
		SystemRangeStartInformation = 0x0032,
		SystemVerifierInformation = 0x0033,
		SystemVerifierThunkExtend = 0x0034,
		SystemSessionProcessInformation = 0x0035,
		SystemLoadGdiDriverInSystemSpace = 0x0036,
		SystemNumaProcessorMap = 0x0037,
		SystemPrefetcherInformation = 0x0038,
		SystemExtendedProcessInformation = 0x0039,
		SystemRecommendedSharedDataAlignment = 0x003A,
		SystemComPlusPackage = 0x003B,
		SystemNumaAvailableMemory = 0x003C,
		SystemProcessorPowerInformation = 0x003D,
		SystemEmulationBasicInformation = 0x003E,
		SystemEmulationProcessorInformation = 0x003F,
		SystemExtendedHandleInformation = 0x0040,
		SystemLostDelayedWriteInformation = 0x0041,
		SystemBigPoolInformation = 0x0042,
		SystemSessionPoolTagInformation = 0x0043,
		SystemSessionMappedViewInformation = 0x0044,
		SystemHotpatchInformation = 0x0045,
		SystemObjectSecurityMode = 0x0046,
		SystemWatchdogTimerHandler = 0x0047,
		SystemWatchdogTimerInformation = 0x0048,
		SystemLogicalProcessorInformation = 0x0049,
		SystemWow64SharedInformationObsolete = 0x004A,
		SystemRegisterFirmwareTableInformationHandler = 0x004B,
		SystemFirmwareTableInformation = 0x004C,
		SystemModuleInformationEx = 0x004D,
		SystemVerifierTriageInformation = 0x004E,
		SystemSuperfetchInformation = 0x004F,
		SystemMemoryListInformation = 0x0050,
		SystemFileCacheInformationEx = 0x0051,
		SystemThreadPriorityClientIdInformation = 0x0052,
		SystemProcessorIdleCycleTimeInformation = 0x0053,
		SystemVerifierCancellationInformation = 0x0054,
		SystemProcessorPowerInformationEx = 0x0055,
		SystemRefTraceInformation = 0x0056,
		SystemSpecialPoolInformation = 0x0057,
		SystemProcessIdInformation = 0x0058,
		SystemErrorPortInformation = 0x0059,
		SystemBootEnvironmentInformation = 0x005A,
		SystemHypervisorInformation = 0x005B,
		SystemVerifierInformationEx = 0x005C,
		SystemTimeZoneInformation = 0x005D,
		SystemImageFileExecutionOptionsInformation = 0x005E,
		SystemCoverageInformation = 0x005F,
		SystemPrefetchPatchInformation = 0x0060,
		SystemVerifierFaultsInformation = 0x0061,
		SystemSystemPartitionInformation = 0x0062,
		SystemSystemDiskInformation = 0x0063,
		SystemProcessorPerformanceDistribution = 0x0064,
		SystemNumaProximityNodeInformation = 0x0065,
		SystemDynamicTimeZoneInformation = 0x0066,
		SystemCodeIntegrityInformation = 0x0067,
		SystemProcessorMicrocodeUpdateInformation = 0x0068,
		SystemProcessorBrandString = 0x0069,
		SystemVirtualAddressInformation = 0x006A,
		SystemLogicalProcessorAndGroupInformation = 0x006B,
		SystemProcessorCycleTimeInformation = 0x006C,
		SystemStoreInformation = 0x006D,
		SystemRegistryAppendString = 0x006E,
		SystemAitSamplingValue = 0x006F,
		SystemVhdBootInformation = 0x0070,
		SystemCpuQuotaInformation = 0x0071,
		SystemNativeBasicInformation = 0x0072,
		SystemErrorPortTimeouts = 0x0073,
		SystemLowPriorityIoInformation = 0x0074,
		SystemBootEntropyInformation = 0x0075,
		SystemVerifierCountersInformation = 0x0076,
		SystemPagedPoolInformationEx = 0x0077,
		SystemSystemPtesInformationEx = 0x0078,
		SystemNodeDistanceInformation = 0x0079,
		SystemAcpiAuditInformation = 0x007A,
		SystemBasicPerformanceInformation = 0x007B,
		SystemQueryPerformanceCounterInformation = 0x007C,
		SystemSessionBigPoolInformation = 0x007D,
		SystemBootGraphicsInformation = 0x007E,
		SystemScrubPhysicalMemoryInformation = 0x007F,
		SystemBadPageInformation = 0x0080,
		SystemProcessorProfileControlArea = 0x0081,
		SystemCombinePhysicalMemoryInformation = 0x0082,
		SystemEntropyInterruptTimingInformation = 0x0083,
		SystemConsoleInformation = 0x0084,
		SystemPlatformBinaryInformation = 0x0085,
		SystemThrottleNotificationInformation = 0x0086,
		SystemHypervisorProcessorCountInformation = 0x0087,
		SystemDeviceDataInformation = 0x0088,
		SystemDeviceDataEnumerationInformation = 0x0089,
		SystemMemoryTopologyInformation = 0x008A,
		SystemMemoryChannelInformation = 0x008B,
		SystemBootLogoInformation = 0x008C,
		SystemProcessorPerformanceInformationEx = 0x008D,
		SystemSpare0 = 0x008E,
		SystemSecureBootPolicyInformation = 0x008F,
		SystemPageFileInformationEx = 0x0090,
		SystemSecureBootInformation = 0x0091,
		SystemEntropyInterruptTimingRawInformation = 0x0092,
		SystemPortableWorkspaceEfiLauncherInformation = 0x0093,
		SystemFullProcessInformation = 0x0094,
		MaxSystemInfoClass = 0x0095
	} SYSTEM_INFORMATION_CLASS;

#ifdef _WIN64
	//redefine the struct in windows interal header to include undocumented values
	typedef struct _PEB_LDR_DATA {
		ULONG			Length;
		UCHAR			Initialized;
		ULONG64			SsHandle;
		LIST_ENTRY64	InLoadOrderModuleList;
		LIST_ENTRY64	InMemoryOrderModuleList; 
		LIST_ENTRY64	InInitializationOrderModuleList;
		PVOID64			EntryInProgress;
		UCHAR			ShutdownInProgress;
		PVOID64			ShutdownThreadId;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _PEB{
		UCHAR				InheritedAddressSpace;				
		UCHAR				ReadImageFileExecOptions;			
		UCHAR				BeingDebugged;						
		BYTE				Reserved0;								
		ULONG				Reserved1;
		ULONG64				Reserved3;								
		ULONG64				ImageBaseAddress;					
		ULONG64				LoaderData;						
		ULONG64				ProcessParameters;					
	}PEB, *PPEB;

	/** A structure that holds information about a single module loaded by a process **/
	/** LIST_ENTRY is a link list pointing to the prev/next Module loaded **/
	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY64		InLoadOrderModuleList;
		LIST_ENTRY64		InMemoryOrderModuleList;
		LIST_ENTRY64		InInitializationOrderModuleList;
		ULONG64				BaseAddress;
		ULONG64				EntryPoint;
		ULONG				SizeOfImage;	//bytes
		UNICODE_STRING		FullDllName;
		UNICODE_STRING		BaseDllName;
		ULONG				Flags;
		USHORT				LoadCount;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#else
	//redefine the struct in windows interal header to include undocumented values
	typedef struct _PEB_LDR_DATA {
		DWORD					Length;
		UCHAR					Initialized;
		PVOID	                SsHandle;
		LIST_ENTRY              InLoadOrderModuleList;
		LIST_ENTRY				InMemoryOrderModuleList;
		LIST_ENTRY              InInitializationOrderModuleList;
		PVOID					EntryInProgress;
		UCHAR					ShutdownInProgress;
		PVOID					ShutdownThreadId;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _PEB{
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		BYTE Reserved2[9];
		PPEB_LDR_DATA LoaderData;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		BYTE Reserved3[448];
		ULONG SessionId;
	}PEB, *PPEB;

	/** A structure that holds information about a single module loaded by a process **/
	/** LIST_ENTRY is a link list pointing to the prev/next Module loaded **/
	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY            InLoadOrderModuleList;
		LIST_ENTRY            InMemoryOrderModuleList;
		LIST_ENTRY            InInitializationOrderModuleList;
		PVOID                 BaseAddress;
		PVOID                 EntryPoint;
		ULONG                 SizeOfImage;
		UNICODE_STRING        FullDllName;
		UNICODE_STRING        BaseDllName;
		ULONG                 Flags;
		USHORT				  LoadCount;
		USHORT                 TlsIndex;
		LIST_ENTRY            HashTableEntry;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
		_ACTIVATION_CONTEXT *	EntryPointActivationContext;
		PVOID					PatchInformation;
		LIST_ENTRY				ForwarderLinks;
		LIST_ENTRY				ServiceTagLinks;
		LIST_ENTRY				StaticLinks;
		PVOID					ContextInformation;
		DWORD					OriginalBase;
		LARGE_INTEGER			LoadTime;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#endif
}

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
#ifdef _WIN64
		ULONG pad1;
	ULONG UniqueProcessId;
		ULONG pad2;
	ULONG InheritedFromUniqueProcessId;
		ULONG pad3, pad4, pad5;
#else
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
#endif
	ULONG HandleCount;
	ULONG SessionId;
	PVOID PageDirectoryBase;
	ULONG VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	PVOID Reserved[1];
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef NTSTATUS(NTAPI *_ntQSI)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI * pNtQueryInformationProcess)
(
	HANDLE,
	PROCESSINFOCLASS,
	PVOID,
	ULONG,
	PULONG
);

class Process{
private:
	All_SYS::PLDR_DATA_TABLE_ENTRY GetNextNode(PCHAR nNode, int Offset);
	All_SYS::PLDR_DATA_TABLE_ENTRY GetPrevNode(PCHAR nNode, int Offset);
	BOOL RemoveDLL(DWORD PID, std::wstring DLLtoRemove, int ListType);

public:
	BOOL DLLInLoadStatus = FALSE;
	BOOL DLLInMemStatus = FALSE;
	BOOL DLLInInInitializationStatus = FALSE;

	Process(std::string Proc, std::wstring DLLName);
	~Process();

	struct Process_INFO{
		DWORD Process_ID = 0;
		std::string Process_Name = "";
		std::string Create_Time = "";
		ULONG HandleCount = 0;
		ULONG ModuleCount = 0;
		ULONG ThreadCount = 0;
	}Pinfo;

	Process_INFO GetProcessInfo(std::string & PN);

	void ListModules(DWORD PID, int ListType, int Order);
};

#endif