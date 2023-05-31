
COMMENT("XP SP2 / W2K3 SP1 / VISTA")
MAKE_IMPORT_ENTRY(6,0, DecodePointer, 4)
MAKE_IMPORT_ENTRY(6,0, EncodePointer, 4)
COMMENT("XP")
MAKE_IMPORT_ENTRY(5,1, CreateIoCompletionPort, 16)
MAKE_IMPORT_ENTRY(5,1, GetQueuedCompletionStatus, 20)
MAKE_IMPORT_ENTRY(5,1, HeapSetInformation, 16)
MAKE_IMPORT_ENTRY(5,1, HeapQueryInformation, 20)
MAKE_IMPORT_ENTRY(5,1, InitializeSListHead, 4)
MAKE_IMPORT_ENTRY(5,1, InterlockedFlushSList, 4)
MAKE_IMPORT_ENTRY(5,1, InterlockedPopEntrySList, 4)
MAKE_IMPORT_ENTRY(5,1, InterlockedPushEntrySList, 8)
MAKE_IMPORT_ENTRY(5,1, PostQueuedCompletionStatus, 16)
MAKE_IMPORT_ENTRY(5,1, QueryDepthSList, 4)
COMMENT("W2K")
MAKE_IMPORT_ENTRY(5,0, CreateTimerQueue, 0)
MAKE_IMPORT_ENTRY(5,0, CreateTimerQueueTimer, 28)
MAKE_IMPORT_ENTRY(5,0, DeleteTimerQueueTimer, 12)
MAKE_IMPORT_ENTRY(5,0, VerSetConditionMask, 16)
COMMENT("NT 4 SP4+")
MAKE_IMPORT_ENTRY(5,0, VerifyVersionInfoA, 16)
COMMENT("NT 4 SP3+")
MAKE_IMPORT_ENTRY(5,0, InitializeCriticalSectionAndSpinCount, 8)
COMMENT("NT 4")
MAKE_IMPORT_ENTRY(4,0, IsProcessorFeaturePresent, 4)
MAKE_IMPORT_ENTRY(4,0, CancelIo, 4)
COMMENT("NT 3.51")
MAKE_IMPORT_ENTRY(3,51, IsDebuggerPresent, 0)
MAKE_IMPORT_ENTRY(3,51, GetSystemTimeAsFileTime, 4)
COMMENT("NT 3.50")
MAKE_IMPORT_ENTRY(3,50, GetVersionExA, 4)
MAKE_IMPORT_ENTRY(3,50, GetVersionExW, 4)
MAKE_IMPORT_ENTRY(3,50, GetEnvironmentStringsW, 0)
MAKE_IMPORT_ENTRY(3,50, FreeEnvironmentStringsW, 4)
MAKE_IMPORT_ENTRY(3,50, GetLocaleInfoA, 16)
MAKE_IMPORT_ENTRY(3,50, EnumSystemLocalesA, 8)
MAKE_IMPORT_ENTRY(3,50, IsValidLocale, 8)
MAKE_IMPORT_ENTRY(3,50, SetThreadAffinityMask, 8)
MAKE_IMPORT_ENTRY(3,50, GetProcessAffinityMask, 12)
MAKE_IMPORT_ENTRY(3,50, GetHandleInformation, 8)
MAKE_IMPORT_ENTRY(3,50, SetHandleInformation, 12)

