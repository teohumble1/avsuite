#include "AvMiniFilter.h"

// ---------------------------------------------------------------------------
// AvSuite real-time protection minifilter -- Phase 4 architecture skeleton.
//
// SAFETY: this project is intentionally NOT part of the main AvSuite CMake
// build, and the resulting .sys must never be loaded on a developer's
// primary host. Build and load-test only inside a disposable, snapshotted
// VM with a kernel debugger attached and test signing enabled -- a bug here
// can blue-screen the machine, and unlike the Phase 1 skeleton this version
// can also genuinely deny file opens (including, if AvmfPreCreate's requestor
// check below is ever removed or miswired, the AV's own process's opens --
// see the gClientProcessId check). See the project plan's Phase 4 section.
//
// What this skeleton demonstrates:
//   - Registering with the Filter Manager (FltRegisterFilter) for a single
//     PreCreate callback on local disk volumes -- the file-open/execute
//     interception point where real *blocking* protection happens, unlike
//     Phase 1's detect-after-the-fact ReadDirectoryChangesW.
//   - A communication port (FltCreateCommunicationPort/FltSendMessage) so a
//     user-mode service (avrealtimeblock::MinifilterClient, started by
//     avengine::Engine::StartRealtimeProtection, i.e. host_console's
//     --watch) receives a notification for every file open and returns a
//     block/allow verdict.
//
// Safety properties this skeleton depends on -- all "fail open" (allow the
// file) rather than risk a system-wide hang or deadlock:
//   - No client connected (gClientPort == NULL): allow immediately, no send.
//   - FltSendMessage given a bounded timeout (kSendTimeout below): a wedged
//     or crashed client degrades this to detect-only, never to every file
//     open on the system blocking forever.
//   - The connecting client process's own file opens are never intercepted
//     (gClientProcessId check) -- otherwise the client's own scan-time file
//     reads of the very file it's being asked to verdict on would recurse
//     into another FltSendMessage while the client's single message-pump
//     thread is still blocked handling the first one. Self-deadlock,
//     guaranteed, the moment the AV's own process opens anything.
//
// What it still deliberately does NOT do (documented follow-up, not a bug):
//   - Any scanning logic. The driver only ever forwards a raw file path and
//     relays back the caller's verdict; static_scan/behavior_engine stay
//     entirely in user mode.
//   - Queueing/parallelism: FltCreateCommunicationPort below caps
//     MaxConnections at 1, and the reference client services one message at
//     a time -- every file-create on the box serializes behind that one
//     scan. Acceptable for this skeleton; a production version needs a
//     thread pool on the client side (see WDK's "scanner" sample).
// ---------------------------------------------------------------------------

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
ULONG gClientProcessId = 0;
// Protects gClientPort + gClientProcessId against concurrent Disconnect.
// PreCreate acquires shared; Connect/Disconnect acquire exclusive.
// Must be ERESOURCE (not spinlock) because FltSendMessage requires PASSIVE_LEVEL.
ERESOURCE gClientPortLock;

static const LONGLONG kSendTimeout100ns = -50000000LL; // 5 seconds, relative

// Whitelist of executable names that should NOT be scanned (self-referential to prevent deadlock/FP).
static const WCHAR* kWhitelistedExes[] = {
    L"avconsolehost.exe",
    L"avdashboard.exe",
};

static BOOLEAN IsWhitelisted(_In_ PCUNICODE_STRING FileName)
{
    for (ULONG i = 0; i < ARRAYSIZE(kWhitelistedExes); i++) {
        SIZE_T nameLen = wcslen(kWhitelistedExes[i]);
        if (FileName->Length >= nameLen * sizeof(WCHAR)) {
            SIZE_T offsetBytes = FileName->Length - nameLen * sizeof(WCHAR);
            WCHAR* pStart = (WCHAR*)((UCHAR*)FileName->Buffer + offsetBytes);
            if (RtlEqualMemory(pStart, kWhitelistedExes[i], nameLen * sizeof(WCHAR))) {
                // The match must be a WHOLE path component, not merely a suffix:
                // either it is the entire string, or the character just before it
                // is a path separator. Without this, "xavdashboard.exe" ends with
                // "avdashboard.exe" and would be whitelisted -> real-time scan
                // bypass by rename (review #2). NOTE: still name-based; a stronger
                // fix keys off the verified client image/PID.
                if (offsetBytes == 0) {
                    return TRUE;
                }
                WCHAR prev = *(WCHAR*)((UCHAR*)FileName->Buffer + offsetBytes - sizeof(WCHAR));
                if (prev == L'\\' || prev == L'/') {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      AvmfPreCreate,
      NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),  // Size
    FLT_REGISTRATION_VERSION,  // Version
    0,                         // Flags
    NULL,                      // ContextRegistration
    Callbacks,                 // OperationRegistration
    AvmfUnload,                // FilterUnloadCallback
    AvmfInstanceSetup,         // InstanceSetupCallback
    NULL,                      // InstanceQueryTeardownCallback
    NULL,                      // InstanceTeardownStartCallback
    NULL,                      // InstanceTeardownCompleteCallback
    NULL,                      // GenerateFileNameCallback
    NULL,                      // GenerateDestinationFileNameCallback
    NULL                       // NormalizeNameComponentCallback
};

NTSTATUS
AvmfConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    // Single-client design for this skeleton: the Phase 2 service is the
    // only expected connector. A production version should reject a second
    // connection attempt while one is already active.
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&gClientPortLock, TRUE);
    gClientPort = ClientPort;
    gClientProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    ExReleaseResourceLite(&gClientPortLock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

VOID
AvmfDisconnect(
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&gClientPortLock, TRUE);
    FltCloseClientPort(gFilterHandle, &gClientPort);
    gClientPort = NULL;
    gClientProcessId = 0;
    ExReleaseResourceLite(&gClientPortLock);
    KeLeaveCriticalRegion();
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeResourceLite(&gClientPortLock);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        ExDeleteResourceLite(&gClientPortLock);
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        ExDeleteResourceLite(&gClientPortLock);
        return status;
    }

    RtlInitUnicodeString(&portName, AVMINIFILTER_COMM_PORT_NAME);
    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE,
        NULL,
        securityDescriptor);

    status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &objectAttributes,
        NULL,
        AvmfConnect,
        AvmfDisconnect,
        NULL,
        1);

    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        ExDeleteResourceLite(&gClientPortLock);
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        FltUnregisterFilter(gFilterHandle);
        ExDeleteResourceLite(&gClientPortLock);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
AvmfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    // Skip exotic/remote filesystems for this skeleton -- attach only to
    // local disk volumes.
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
AvmfUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    FltCloseCommunicationPort(gServerPort);
    FltUnregisterFilter(gFilterHandle);
    ExDeleteResourceLite(&gClientPortLock);
    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
AvmfPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    AVMF_NOTIFICATION notification;
    // Reply buffer must include FILTER_REPLY_HEADER prefix -- see WDK scanner
    // sample. Without it FltSendMessage returns an error and verdict is never read.
    struct {
        FILTER_REPLY_HEADER Header;
        AVMF_REPLY Payload;
    } reply;
    ULONG replyLength;
    NTSTATUS status;
    LARGE_INTEGER timeout;
    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Fast-path without lock -- authoritative check is inside the lock below.
    if (gClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get name info outside the lock. In a PRE-create callback the target
    // file is not open yet, so requesting the NORMALIZED name is unsafe:
    // Filter Manager may have to issue I/O to resolve it and can re-enter the
    // create path (network redirectors, reparse points), deadlocking. Use the
    // OPENED name, which is resolved from the create parameters already in
    // Data and never triggers that recursion. The WDK "scanner" sample defers
    // NORMALIZED to post-create for the same reason. We fail open on error.
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    // Skip whitelisted executables (AvSuite's own binaries).
    if (IsWhitelisted(&nameInfo->FinalComponent)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(&notification, sizeof(notification));
    notification.MessageType = AvmfMessageFileCreate;

    // UNICODE_STRING.Buffer is NOT null-terminated -- copy by Length (bytes).
    {
        USHORT chars = nameInfo->Name.Length / sizeof(WCHAR);
        USHORT max_chars = (USHORT)(sizeof(notification.FilePath) / sizeof(WCHAR)) - 1;
        if (chars > max_chars) chars = max_chars;
        RtlCopyMemory(notification.FilePath, nameInfo->Name.Buffer, chars * sizeof(WCHAR));
        notification.FilePath[chars] = L'\0';
    }

    FltReleaseFileNameInformation(nameInfo);

    // Acquire shared lock before touching gClientPort/gClientProcessId.
    // AvmfDisconnect holds the exclusive lock while zeroing gClientPort, so
    // this prevents the TOCTOU race (NULL-check passes → Disconnect fires →
    // FltSendMessage called with NULL port → BSOD). Shared lock is enough
    // because multiple PreCreate threads can coexist; only Connect/Disconnect
    // need exclusive. FltSendMessage requires PASSIVE_LEVEL, which holds here;
    // ERESOURCE (not spinlock) is therefore the correct primitive.
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&gClientPortLock, TRUE);

    if (gClientPort != NULL && FltGetRequestorProcessId(Data) != gClientProcessId) {
        RtlZeroMemory(&reply, sizeof(reply));
        replyLength = sizeof(reply);
        timeout.QuadPart = kSendTimeout100ns;

        status = FltSendMessage(
            gFilterHandle,
            &gClientPort,
            &notification,
            sizeof(notification),
            &reply,
            &replyLength,
            &timeout);

        if (NT_SUCCESS(status) && reply.Payload.Verdict == AvmfVerdictBlock) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            result = FLT_PREOP_COMPLETE;
        }
        // Allow on: explicit Allow, STATUS_TIMEOUT (client wedged → degrade to
        // detect-only), or any FltSendMessage failure (client disconnected).
    }

    ExReleaseResourceLite(&gClientPortLock);
    KeLeaveCriticalRegion();

    return result;
}
