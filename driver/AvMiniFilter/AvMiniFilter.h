#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <dontuse.h>
#include <suppress.h>

#define AVMINIFILTER_COMM_PORT_NAME L"\\AvMiniFilterPort"

// Message types exchanged with the user-mode service over the
// FltCreateCommunicationPort connection.
typedef enum _AVMF_MESSAGE_TYPE {
    AvmfMessageFileCreate = 1,
} AVMF_MESSAGE_TYPE;

typedef struct _AVMF_NOTIFICATION {
    AVMF_MESSAGE_TYPE MessageType;
    WCHAR FilePath[260];
} AVMF_NOTIFICATION;

// Verdict returned by the user-mode service via FltSendMessage's reply
// buffer (delivered through FilterReplyMessage on the other side, which
// strips its own FILTER_REPLY_HEADER -- the client's payload struct must
// have the same layout as this one; see avrealtimeblock/minifilter_client.cpp,
// kept in sync by hand since that client can't include this kernel header).
typedef enum _AVMF_VERDICT {
    AvmfVerdictAllow = 0,
    AvmfVerdictBlock = 1,
} AVMF_VERDICT;

typedef struct _AVMF_REPLY {
    AVMF_VERDICT Verdict;
} AVMF_REPLY;

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
AvmfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

NTSTATUS
AvmfUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
AvmfPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

EXTERN_C_END
