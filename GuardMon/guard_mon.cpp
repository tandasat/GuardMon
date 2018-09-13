// Copyright (c) 2015-2018, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements extended functions for the GuardMon.
//
#include "guard_mon.h"
#include <intrin.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/asm.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// Install patch(es) to the kernel so that PatchGuard fires and GuardMon can
// detect it too. It is, however, mostly for a demonstration purpose because
// GuardMon cannot always kill PatchGuard. For example, PatchGuard may run with
// a image region or may not access to CR0 (confirmed on Win10 10586). It means
// GuardMon is unable to catch PatchGuard's activities.
static const bool kGMonpInstallPatch = false;

// Enables dirty, unreliable hack for Windows 10.
static const bool kGMonpEnableDirtyHack = false;

////////////////////////////////////////////////////////////////////////////////
//
// types
//
struct PgContext {
  UCHAR reserved[0xc8];
  void *ExAcquireResourceSharedLite;  // + 0xc8
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

PVOID NTAPI RtlPcToFileHeader(_In_ PVOID pc_value, _Out_ PVOID *base_of_image);

static ULONG_PTR GMonIsPgExcutionContext(_In_ const GpRegisters *registers);

static bool GMonpIsPgContext(_In_ ULONG_PTR address);

static void GMonpNeutralizePgContextForDpc(_In_ PgContext *pg_context);

static void GMonpFakeExQueueWorkItem(_Inout_ __drv_aliasesMem void *work_item,
                                     _In_ void *queue_type);

DECLSPEC_NORETURN void GMonWaitForever(_In_ const AllRegisters *registers,
                                       _In_ ULONG_PTR stack_pointer);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, GMonInitialization)
#pragma alloc_text(PAGE, GMonTermination)
#pragma alloc_text(INIT, GMonInstallPatchCallback)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// An address of ExAcquireResourceSharedLite. Used to verify the if the address
// is a PatchGuard context.
static void *g_gmonp_ExAcquireResourceSharedLite = nullptr;

// Indicates if the system is Windows 10 where dirty, unreliable hack can be
// applied.
static bool g_gmonp_is_windows10 = false;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes GuardMon components
_Use_decl_annotations_ NTSTATUS GMonInitialization() {
  PAGED_CODE();

  g_gmonp_ExAcquireResourceSharedLite =
      UtilGetSystemProcAddress(L"ExAcquireResourceSharedLite");
  if (!g_gmonp_ExAcquireResourceSharedLite) {
    return STATUS_PROCEDURE_NOT_FOUND;
  }

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (os_version.dwMajorVersion == 10 && os_version.dwMinorVersion == 0) {
    g_gmonp_is_windows10 = true;
  }
  return STATUS_SUCCESS;
}

// Terminates GuardMon components
_Use_decl_annotations_ void GMonTermination() { PAGED_CODE(); }

// Modifies IDTL so that PatchGuard fires soon.
_Use_decl_annotations_ NTSTATUS GMonInstallPatchCallback(void *context) {
  UNREFERENCED_PARAMETER(context);

  if (kGMonpInstallPatch) {
    Idtr idt = {};
    __sidt(&idt);
    const auto old_limit = idt.limit;
    idt.limit = 0xffff;
    __lidt(&idt);
    __sidt(&idt);
    HYPERPLATFORM_LOG_INFO("Patched IDTL %04hx => %04hx", old_limit, idt.limit);
  }
  return STATUS_SUCCESS;
}

// Checks if the address is out of any kernel modules. Beware that this is not
// comprehensive check to detect all possible patterns of the interesting things
_Use_decl_annotations_ bool GMonIsNonImageKernelAddress(ULONG_PTR address) {
  void *base = nullptr;
  if (address >= reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) &&
      !RtlPcToFileHeader(reinterpret_cast<void *>(address), &base)) {
    return true;
  }
  return false;
}

// Takes out a flag indicating that CR0 modification does not take place
_Use_decl_annotations_ void GMonRemoveNoCr0ModificationFlag(
    const GpRegisters *registers) {
  if (!g_gmonp_is_windows10 || !kGMonpEnableDirtyHack) {
    return;
  }

  const auto pg_context =
      reinterpret_cast<PgContext *>(GMonIsPgExcutionContext(registers));
  if (!pg_context) {
    return;
  }
  HYPERPLATFORM_LOG_INFO_SAFE("PatchGuard Context = %p", pg_context);

  // Take out a flag indicating that CR0 modification does not take place from
  // a PatchGuard context control field at +0x688 (on 10.0.10568.122).
  static const auto kOffsetToControlFlagsField = 0x688u;
  static const auto kNoCr0ModificationFlag = 0x8000000u;
  const auto pg_context_byte = reinterpret_cast<UCHAR *>(pg_context);
  const auto flags =
      reinterpret_cast<ULONG *>(pg_context_byte + kOffsetToControlFlagsField);
  if (*flags & kNoCr0ModificationFlag) {
    const auto old_value = *flags;
    *flags &= (~kNoCr0ModificationFlag);
    HYPERPLATFORM_LOG_INFO_SAFE(
        "A control flag at %p has been modified (0x%08x => 0x%08x)", flags,
        old_value, *flags);
  }
}

// Checks if the thread is executing in a context of PatchGuard. Returns an
// address to overwrite a guest IP if the is the case. Otherwise, returns 0.
_Use_decl_annotations_ ULONG_PTR
GMonCheckExecutionContext(const GpRegisters *registers, ULONG_PTR guest_ip) {
  const auto pg_context =
      reinterpret_cast<PgContext *>(GMonIsPgExcutionContext(registers));
  if (!pg_context) {
    return 0;
  }
  HYPERPLATFORM_LOG_INFO_SAFE("PatchGuard Context = %p", pg_context);

  // An epilogue of Pg_xSelfValidation(). Now the thread can be executing a DPC
  // function Pg_xSelfValidation(). In that case, we need to return from it
  // safely.
  //
  // 48 8B C3                 mov     rax, rbx        ; Windows 7
  // 48 8B C7                 mov     rax, rdi        ; Windows 8.1 and 10
  // 4C 8D 9C 24 C0 02 00 00  lea     r11, [rsp+2C0h]
  // 49 8B 5B 30              mov     rbx, [r11+30h]
  // 49 8B 73 38              mov     rsi, [r11+38h]
  // 49 8B 7B 40              mov     rdi, [r11+40h]
  // 49 8B E3                 mov     rsp, r11
  // 41 5F                    pop     r15
  // 41 5E                    pop     r14
  // 41 5D                    pop     r13
  // 41 5C                    pop     r12
  // 5D                       pop     rbp
  // C3                       retn
  static const UCHAR kDpcEpiloguePattern8_10[] = {
      0x48, 0x8B, 0xC7, 0x4C, 0x8D, 0x9C, 0x24, 0xC0, 0x02, 0x00, 0x00, 0x49,
      0x8B, 0x5B, 0x30, 0x49, 0x8B, 0x73, 0x38, 0x49, 0x8B, 0x7B, 0x40, 0x49,
      0x8B, 0xE3, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5D, 0xC3,
  };
  static const UCHAR kDpcEpiloguePattern7[] = {
      0x48, 0x8B, 0xC3, 0x4C, 0x8D, 0x9C, 0x24, 0xC0, 0x02, 0x00, 0x00, 0x49,
      0x8B, 0x5B, 0x30, 0x49, 0x8B, 0x73, 0x38, 0x49, 0x8B, 0x7B, 0x40, 0x49,
      0x8B, 0xE3, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5D, 0xC3,
  };

  // Try Win8 and 10 pattern
  auto epilogue_address =
      UtilMemMem(reinterpret_cast<void *>(guest_ip), 0x400,
                 kDpcEpiloguePattern8_10, sizeof(kDpcEpiloguePattern8_10));
  if (!epilogue_address) {
    // Try Win7 pattern if failed
    epilogue_address =
        UtilMemMem(reinterpret_cast<void *>(guest_ip), 0x400,
                   kDpcEpiloguePattern7, sizeof(kDpcEpiloguePattern7));
  }
  HYPERPLATFORM_LOG_INFO_SAFE("DPC Epilogue Address = %p", epilogue_address);

  if (epilogue_address) {
    // Executing Pg_xSelfValidation(). Set a return address to its epilogue and
    // neutralize the context.
    GMonpNeutralizePgContextForDpc(pg_context);
    return reinterpret_cast<ULONG_PTR>(epilogue_address);
  } else {
    // Not. Likely to be in a main validation routine. Let the thread return to
    // AsmWaitForever().
    return reinterpret_cast<ULONG_PTR>(AsmWaitForever);
  }
}

// Checks if the context have a reference to the PatchGuard context.
_Use_decl_annotations_ static ULONG_PTR GMonIsPgExcutionContext(
    const GpRegisters *registers) {
  // clang-format off
  if (GMonpIsPgContext(registers->ax)) { return registers->ax; }
  if (GMonpIsPgContext(registers->bx)) { return registers->bx; }
  if (GMonpIsPgContext(registers->cx)) { return registers->cx; }
  if (GMonpIsPgContext(registers->dx)) { return registers->dx; }
  if (GMonpIsPgContext(registers->di)) { return registers->di; }
  if (GMonpIsPgContext(registers->si)) { return registers->si; }
  if (GMonpIsPgContext(registers->bp)) { return registers->bp; }
  if (GMonpIsPgContext(registers->r9)) { return registers->r9; }
  if (GMonpIsPgContext(registers->r10)) { return registers->r10; }
  if (GMonpIsPgContext(registers->r11)) { return registers->r11; }
  if (GMonpIsPgContext(registers->r12)) { return registers->r12; }
  if (GMonpIsPgContext(registers->r13)) { return registers->r13; }
  if (GMonpIsPgContext(registers->r14)) { return registers->r14; }
  if (GMonpIsPgContext(registers->r15)) { return registers->r15; }
  // clang-format on
  return 0;
}

// Checks if the address is the PatchGuard context
_Use_decl_annotations_ static bool GMonpIsPgContext(ULONG_PTR address) {
  const auto p_ExAcquireResourceSharedLite =
      g_gmonp_ExAcquireResourceSharedLite;
  const auto pg_context = reinterpret_cast<PgContext *>(address);

  // Test if any of 10 fields following ExAcquireResourceSharedLite has a
  // pointer to the ExAcquireResourceSharedLite().
  auto potential_ExAcquireResourceSharedLite =
      &pg_context->ExAcquireResourceSharedLite;
  static const auto kMaxPointersToCheck = 10u;
  for (auto i = 0u; i < kMaxPointersToCheck; ++i) {
    if (UtilIsAccessibleAddress(potential_ExAcquireResourceSharedLite)) {
      if (*potential_ExAcquireResourceSharedLite ==
          p_ExAcquireResourceSharedLite) {
        return true;
      }
    }
    ++potential_ExAcquireResourceSharedLite;
  }

  return false;
}

// Overwrites a function pointer to ExQueueWorkItem() in the PatchGuard context.
// This function just fills 10 pointers from the ExAcquireResourceSharedLite
// field because we do not exactly know which field holds a pointer to the
// ExQueueWorkItem().
_Use_decl_annotations_ static void GMonpNeutralizePgContextForDpc(
    PgContext *pg_context) {
  auto potential_ExAcquireResourceSharedLite =
      &pg_context->ExAcquireResourceSharedLite;

  static const auto kMaxPointersToOverwrite = 10u;
  for (auto i = 0u; i < kMaxPointersToOverwrite; ++i) {
    *potential_ExAcquireResourceSharedLite = GMonpFakeExQueueWorkItem;
    ++potential_ExAcquireResourceSharedLite;
  }
}

// A fake ExQueueWorkItem(). Does nothing. It is called from a neutralized
// PatchGuard context after it returned from the Pg_xSelfValidation().
_Use_decl_annotations_ static void GMonpFakeExQueueWorkItem(void *work_item,
                                                            void *queue_type) {
  UNREFERENCED_PARAMETER(work_item);
  UNREFERENCED_PARAMETER(queue_type);

  HYPERPLATFORM_LOG_INFO_SAFE(
      "PatchGuard context has been detected and terminated.");
}

// Wait forever in order to disable this PatchGuard context. This function
// should not be executed from the first validation routine that runs as DPC (
// namely, Pg_xSelfValidation()). Since DPC routines cannot lower IRQL,
// execution of this function results in a bug check.
#pragma warning(push)
#pragma warning(disable : 28167)
_Use_decl_annotations_ void GMonWaitForever(const AllRegisters *registers,
                                            ULONG_PTR stack_pointer) {
  UNREFERENCED_PARAMETER(registers);
  UNREFERENCED_PARAMETER(stack_pointer);

  HYPERPLATFORM_LOG_INFO_SAFE(
      "PatchGuard context has been detected and terminated.");
  HYPERPLATFORM_COMMON_DBG_BREAK();

#pragma warning(push)
#pragma warning(disable : 28138)
  KeLowerIrql(PASSIVE_LEVEL);
#pragma warning(push)

  // Wait until this thread ends == never returns
  for (auto status = STATUS_SUCCESS;;) {
    status = KeWaitForSingleObject(PsGetCurrentThread(), Executive, KernelMode,
                                   FALSE, nullptr);
    HYPERPLATFORM_LOG_WARN("Oops? (%08x)", status);
    UtilSleep(60000);
  }
}
#pragma warning(push)

}  // extern "C"
