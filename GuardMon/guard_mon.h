// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares extended functions for the GuardMon.
//

#ifndef GUARDMON_GUARD_MON_H_
#define GUARDMON_GUARD_MON_H_

#include "../HyperPlatform/HyperPlatform/ia32_type.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS GMonInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) void GMonTermination();

NTSTATUS GMonInstallPatchCallback(_In_opt_ void* context);

bool GMonIsNonImageKernelAddress(_In_ ULONG_PTR address);

void GMonRemoveNoCr0ModificationFlag(_In_ const GpRegisters* registers);

ULONG_PTR GMonCheckExecutionContext(_In_ const GpRegisters* registers,
                                    _In_ ULONG_PTR guest_ip);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif  // GUARDMON_GUARD_MON_H_
