#pragma once

#include <atlbase.h>
#include <atlstr.h>
#include <psapi.h>
#include "bcrypt.h"

#define ASSERT ATLASSERT
#define VERIFY ATLVERIFY
#define TRACE ATLTRACE

//
// These definitions from the WDK are reproduced here to avoid the dependency on
// the WDK just to run this sample project.
//

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INVALID_BUFFER_SIZE
#define STATUS_INVALID_BUFFER_SIZE ((NTSTATUS)0xC0000206L)
#endif

#ifndef STATUS_INVALID_SIGNATURE
#define STATUS_INVALID_SIGNATURE ((NTSTATUS)0xC000A000L)
#endif

#define ASSERT(a)
#include "KerrSecurityCryptography.h"
using namespace Kerr::Security::Cryptography;

/*
//#using <System.dll>
using namespace System::Security::Cryptography;
using namespace System::Text;
*/