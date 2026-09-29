# ulv — Loader Verifier

`ulv.dll` is a loader-verifier module for Windows CE and Windows Phone 7. It
comes from the FullUnlock v4.0 project (© Maxim Menshikov (ultrashot), 2012). It stands in for the
stock `\Windows\mslvmod.dll`. The OS loader calls that component to authenticate
and authorize every module before it runs. `ulv` forwards to the real verifier
but overrides its verdicts, so the loader allows unsigned and developer code.

The project builds from the folder that was named `newlv`. The project, the
module, and its import library are all called `ulv` (`ulv.dll` and `ulv.lib`).

This is legacy research and homebrew code for a platform that reached end of
life long ago.

## How it works

The loader looks up the `LVMod*` entry points (see `ulv.def`) in this DLL. On
first use, `ulv` loads the stock module with
`LoadKernelLibrary(L"\\Windows\\mslvmod.dll")` and resolves the original
`LVMod*` functions (`ulv.cpp`). Each export calls through to the original and
then adjusts the result:

- `LVModAuthorize` always reports `LV_AUTHORIZATION_EXECUTE`.
- `LVModRouting` routes the module to the system account when the stock router
  declines.
- `LVModGetDeveloperUnlockState` and `LVModSetDeveloperUnlockState` report and
  persist an unlocked developer state.
- The other exports are thin pass-throughs to the stock verifier.

`crypto.cpp` verifies ECDSA-P256 signatures over BCrypt. It uses the Kenny Kerr
CNG wrappers in `KerrSecurityCryptography.h`. `AccountManager.cpp` and `adb7.cpp`
wrap the account-database (ADB) API used for routing.

## Layout

```
ulv/
├── ulv.vcproj          Visual Studio 2008 project (WM6 Pro ARMv4I)
├── .clang-format       Formatting rules for src/
├── src/                Project sources
│   ├── ulv.cpp             LVMod* exports and stock-module proxy
│   ├── crypto.cpp          ECDSA-P256 signature verification (BCrypt)
│   ├── AccountManager.cpp/.h, adb7.cpp   ADB account helpers
│   ├── Protection.cpp      Anti-tamper stub
│   ├── Precompiled.cpp/.h   ATL/BCrypt helper header used by crypto.cpp
│   ├── stdafx.h/.cpp        Precompiled-header stub
│   ├── debug.h, resource.h, resources.rc
│   └── ulv.def             Exported LVMod* entry points
└── sdk/                Vendored SDK / third-party headers + import libraries
    ├── lvmod.h, loaderverifier.h, mloaderverifier.h, developerunlock.h, acctid.h
    ├── adb7.h              ADB (account database) API
    ├── bcrypt.h + bcrypt.lib, KerrSecurityCryptography.h
    └── coredll7.lib
```

## Building

You need Visual Studio 2008 with the Windows Mobile 6 Professional SDK (ARMV4I)
installed. To build the module:

1. Open `ulv.vcproj`.
2. Build the Release configuration.

The output is `ulv.dll`. The include and library paths point at `src/` and
`sdk/`. The project is self-contained and does not need an enclosing solution.
`crypto.cpp` links `bcrypt.lib` with `#pragma comment(lib, ...)`. The linker
resolves it from `sdk/`.
