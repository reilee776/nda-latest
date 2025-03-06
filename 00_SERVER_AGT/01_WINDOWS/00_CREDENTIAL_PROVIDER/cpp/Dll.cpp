//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// Standard dll required functions and class factory implementation.

#include <windows.h>
#include <DbgHelp.h>
#include <tchar.h>
#include <strsafe.h>
#include <unknwn.h>
#include "Dll.h"
#include "helpers.h"

#pragma comment (lib, "dbghelp.lib")

void WriteDump(EXCEPTION_POINTERS* pExceptionInfo)
{
	TCHAR szFilePath[MAX_PATH] = L"C:\\Log\\CredentialProvider.dmp";

	// 덤프 파일 저장 경로 설정
	HANDLE hFile = CreateFile(szFilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		OutputDebugString(L"[ERROR] 덤프 파일을 생성할 수 없음!");
		return;
	}

	// 덤프 정보 작성
	MINIDUMP_EXCEPTION_INFORMATION dumpInfo;
	dumpInfo.ThreadId = GetCurrentThreadId();
	dumpInfo.ExceptionPointers = pExceptionInfo;
	dumpInfo.ClientPointers = TRUE;

	// 덤프 생성
	BOOL bSuccess = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpWithFullMemory, &dumpInfo, NULL, NULL);

	CloseHandle(hFile);

	if (bSuccess)
	{
		OutputDebugString(L"[DEBUG] 덤프 파일 생성 완료!");
	}
	else
	{
		OutputDebugString(L"[ERROR] MiniDumpWriteDump 실패!");
	}
}

LONG WINAPI CustomUnhandledExceptionFilter(EXCEPTION_POINTERS* pExceptionInfo)
{
	OutputDebugString(L"[ERROR] Credential Provider에서 충돌 발생! 덤프 생성 중...");

	// 덤프 파일 생성
	WriteDump(pExceptionInfo);

	return EXCEPTION_EXECUTE_HANDLER;
}

void SetUnhandledExceptionHandler()
{
	SetUnhandledExceptionFilter(CustomUnhandledExceptionFilter);
	OutputDebugString(L"[DEBUG] Unhandled Exception Handler 등록 완료!");
}


static long g_cRef = 0;   // global dll reference count
HINSTANCE g_hinst = NULL; // global dll hinstance

extern HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv);
EXTERN_C GUID CLSID_NDAProvider;

class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : _cRef(1)
    {
    }

    // IUnknown
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CClassFactory, IClassFactory),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
            delete this;
        return cRef;
    }

    // IClassFactory
    IFACEMETHODIMP CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid, __deref_out void **ppv)
    {
        HRESULT hr;
        if (!pUnkOuter)
        {
            hr = CSample_CreateInstance(riid, ppv);
        }
        else
        {
            *ppv = NULL;
            hr = CLASS_E_NOAGGREGATION;
        }
        return hr;
    }

    IFACEMETHODIMP LockServer(__in BOOL bLock)
    {
        if (bLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

private:
    ~CClassFactory()
    {
    }
    long _cRef;
};

HRESULT CClassFactory_CreateInstance(__in REFCLSID rclsid, __in REFIID riid, __deref_out void **ppv)
{
    *ppv = NULL;

    HRESULT hr;

    if (CLSID_NDAProvider == rclsid)
    {
        CClassFactory* pcf = new CClassFactory();
        if (pcf)
        {
            hr = pcf->QueryInterface(riid, ppv);
            pcf->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    return hr;
}

void DllAddRef()
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cRef);
}

STDAPI DllCanUnloadNow()
{
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

STDAPI DllGetClassObject(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

STDAPI_(BOOL) DllMain(__in HINSTANCE hinstDll, __in DWORD dwReason, __in void *)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
		SetUnhandledExceptionHandler();
        DisableThreadLibraryCalls(hinstDll);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    g_hinst = hinstDll;
    return TRUE;
}

