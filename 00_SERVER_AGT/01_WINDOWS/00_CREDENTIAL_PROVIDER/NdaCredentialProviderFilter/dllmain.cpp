// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.

#include <windows.h>
#include <unknwn.h>
#include "dllmain.h"
#include <shlwapi.h>  // QITAB 정의 포함
#include "pch.h"

static long g_cRef = 0;   // global dll reference count
HINSTANCE g_hinst = NULL; // global dll hinstance

extern HRESULT CNda_CreateInstance(__in REFIID riid, __deref_out void** ppv);
EXTERN_C GUID CLSID_NdaFilter;

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
		LONG cRef = InterlockedDecrement(&_cRef);
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
			hr = CNda_CreateInstance(riid, ppv);
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

	if (CLSID_NdaFilter == rclsid)
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

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

	g_hinst = hModule;
    return TRUE;
}

