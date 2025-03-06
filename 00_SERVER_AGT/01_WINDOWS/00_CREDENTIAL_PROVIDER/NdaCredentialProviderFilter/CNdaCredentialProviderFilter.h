#pragma once
#include <credentialprovider.h>
#include "dllmain.h"
#include "guid.h"

class CNdaCredentialProviderFilter :
	public ICredentialProviderFilter
{
public:

	//This section contains some COM boilerplate code 

	// IUnknown 
	STDMETHOD_(ULONG, AddRef)()
	{
		return _cRef++;
	}

	STDMETHOD_(ULONG, Release)()
	{
		LONG cRef = _cRef--;
		if (!cRef)
		{
			delete this;
		}
		return cRef;
	}

	STDMETHOD(QueryInterface)(REFIID riid, void** ppv)
	{
		HRESULT hr;
		if (IID_IUnknown == riid || IID_ICredentialProviderFilter == riid)
		{
			*ppv = this;
			reinterpret_cast<IUnknown*>(*ppv)->AddRef();
			hr = S_OK;
		}
		else
		{
			*ppv = NULL;
			hr = E_NOINTERFACE;
		}
		return hr;
	}
	//#pragma warning(disable:4100)

public:
	//Implementation of ICredentialProviderFilter 
	IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		DWORD dwFlags,
		GUID* rgclsidProviders,
		BOOL* rgbAllow,
		DWORD cProviders);

	IFACEMETHODIMP UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn,
		CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut);

	friend HRESULT CNda_CreateInstance(__in REFIID riid, __deref_out void** ppv);


protected:
	CNdaCredentialProviderFilter();
	__override ~CNdaCredentialProviderFilter();

private:
	LONG _cRef;
};

