#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "pch.h"
#include "CNdaCredentialProviderFilter.h"



// Boilerplate code to create our provider.
HRESULT CNda_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
	HRESULT hr;

	CNdaCredentialProviderFilter* pProvider = new CNdaCredentialProviderFilter();

	if (pProvider)
	{
		hr = pProvider->QueryInterface(riid, ppv);
		pProvider->Release();
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	return hr;
}

HRESULT CNdaCredentialProviderFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, GUID* rgclsidProviders, BOOL* rgbAllow, DWORD cProviders)
{
	switch (cpus)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
		for (DWORD i = 0; i < cProviders; i++)
		{
			if (i < dwFlags)
			{
			}
			//if (IsEqualGUID(rgclsidProviders[i], CLSID_PasswordCredentialProvider))
			// Only allow OTP CPs
			if (IsEqualGUID(rgclsidProviders[i], CLSID_NDAPASSWORD)) {
				rgbAllow[i] = TRUE;
			}
			else {
				rgbAllow[i] = FALSE;
			}
		}
		return S_OK;
		break;
	case CPUS_CREDUI:
	case CPUS_CHANGE_PASSWORD:
		return E_NOTIMPL;
	default:
		return E_INVALIDARG;
	}
}

CNdaCredentialProviderFilter::CNdaCredentialProviderFilter() :
	_cRef(1)
{
	DllAddRef();
}

CNdaCredentialProviderFilter::~CNdaCredentialProviderFilter()
{
	DllRelease();
}

HRESULT CNdaCredentialProviderFilter::UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpsIn, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut)
{
	UNREFERENCED_PARAMETER(pcpsIn);
	UNREFERENCED_PARAMETER(pcpcsOut);
	return E_NOTIMPL;
}