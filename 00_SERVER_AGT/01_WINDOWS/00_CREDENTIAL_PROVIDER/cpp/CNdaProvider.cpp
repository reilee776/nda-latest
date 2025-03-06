//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// In this sample, we will display one tile that uses each of the nine
// available UI controls.

#include <initguid.h>
#include "CNdaProvider.h"
#include "CNdaCredential.h"
#include "guid.h"

CNdaProvider::CNdaProvider():
    _cRef(1),
    _pCredential(nullptr),/*,
    _pCredProviderUserArray(nullptr)
	*/
	_nowNumAuth (NDACP_AUTH_OS)
{
	_pcpe = NULL;
    DllAddRef();
}

CNdaProvider::~CNdaProvider()
{
    if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
	/*
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }
	*/

    DllRelease();
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CNdaProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    HRESULT hr;

	NDALOG("SetUsageScenario call..");

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider
// into this sample.]
HRESULT CNdaProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
    return E_NOTIMPL;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated.
HRESULT CNdaProvider::Advise(
    _In_ ICredentialProviderEvents * pcpe,
    _In_ UINT_PTR upAdviseContext)
{
	if (_pcpe)
	{
		_pcpe->Release();
	}

	/*
	_pcpe = pcpe;
	_pcpe->AddRef();
	*/
	_pCredProvEvents = pcpe;
	_upAdviseContext = upAdviseContext;

    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CNdaProvider::UnAdvise()
{
	if (_pcpe)
	{
		_pcpe->Release();
		_pcpe = NULL;
	}

	if (_pCredProvEvents)
	{
		_pCredProvEvents->Release();
		_pCredProvEvents = NULL;
	}

    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors.
HRESULT CNdaProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT CNdaProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr;
    *ppcpfd = nullptr;

	NDALOG("GetFieldDescriptorAt call...");

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
		NDALOG("GetFieldDescriptorAt Verify dwIndex is a valid field.");
    }
    else
    {
        hr = E_INVALIDARG;
		NDALOG("GetFieldDescriptorAt hr = E_INVALIDARG ");
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If
// more than one provider specifies a default the last used cred prov gets to pick
// the default. If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call
// GetSerialization on the credential you've specified as the default and will submit
// that credential for authentication without showing any further UI.
HRESULT CNdaProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

	NDALOG("GetCredentialCount call...");

    if (_fRecreateEnumeratedCredentials)
    {
		NDALOG("GetCredentialCount not null _fRecreateEnumeratedCredentials");
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }
	else
	{
		NDALOG("GetCredentialCount is null _fRecreateEnumeratedCredentials");
	}

    *pdwCount = 1;

    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT CNdaProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

	NDALOG("GetCredentialAt call...");
    if ((dwIndex == 0) && ppcpc)
    {
		NDALOG("GetCredentialAt (dwIndex == 0) && ppcpc");
        hr = _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
	}
	else
	{
		NDALOG("GetCredentialAt (dwIndex != 0) && !ppcpc");
	}
    return hr;
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
/*
HRESULT CNdaProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
    if (_pCredProviderUserArray)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}
*/

void CNdaProvider::_CreateEnumeratedCredentials()
{
	NDALOG("_CreateEnumeratedCredentials call...");
    switch (_cpus)
    {
    case CPUS_LOGON:
		{
			_EnumerateCredentials(NULL, NULL);

			break;
		}
    case CPUS_UNLOCK_WORKSTATION:
        {
			PWSTR szUserName = NULL;
			PWSTR szDomainName = NULL;
			DWORD dwLen;

			if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
				WTS_CURRENT_SESSION,
				WTSUserName,
				&szUserName,
				&dwLen)) szUserName = NULL;

			if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
				WTS_CURRENT_SESSION,
				WTSDomainName,
				&szDomainName,
				&dwLen)) szDomainName = NULL;

		NDALOG("_CreateEnumeratedCredentials :: CPUS_LOGON");
            _EnumerateCredentials(szUserName, szDomainName);
            break;
        }
    default:
		NDALOG("_CreateEnumeratedCredentials :: default");
        break;
    }
}

void CNdaProvider::_ReleaseEnumeratedCredentials()
{
    if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
}

HRESULT CNdaProvider::_EnumerateCredentials(
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name
)
{
    HRESULT hr = E_UNEXPECTED;
	NDALOG("_EnumerateCredentials call..");

	CNdaCredential * ppc = new(std::nothrow) CNdaCredential(this);

	if (ppc)
	{
		if (_cpus == CPUS_UNLOCK_WORKSTATION)
		{
			NDALOG("_EnumerateCredentials :: CPUS_UNLOCK_WORKSTATION");
			hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairsUnlock, user_name, domain_name);
		}
		else
		{
			NDALOG("_EnumerateCredentials :: CPUS_LOGON");
			if (_nowNumAuth == NDACP_AUTH_OS)
				hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, user_name, domain_name);
			else if (_nowNumAuth == NDACP_AUTH_HIWARE)
				hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairsHIWAREAuth, user_name, domain_name);
			else if (_nowNumAuth == NDACP_AUTH_HIOTP)
				hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairsHIOTPAuth, user_name, domain_name);
		}
	
	}

	if (SUCCEEDED(hr))
	{
		_pCredential = ppc;
	}
	else
	{
		// Release the pointer to account for the local reference.
		ppc->Release();
	}
	
	NDALOG("_pCredProviderUserArray is nullptr!");

    return hr;
}

void CNdaProvider::ForceRefreshUI()
{
	if (_pCredProvEvents)
	{
		_pCredProvEvents->CredentialsChanged(_upAdviseContext);
	}
}

//void CNdaProvider::OnChange ()

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    CNdaProvider *pProvider = new(std::nothrow) CNdaProvider();
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

