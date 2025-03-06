//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
#ifndef CNDA_PROVIDER_H
#define CNDA_PROVIDER_H

#include "helpers.h"
#include <windows.h>
#include <strsafe.h>
#include <new>
#include <Wtsapi32.h>

#pragma comment(lib, "wtsapi32.lib")

#include "CNdaCredential.h"
class CNdaCredential;
class CNdaProvider : public ICredentialProvider/*,
                        public ICredentialProviderSetUserArray*/
{
  public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CNdaProvider, ICredentialProvider), // IID_ICredentialProvider
            //QITABENT(CNdaProvider, ICredentialProviderSetUserArray), // IID_ICredentialProviderSetUserArray
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

  public:
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(_In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const *pcpcs);

    IFACEMETHODIMP Advise(_In_ ICredentialProviderEvents *pcpe, _In_ UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(_Out_ DWORD *pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,  _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd);

    IFACEMETHODIMP GetCredentialCount(_Out_ DWORD *pdwCount,
                                      _Out_ DWORD *pdwDefault,
                                      _Out_ BOOL *pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
                                   _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc);

	void ForceRefreshUI();
	/*
    IFACEMETHODIMP SetUserArray(_In_ ICredentialProviderUserArray *users);
	*/
    friend HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv);

	DWORD									_nowNumAuth;

  protected:
    CNdaProvider();
    __override ~CNdaProvider();

  private:
    void _ReleaseEnumeratedCredentials();
    void _CreateEnumeratedCredentials();
    HRESULT _EnumerateEmpty();
    HRESULT _EnumerateCredentials(
		__in_opt PWSTR user_name,
		__in_opt PWSTR domain_name
	);
    HRESULT _EnumerateEmptyTileCredential();

	UINT_PTR _upAdviseContext;  // Credential Context ¿˙¿Â

private:
    long                                    _cRef;            // Used for reference counting.
    CNdaCredential							*_pCredential;    // SampleV2Credential
    bool                                    _fRecreateEnumeratedCredentials;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
	ICredentialProviderEvents				*_pcpe;

	ICredentialProviderEvents				* _pCredProvEvents;
	/*
    ICredentialProviderUserArray            *_pCredProviderUserArray;
	*/
	


};

#endif // CNDA_PROVIDER_H