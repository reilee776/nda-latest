//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CNdaCredential.h"
#include "guid.h"

CNdaCredential::CNdaCredential(CNdaProvider *privider):
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0)
{
    DllAddRef();

	_privider = privider;
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CNdaCredential::~CNdaCredential()
{
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}

INT CNdaCredential::GetOsAuthResult(wchar_t *szRealName, wchar_t *szDomainName, wchar_t *szPassword)
{
	INT nResult = 0;
	HANDLE hToken = NULL;

	if (LogonUserW(szRealName, szDomainName, szPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
	{
		nResult = 1;
		CloseHandle(hToken);
	}
	else
	{
		DWORD dwError = GetLastError();
		switch (dwError)
		{
		case ERROR_PASSWORD_MUST_CHANGE:
			nResult = -1;  // 비밀번호 변경 필요
			break;

		case ERROR_ACCOUNT_LOCKED_OUT:
			nResult = -2;  // 계정 잠김
			break;

		case ERROR_LOGON_FAILURE:
			nResult = -3;
			break;
		default:
			nResult = 0;
			break;
		}
	}

	return nResult;
}

BOOL CNdaCredential::SetAuthType(int nType)
{
	BOOL bRet = TRUE;

	if (_privider) {
		_privider->_nowNumAuth = nType;
	}
	else
	{
		bRet = FALSE;
	}

	return bRet;
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CNdaCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                  /*    _In_ ICredentialProviderUser *pcpUser,*/
										__in_opt PWSTR user_name,
										__in_opt PWSTR domain_name
)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

	NDALOG("Initialize call...");

	if (user_name)
		_user_name = user_name;

	if (domain_name)
		_domain_name = domain_name;
	
	NDALOG("Initialize call...");

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Sample Credential", &_rgFieldStrings[SFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"HIWARE Credential Provider", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_HIAUTH_ACCT]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_HIAUTH_PASSWD]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_HIOTP_PASSWD]);
	}

	if (SUCCEEDED(hr))
	{
		if (_cpus == CPUS_UNLOCK_WORKSTATION && _user_name)
		{
			hr = SHStrDupW(_user_name, &_rgFieldStrings[SFI_LABEL]);
			hr = SHStrDupW(_user_name, &_rgFieldStrings[SFI_LARGE_TEXT]);
			hr = SHStrDupW(_user_name, &_rgFieldStrings[SFI_ACCOUNT_EDIT]);
		}
		else
			hr = SHStrDupW(L"", &_rgFieldStrings[SFI_ACCOUNT_EDIT]);
	}

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CNdaCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT CNdaCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CNdaCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
	//_privider->ForceRefreshUI();
    *pbAutoLogon = FALSE;
	/*
	if (_cpus == CPUS_UNLOCK_WORKSTATION)
	{
		WCHAR loggedUserName[UNLEN + 1] = { 0 };
		DWORD size = ARRAYSIZE(loggedUserName);

		if (GetLoggedOnUserName(loggedUserName, size))
		{
			if (_pCredProvCredentialEvents)
			{
				_pCredProvCredentialEvents->SetFieldString(this, SFI_LARGE_TEXT, loggedUserName);
				OutputDebugString(L"[DEBUG] SFI_LARGE_TEXT set success!");
				char utf8UserName[UNLEN * 2 + 1] = { 0 };
				WideCharToMultiByte(CP_UTF8, 0, loggedUserName, -1, utf8UserName, sizeof(utf8UserName), NULL, NULL);

				NDALOG("[DEBUG] SFI_LARGE_TEXT Setting user name!,(%s)", utf8UserName);
			}
		}
		else
		{
			NDALOG("[ERROR] GetLoggedOnUserName() FAIL! Empty Data");
		}
	}
	*/

    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CNdaCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CNdaCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CNdaCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CNdaCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;
	NDALOG("GetBitmapValue CALL...");
    if ((SFI_TILEIMAGE == dwFieldID) )
    {
		NDALOG("GetBitmapValue :: (SFI_TILEIMAGE == dwFieldID) && phbmp ");
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TITLE_USER));
        if (hbmp != nullptr)
        {
			NDALOG("GetBitmapValue :: BITMAP CHANGE!!");
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
			NDALOG("GetBitmapValue :: BITMAP CHANGE FAIL!!");
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
		NDALOG("GetBitmapValue :: DEFAULT FAIL!!!");
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CNdaCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        *pdwAdjacentTo = SFI_PASSWORD;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CNdaCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CNdaCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(pbChecked);

    HRESULT hr = S_OK;
    *ppwszLabel = nullptr;
	/*
    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _fChecked;
        hr = SHStrDupW(_rgFieldStrings[SFI_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }
	*/
    return hr;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CNdaCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CNdaCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CNdaCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CNdaCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user clicks a command link.
HRESULT CNdaCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;

    //CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        //HWND hwndOwner = nullptr;
        switch (dwFieldID)
        {
			/*
        case SFI_LAUNCHWINDOW_LINK:
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }

            // Pop a messagebox indicating the click.
            ::MessageBox(hwndOwner, L"Command link clicked", L"Click!", 0);
            break;
        case SFI_HIDECONTROLS_LINK:
            _pCredProvCredentialEvents->BeginFieldUpdates();
            cpfsShow = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_FULLNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_DISPLAYNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_LOGONSTATUS_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_CHECKBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_EDIT_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_COMBOBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_HIDECONTROLS_LINK, _fShowControls? L"Hide additional controls" : L"Show additional controls");
            _pCredProvCredentialEvents->EndFieldUpdates();
            _fShowControls = !_fShowControls;
            break;
			*/
        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT CNdaCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

	INIT_ZERO_WCHAR(username, 64);
	INIT_ZERO_WCHAR(domain, 64);

	BOOL bGetCompName = FALSE;
	WCHAR wszComputerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD dwSize = ARRAYSIZE(wszComputerName);

	WCHAR wsz[64];
	//DWORD cch = ARRAYSIZE(wsz);

	NDALOG("GetSerialization Call...");

	_SeparateUserAndDomainName(_rgFieldStrings[SFI_ACCOUNT_EDIT], username, sizeof(username), domain, sizeof(domain));

	// Set domain name:
	// [안전성 추가] 기존 메모리 해제 전 NULL 체크
	if (_domain_name)
	{
		if (IsBadReadPtr(_domain_name, sizeof(wchar_t)))
		{
			NDALOG("[ERROR] _domain_name이 올바른 메모리를 가리키지 않음! 초기화 수행");
			_domain_name = NULL;
		}
		else
		{
			free(_domain_name);
			_domain_name = NULL;
		}
	}

	if (domain && domain[0])  // DOMAIN\USERNAME 형태
	{
		_domain_name = _wcsdup(domain);
	}
	else
	{
		// 컴퓨터 이름 가져오기 시도
		bGetCompName = GetComputerNameW(wszComputerName, &dwSize);
		if (bGetCompName)
		{
			_domain_name = _wcsdup(wszComputerName);
			NDALOG("[DEBUG] 기본 도메인으로 컴퓨터 이름 사용: %S", _domain_name);
		}
		else
		{
			// GetComputerNameW() 실패 시 기본 도메인 설정 (로컬 사용자 로그인 대비)
			_domain_name = _wcsdup(L"localhost");
			NDALOG("[WARNING] GetComputerNameW 실패! 기본 도메인으로 'localhost' 설정");
		}
	}
	// [안전성 추가] _domain_name이 NULL이면 기본값 설정
	if (!_domain_name)
	{
		NDALOG("[ERROR] _domain_name이 NULL임! 기본 도메인으로 'localhost' 설정");
		_domain_name = _wcsdup(L"localhost");
	}

	if ((_domain_name && _domain_name[0]) || bGetCompName)
	{
		PWSTR pwzProtectedPassword;

		hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);

		if (SUCCEEDED(hr))
		{
			if (_privider->_nowNumAuth == NDACP_AUTH_OS)
			{
				NDALOG("GetOsAuthResult befor");
				if (GetOsAuthResult(username, _domain_name, pwzProtectedPassword) == 1)
				{
					NDALOG("GetOsAuthResult TRUE");
					SetAuthType(NDACP_AUTH_HIWARE);
					
					Process_HIWAREAUTH_Field();

					//_privider->ForceRefreshUI();

					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
					return S_FALSE;
				}
				else
				{
					_privider->ForceRefreshUI();
					SetAuthType(NDACP_AUTH_OS);
				}
			}

			if (_privider->_nowNumAuth == NDACP_AUTH_HIWARE)
			{
				SetAuthType(NDACP_AUTH_HIWARE + 1);

				Process_HIOTP_Field();

				//_privider->ForceRefreshUI();

				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				return S_FALSE;
			}

			if (_privider->_nowNumAuth == NDACP_AUTH_HIOTP)
			{
				
			}

			SetAuthType(NDACP_AUTH_OS);

			KERB_INTERACTIVE_UNLOCK_LOGON kiul;

			// Initialize kiul with weak references to our credential.
			hr = KerbInteractiveUnlockLogonInit(wsz, username, pwzProtectedPassword, _cpus, &kiul);
			if (SUCCEEDED(hr))
			{
				// We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
				// KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
				// as necessary.
				hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
				if (SUCCEEDED(hr))
				{
					ULONG ulAuthPackage;
					hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
					if (SUCCEEDED(hr))
					{
						pcpcs->ulAuthenticationPackage = ulAuthPackage;
						pcpcs->clsidCredentialProvider = CLSID_NDAProvider;

						// At this point the credential has created the serialized credential used for logon
						// By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
						// that we have all the information we need and it should attempt to submit the 
						// serialized credential.
						*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
					}
				}
			}
			CoTaskMemFree(pwzProtectedPassword);
		}
	}
	else
	{
		DWORD dwErr = GetLastError();
		hr = HRESULT_FROM_WIN32(dwErr);
	}
	
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CNdaCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
/*
HRESULT CNdaCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}
*/

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CNdaCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}

void CNdaCredential::_SeparateUserAndDomainName(
	__in wchar_t *domain_slash_username,
	__out wchar_t *username,
	__in int sizeUsername,
	__out_opt wchar_t *domain,
	__in_opt int sizeDomain
)
{
	int pos;
	for (pos = 0; domain_slash_username[pos] != L'\\' && domain_slash_username[pos] != NULL; pos++);

	if (domain_slash_username[pos] != NULL)
	{
		int i;
		for (i = 0; i < pos && i < sizeDomain; i++)
			domain[i] = domain_slash_username[i];
		domain[i] = L'\0';

		for (i = 0; domain_slash_username[pos + i + 1] != NULL && i < sizeUsername; i++)
			username[i] = domain_slash_username[pos + i + 1];
		username[i] = L'\0';
	}
	else
	{
		int i;
		for (i = 0; i < pos && i < sizeUsername; i++)
			username[i] = domain_slash_username[i];
		username[i] = L'\0';
	}
}

void CNdaCredential::Process_HIWAREAUTH_Field()
{
	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->BeginFieldUpdates();

		_pCredProvCredentialEvents->SetFieldState(this, SFI_ACCOUNT_EDIT, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_HIDDEN);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_HIAUTH_ACCT, CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_HIAUTH_PASSWD, CPFS_DISPLAY_IN_SELECTED_TILE);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_HIOTP_PASSWD, CPFS_HIDDEN);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);

		HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TITLE_HIWARE));
		if (hbmp != nullptr)
		{
			NDALOG("Process_HIOTP_Field LoadBitmap SUCCESS");
			_pCredProvCredentialEvents->SetFieldBitmap(this, SFI_TILEIMAGE, hbmp);

		}
		else
		{
			NDALOG("Process_HIOTP_Field LoadBitmap fail!");
		}

		_pCredProvCredentialEvents->EndFieldUpdates();

		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_HIAUTH_ACCT, CPFIS_FOCUSED);
		
	}
}

void CNdaCredential::Process_HIOTP_Field()
{
	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->BeginFieldUpdates();

		_pCredProvCredentialEvents->SetFieldState(this, SFI_ACCOUNT_EDIT, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_HIDDEN);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_HIAUTH_ACCT, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_HIAUTH_PASSWD, CPFS_HIDDEN);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_HIOTP_PASSWD, CPFS_DISPLAY_IN_SELECTED_TILE);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_SUBMIT_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);

		HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TITLE_HIOTP));
		if (hbmp != nullptr)
		{
			NDALOG("Process_HIOTP_Field LoadBitmap SUCCESS");
			_pCredProvCredentialEvents->SetFieldBitmap(this, SFI_TILEIMAGE, hbmp);

		}
		else
		{
			NDALOG("Process_HIOTP_Field LoadBitmap fail!");
		}

		_pCredProvCredentialEvents->EndFieldUpdates();

		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_HIOTP_PASSWD, CPFIS_FOCUSED);
	}
}