//+--------------------------------------------------------------------------
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved
// AGPLv3 2017 Martino Dell'Ambrogio
//
// File:        exit.cpp
//
// Contents:    CCertExitPlus implementation
//
//---------------------------------------------------------------------------

#include "pch.cpp"
#pragma hdrstop

#include <assert.h>
#include <ppl.h>
#include "celib.h"

#pragma warning(push)
#pragma warning(disable : 4996) // to disable SDK warning from using deprecated APIs with ATL 7.0 and greater
#include "exit.h"
#include "module.h"
#pragma warning(pop)

char g_tmpBuffer[16384];
BOOL fDebug = DBG_CERTSRV;
TCHAR g_WriteCert2FilePath[MINSTRSIZE];
TCHAR g_StartProcess[BUFSIZE * 2];

#ifndef DBG_CERTSRV
#error -- DBG_CERTSRV not defined!
#endif

#define ceEXITEVENTS \
    (EXITEVENT_CERTDENIED | \
    EXITEVENT_CERTISSUED | \
    EXITEVENT_CERTPENDING | \
    EXITEVENT_CERTRETRIEVEPENDING | \
    EXITEVENT_CERTREVOKED | \
    EXITEVENT_CRLISSUED | \
    EXITEVENT_SHUTDOWN | \
    EXITEVENT_CERTIMPORTED)

typedef struct ProcThrData {
	DWORD FileSize;
	TCHAR ProgPath[BUFSIZE * 2];
	TCHAR FileName[MINSTRSIZE];
	BYTE *pRawCert;
} PROCTHRDATA;

extern HINSTANCE g_hInstance;
extern LPWSTR g_pwszUnavailable;

HRESULT GetServerCallbackInterface(
                           OUT ICertServerExit** ppServer,
                           IN LONG Context)
{
    HRESULT hr;

    if (NULL == ppServer)
    {
        hr = E_POINTER;
        _JumpError(hr, error, "Exit:NULL pointer");
    }

    hr = CoCreateInstance(
        CLSID_CCertServerExit,
        NULL,               // pUnkOuter
        CLSCTX_INPROC_SERVER,
        IID_ICertServerExit,
        (VOID **) ppServer);
    _JumpIfError(hr, error, "Exit:CoCreateInstance");

    if (*ppServer == NULL)
    {
        hr = E_UNEXPECTED;
        _JumpError(hr, error, "Exit:NULL *ppServer");
    }

    // only set context if nonzero
    if (0 != Context)
    {
        hr = (*ppServer)->SetContext(Context);
        _JumpIfError(hr, error, "Exit: SetContext");
    }

error:
    return(hr);
}


//+--------------------------------------------------------------------------
// CCertExitPlus::~CCertExitPlus -- destructor
//
// free memory associated with this instance
//+--------------------------------------------------------------------------

CCertExitPlus::~CCertExitPlus()
{
    SysFreeString(m_strCAName);
    if (NULL != m_pwszRegStorageLoc)
    {
        LocalFree(m_pwszRegStorageLoc);
    }
    if (NULL != m_hExitKey)
    {
        RegCloseKey(m_hExitKey);
    }
    SysFreeString(m_strDescription);
}


//+--------------------------------------------------------------------------
// CCertExitPlus::Initialize -- initialize for a CA & return interesting Event Mask
//
// Returns S_OK on success.
//+--------------------------------------------------------------------------

STDMETHODIMP
CCertExitPlus::Initialize(
                      /* [in] */ BSTR const strConfig,
                      /* [retval][out] */ LONG __RPC_FAR *pEventMask)
{
    HRESULT hr = S_OK;
    DWORD cbbuf;
    DWORD dwType;
    ENUM_CATYPES CAType;
    ICertServerExit *pServer = NULL;
    VARIANT varValue;
    WCHAR sz[MAX_PATH];
    size_t len;

	LOG(true, "Debug: ADCSExitPlus-Initialize...\n");
    VariantInit(&varValue);

    assert(wcslen(wsz_PLUS_DESCRIPTION) < ARRAYSIZE(sz));
    StringCchCopy(sz, ARRAYSIZE(sz), wsz_PLUS_DESCRIPTION);
    sz[ARRAYSIZE(sz) - 1] = L'\0';

    m_strDescription = SysAllocString(sz);
    if (IsNullBStr(m_strDescription))
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "Exit:SysAllocString");
    }

    m_strCAName = SysAllocString(strConfig);
    if (IsNullBStr(m_strCAName))
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "Exit:SysAllocString");
    }

    *pEventMask = ceEXITEVENTS;
    DBGPRINT((fDebug, "Exit:Initialize(%ws) ==> %x\nCompiled at " __DATE__ ", " __TIME__ ".\n", m_strCAName, *pEventMask));

    // get server callbacks
    hr = GetServerCallbackInterface(&pServer, 0);
    _JumpIfError(hr, error, "Exit:GetServerCallbackInterface");

    // get storage location
    hr = exitGetProperty(
        pServer,
        FALSE,	// fRequest
        wszPROPMODULEREGLOC,
        PROPTYPE_STRING,
        &varValue);
    _JumpIfErrorStr(hr, error, "Exit:exitGetProperty", wszPROPMODULEREGLOC);

    len = wcslen(varValue.bstrVal) + 1;
    m_pwszRegStorageLoc = (LPWSTR)LocalAlloc(LMEM_FIXED, len *sizeof(WCHAR));
    if (NULL == m_pwszRegStorageLoc)
    {
		LOG(true, "Error: GetProperty MODULEREGLOC Failed with Out Of Memory !\n");
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "Exit:LocalAlloc");
    }
    StringCchCopy(m_pwszRegStorageLoc, len, varValue.bstrVal);
    VariantClear(&varValue);

	WCS2CHAR(m_pwszRegStorageLoc);
	LOG(true, "Debug: REGKey: %s.\n", g_tmpBuffer);

    // get CA type
    hr = exitGetProperty(
        pServer,
        FALSE,	// fRequest
        wszPROPCATYPE,
        PROPTYPE_LONG,
        &varValue);
	if (hr != S_OK) {
		LOG(true, "Error: GetProperty CAType Failed.\n");
		_JumpIfErrorStr(hr, error, "Exit:exitGetProperty", wszPROPCATYPE);
	}

    CAType = (ENUM_CATYPES) varValue.lVal;
    VariantClear(&varValue);

    hr = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        m_pwszRegStorageLoc,
        0,              // dwReserved
        KEY_ENUMERATE_SUB_KEYS | KEY_EXECUTE | KEY_QUERY_VALUE,
        &m_hExitKey);
    if (S_OK != hr)
    {
		LOG(true, "Error: RegOpenKey Failed.\n");
        if ((HRESULT) ERROR_FILE_NOT_FOUND == hr)
        {
            hr = S_OK;
            goto error;
        }
        _JumpError(hr, error, "Exit:RegOpenKeyEx");
    }

    hr = exitGetProperty(
        pServer,
        FALSE,	// fRequest
        wszPROPCERTCOUNT,
        PROPTYPE_LONG,
        &varValue);
	if (hr != S_OK) {
		LOG(true, "Error: GetProperty CERTCOUNT Failed.\n");
		_JumpIfErrorStr(hr, error, "Exit:exitGetProperty", wszPROPCERTCOUNT);
	}

    m_cCACert = varValue.lVal;

    cbbuf = sizeof(m_dwExitPublishFlags);
    hr = RegQueryValueEx(
        m_hExitKey,
        wszREGCERTPUBLISHFLAGS,
        NULL,           // lpdwReserved
        &dwType,
        (BYTE *) &m_dwExitPublishFlags,
        &cbbuf);
    if (S_OK != hr)
    {
		LOG(true, "Error: RegQuery REGCERTPUBLISHFLAGS Failed.\n");
        m_dwExitPublishFlags = 0;
	}

	//Get Configparams from Registry for: WriteCert2FilePath, StartProcess
	cbbuf = sizeof(g_WriteCert2FilePath);
	hr = RegQueryValueEx(
		m_hExitKey,
		TEXT("WriteCert2FilePath"),
		NULL,           // lpdwReserved
		&dwType,
		(BYTE*)g_WriteCert2FilePath,
		&cbbuf);
	if (S_OK != hr)
	{
		LOG(true, "Error: RegQuery WriteCert2FilePath Failed.\n");
		g_WriteCert2FilePath[0] = '\0';
		g_WriteCert2FilePath[1] = '\0';
	}
	else {
		if (g_WriteCert2FilePath[_tcslen(g_WriteCert2FilePath) - 1] != '\\')
			StringCbPrintf(g_WriteCert2FilePath, sizeof(g_WriteCert2FilePath), TEXT("%s\\"), g_WriteCert2FilePath);
	}
	cbbuf = sizeof(g_StartProcess);
	hr = RegQueryValueEx(
		m_hExitKey,
		TEXT("StartProcess"),
		NULL,           // lpdwReserved
		&dwType,
		(BYTE*)g_StartProcess,
		&cbbuf);
	if (S_OK != hr)
	{
		LOG(true, "Error: RegQuery StartProcess Failed.\n");
		g_StartProcess[0] = '\0';
		g_StartProcess[1] = '\0';
	}

	WCS2CHAR(g_WriteCert2FilePath);
	LOG(true, "Debug: REGKey-WriteCert2FilePath: %s.\n", g_tmpBuffer);
	WCS2CHAR(g_StartProcess);
	LOG(true, "Debug: REGKey-StartProcess: %s.\n", g_tmpBuffer);

    hr = S_OK;

error:
    VariantClear(&varValue);
    if (NULL != pServer)
    {
        pServer->Release();
    }
    return(ceHError(hr));
}


//+--------------------------------------------------------------------------
// CCertExitPlus::_ExpandEnvironmentVariables -- Expand environment variables
//
//+--------------------------------------------------------------------------

HRESULT
CCertExitPlus::_ExpandEnvironmentVariables(
                                       __in LPCWSTR pwszIn,
                                       __out_ecount(cwcOut) LPWSTR pwszOut,
                                       IN DWORD cwcOut)
{
    HRESULT hr = HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
    WCHAR awcVar[MAX_PATH];
    LPCWSTR pwszSrc;
    WCHAR *pwszDst;
    WCHAR *pwszVar;
    DWORD cwc;

    pwszSrc = pwszIn;
    pwszDst = pwszOut;
    WCHAR* const pwszDstEnd = &pwszOut[cwcOut] ;

    while (L'\0' != (*pwszDst = *pwszSrc++))
    {
        if ('%' == *pwszDst)
        {
            *pwszDst = L'\0';
            pwszVar = awcVar;

            while (L'\0' != *pwszSrc)
            {
                if ('%' == *pwszSrc)
                {
                    pwszSrc++;
                    break;
                }
                *pwszVar++ = *pwszSrc++;
                if (pwszVar >= &awcVar[sizeof(awcVar)/sizeof(awcVar[0]) - 1])
                {
                    _JumpError(hr, error, "Exit:overflow 1");
                }
            }
            *pwszVar = L'\0';
            cwc = GetEnvironmentVariable(awcVar, pwszDst, SAFE_SUBTRACT_POINTERS(pwszDstEnd, pwszDst));
            if (0 == cwc)
            {
                hr = ceHLastError();
                _JumpError(hr, error, "Exit:GetEnvironmentVariable");
            }
            if ((DWORD) (pwszDstEnd - pwszDst) <= cwc)
            {
                _JumpError(hr, error, "Exit:overflow 2");
            }
            pwszDst += cwc;
        }
        else
        {
            pwszDst++;
        }
        if (pwszDst >= pwszDstEnd)
        {
            _JumpError(hr, error, "Exit:overflow 3");
        }
    }
    hr = S_OK;

error:
    return(hr);
}

inline void WCS2CHAR(TCHAR *strValue) {
	if (sizeof(TCHAR) > 1) {
		wcstombs(g_tmpBuffer, strValue, 16384);
	}
	else
		memcpy_s(g_tmpBuffer, 16384, strValue, strlen((char*)strValue));
}

DWORD WINAPI ProcessThread(void *lpParam)
{
	//HANDLE hStdout;
	PROCTHRDATA *pParams;
	TCHAR cmdLine[BUFSIZE*2];
	HRESULT hr;
	DWORD cbWritten;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	//LOG(true, "DEBUG: ProcessThread is started.\n");

	// Cast the parameter to the correct data type.
	// The pointer is known to be valid because 
	// it was checked for NULL before the thread was created.
	pParams = (PROCTHRDATA*)lpParam;

	if (pParams->FileName != NULL) {
		// open file & write binary cert out.
		hFile = CreateFile(
			pParams->FileName,
			GENERIC_WRITE,
			0,			// dwShareMode
			NULL,		// lpSecurityAttributes
			CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL,
			NULL);		// hTemplateFile
		if (INVALID_HANDLE_VALUE == hFile)
		{
			WCS2CHAR(pParams->FileName);
			LOG(true, "Error: Create file for Cert: %s FAILED !\n", g_tmpBuffer);
			hr = ceHLastError();
			_JumpErrorStr(hr, error, "Exit:CreateFile", pParams->FileName);
		}
		if (!WriteFile(hFile, pParams->pRawCert, pParams->FileSize, &cbWritten, NULL))
		{
			WCS2CHAR(pParams->FileName);
			LOG(true, "Error: Write to file for Cert: %s FAILED !\n", g_tmpBuffer);
			hr = ceHLastError();
			_JumpErrorStr(hr, error, "Exit:WriteFile", pParams->FileName);
		}
		CloseHandle(hFile);
		hFile = NULL;

		if (cbWritten != pParams->FileSize)
		{
			hr = STG_E_WRITEFAULT;
			DBGPRINT((
				fDebug,
				"Exit:WriteFile(%ws): attempted %x, actual %x bytes: %x\n",
				pParams->FileName,
				pParams->FileSize,
				cbWritten,
				hr));
			WCS2CHAR(pParams->FileName);
			LOG(true, "Error: Write to file for Cert: %s WRITEFAULT !\n", g_tmpBuffer);
			goto error;
		}
	}

	if (pParams->ProgPath) {
		StringCbPrintf(cmdLine, BUFSIZE*2, TEXT("%s %s"), pParams->ProgPath, pParams->FileName);
		CreateChildProcess(TRUE, cmdLine);
	}

error:

	//Release Param-Mem
	if (pParams->pRawCert != NULL)
		concurrency::Free(pParams->pRawCert);
	HeapFree(GetProcessHeap(), 0, pParams);
	return 0;
}

// Create a child process that uses the previously created pipes for STDIN and STDOUT.
BOOL CreateChildProcess(BOOL bWait4Proc, TCHAR *szCmdline)
{
	////powershell.exe -command \"& {C:\\test\\t.ps1}\""
	////TEXT("%s -command c:\\pki\\NewCertAction.ps1");
	//TCHAR szCmdline[] = TEXT("powershell.exe -file c:\\pki\\NewCertAction.ps1");
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure. 
	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	/*
	siStartInfo.hStdError = g_hChildStd_OUT_Wr;
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
	*/

	// Create the child process. 
	bSuccess = CreateProcess(NULL,  // _T("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
		szCmdline,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		FALSE,          // handles are not inherited. Set to  TRUE  hStdError, hStdOutput, hStdInput are passed
		0,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&siStartInfo,  // STARTUPINFO pointer 
		&piProcInfo);  // receives PROCESS_INFORMATION 

	 // If an error occurs, exit the application. 
	if (!bSuccess) {
		//ErrorExit(TEXT("CreateProcess"));
	}
	else
	{
		if (bWait4Proc) {
			// Wait until child process exits.
			WaitForSingleObject(piProcInfo.hProcess, INFINITE);
		}
		// Close handles to the child process and its primary thread.
		// Some applications might keep these handles to monitor the status
		// of the child process, for example. 
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
	}
	return(bSuccess);
}

// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data.
void WriteToPipe(HANDLE hInputFile, HANDLE hChildStd_IN_Wr)
{
	DWORD dwRead, dwWritten;
	CHAR chBuf[BUFSIZE];
	BOOL bSuccess = FALSE;

	for (;;)
	{
		bSuccess = ReadFile(hInputFile, chBuf, BUFSIZE, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;

		bSuccess = WriteFile(hChildStd_IN_Wr, chBuf, dwRead, &dwWritten, NULL);
		if (!bSuccess) break;
	}

	// Close the pipe handle so the child process stops reading. 
	if (!CloseHandle(hChildStd_IN_Wr)) {
		//ErrorExit(TEXT("StdInWr CloseHandle"));
	}
}

// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data.
void ReadFromPipe(HANDLE hChildStd_OUT_Rd)
{
	DWORD dwRead, dwWritten;
	CHAR chBuf[BUFSIZE];
	BOOL bSuccess = FALSE;
	HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

	for (;;)
	{
		bSuccess = ReadFile(hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;

		bSuccess = WriteFile(hParentStdOut, chBuf, dwRead, &dwWritten, NULL);
		if (!bSuccess) break;
	}
}

HRESULT exitGetRequestAttribute(
                        IN ICertServerExit *pServer,
                        IN WCHAR const *pwszAttributeName,
                        OUT BSTR *pstrOut)
{
    HRESULT hr;
    BSTR strName = NULL;

    *pstrOut = NULL;
    strName = SysAllocString(pwszAttributeName);
    if (IsNullBStr(strName))
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "Exit:SysAllocString");
    }
    hr = pServer->GetRequestAttribute(strName, pstrOut);
    _JumpIfErrorStr2(
        hr,
        error,
        "Exit:GetRequestAttribute",
        pwszAttributeName,
        CERTSRV_E_PROPERTY_EMPTY);

error:
    SysFreeString(strName);
    return(hr);
}


//+--------------------------------------------------------------------------
// CCertExitPlus::_WriteCertToFile -- write binary certificate to a file
//
//+--------------------------------------------------------------------------
HRESULT CCertExitPlus::_WriteCertToFile(
                            IN ICertServerExit *pServer,
                            IN BYTE const *pbCert,
                            IN DWORD cbCert)
{
    HRESULT hr;
    BSTR strCertFile = NULL;
    TCHAR wszFile[cwcDWORDSPRINTF+5]; //format "requestid.cer"
    VARIANT varRequestID;
	DWORD dwThreadId = 0;
	PROCTHRDATA *pThrData = NULL;

	//LOG(true, "DEBUG: _WriteCertToFile - 1.\n");

    VariantInit(&varRequestID);

    /*
	hr = exitGetRequestAttribute(pServer, wszPROPEXITCERTFILE, &strCertFile);
    if (S_OK != hr)
    {
        DBGPRINT((
            fDebug,
            "Exit:exitGetRequestAttribute(%ws): %x%hs\n",
            wszPROPEXITCERTFILE,
            hr,
            CERTSRV_E_PROPERTY_EMPTY == hr? " EMPTY VALUE" : ""));
        if (CERTSRV_E_PROPERTY_EMPTY == hr)
        {
            hr = S_OK;
        }
		LOG(true, "Debug: _WriteFile PROPEXITCERTFILE  FAILED !\n");
        //goto error;
    }
	*/

    // build file name as "requestid.cer"
    hr = exitGetProperty(
        pServer,
        TRUE,  // fRequest,
        wszPROPREQUESTREQUESTID,
        PROPTYPE_LONG,
        &varRequestID);
	if (hr != S_OK) {
		LOG(true, "Error: _WriteFile Get REQUESTID FAILED !\n");
		_JumpIfErrorStr(hr, error, "Exit:exitGetProperty", wszPROPREQUESTREQUESTID);
	}
    StringCbPrintf(wszFile, sizeof(wszFile), L"%d.cer", V_I4(&varRequestID));

	//WCS2CHAR(wszFile);
	//LOG(true, "DEBUG: _WriteCertToFile - 2 %s.\n", g_tmpBuffer);

    /* hr = _ExpandEnvironmentVariables(
        L"%SystemRoot%\\System32\\" wszCERTENROLLSHAREPATH L"\\",
        wszDir,
        ARRAYSIZE(wszDir));
	_JumpIfError(hr, error, "_ExpandEnvironmentVariables"); */
	//by Erwin & Matthias:
	pThrData = (PROCTHRDATA*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PROCTHRDATA));
	if (pThrData == NULL) {
		LOG(true, "Error: CreateThread for Cert-Operations failed with OUT-OF-MEMORY !\n");
		_JumpError(hr, error, "Exit:Start Process failed. OUT-OF-MEMORY !");
	}

	if (g_WriteCert2FilePath != NULL) {
		//LOG(true, "DEBUG: Write2File init Filepath.\n");
		StringCbPrintf(pThrData->FileName, MINSTRSIZE, TEXT("%s%s"), g_WriteCert2FilePath, wszFile);

		//WCS2CHAR(pThrData->FileName);
		//LOG(true, "DEBUG: Write2File:%s.\n", g_tmpBuffer);
	}

	pThrData->FileSize = cbCert;
	pThrData->pRawCert = (BYTE*)concurrency::Alloc(cbCert);
	if (pThrData->pRawCert == NULL) {
		LOG(true, "Error: CreateThread for Cert-Operations failed with OUT-OF-MEMORY !\n");
		HeapFree(GetProcessHeap(), 0, pThrData);
		_JumpError(1, error, "Exit:Start Process failed. OUT-OF-MEMORY !");
	}
	memcpy_s(pThrData->pRawCert, cbCert, pbCert, cbCert);

	if (g_StartProcess != NULL) {
		StringCbPrintf(pThrData->ProgPath, BUFSIZE*2, g_StartProcess);

		//WCS2CHAR(pThrData->ProgPath);
		//LOG(true, "DEBUG: Write2File:%s.\n", g_tmpBuffer);
	}

	if ((g_WriteCert2FilePath != NULL) || (g_StartProcess != NULL)) {
		HANDLE hThread = CreateThread(
			NULL,                   // default security attributes
			0,                      // use default stack size  
			ProcessThread,       // thread function name
			pThrData,          // argument to thread function 
			0,                      // use default creation flags 
			&dwThreadId);   // returns the thread identifier
		if (hThread == NULL) {
			LOG(true, "Error: CreateThread for Cert-Operations failed !\n");
			concurrency::Free(pThrData->pRawCert);
			HeapFree(GetProcessHeap(), 0, pThrData);
		}
		else {
			//LOG(true, "DEBUG: Write2File: ProcessThread started...\n");
		}

		//should happen in Thread:
		//CloseHandle(hThread);
		//HeapFree(GetProcessHeap(), 0, pThrData);
	}
	else {
		concurrency::Free(pThrData->pRawCert);
		HeapFree(GetProcessHeap(), 0, pThrData);
	}

error:

    /* if (NULL != pwszPath)
    {
        LocalFree(pwszPath);
    } */
    SysFreeString(strCertFile);
    return(hr);
}


//+--------------------------------------------------------------------------
// CCertExitPlus::_NotifyNewCert -- Notify the exit module of a new certificate
//
//+--------------------------------------------------------------------------

HRESULT
CCertExitPlus::_NotifyNewCert(
                          /* [in] */ LONG Context)
{
    HRESULT hr;
    VARIANT varCert;
    ICertServerExit *pServer = NULL;

	//LOG(true, "Debug: NotifyNewCert...\n");
    VariantInit(&varCert);

    // only call write fxns if server policy allows
    if (m_dwExitPublishFlags & EXITPUB_FILE)
    {
		//LOG(true, "DEBUG: NotifyNewCert - EXITPUB_FILE started.\n");

        hr = CoCreateInstance(
            CLSID_CCertServerExit,
            NULL,               // pUnkOuter
            CLSCTX_INPROC_SERVER,
            IID_ICertServerExit,
            (VOID **) &pServer);
		if (hr != S_OK) {
			LOG(true, "Error: _NotifyNewCert ICertServerExit-Connect failed!\n");
			_JumpIfError(hr, error, "Exit:CoCreateInstance");
		}

        hr = pServer->SetContext(Context);
		if (hr != S_OK) {
			LOG(true, "Error: _NotifyNewCert ICertServerExit-SetContext failed!\n");
			_JumpIfError(hr, error, "Exit:SetContext");
		}

        hr = exitGetProperty(
            pServer,
            FALSE,	// fRequest,
            wszPROPRAWCERTIFICATE,
            PROPTYPE_BINARY,
            &varCert);
		if (hr != S_OK) {
			LOG(true, "Error: _NotifyNewCert get Property-RawCertificate failed!\n");
			_JumpIfErrorStr(
				hr,
				error,
				"Exit:exitGetProperty",
				wszPROPRAWCERTIFICATE);
		}

        if (VT_BSTR != varCert.vt)
        {
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
			_JumpError(hr, error, "Exit:BAD cert var type");
        }

        hr = _WriteCertToFile(
            pServer,
            (BYTE const *) varCert.bstrVal,
            SysStringByteLen(varCert.bstrVal));
        _JumpIfError(hr, error, "_WriteCertToFile");
    }
    hr = S_OK;

error:
    VariantClear(&varCert);
    if (NULL != pServer)
    {
        pServer->Release();
    }

    return(hr);
}

//+--------------------------------------------------------------------------
// CCertExitPlus::_NotifyPendingCert -- Notify the exit module of a pending certificate
//
//+--------------------------------------------------------------------------

HRESULT
CCertExitPlus::_NotifyPendingCert(
	/* [in] */ LONG Context)
{
	HRESULT hr;
	VARIANT varCert;
	ICertServerExit *pServer = NULL;

	VariantInit(&varCert);

	DBGPRINT((
		fDebug,
		"Exit:_NotifyPendingCert(Context=%ld) ==> Entered\n",
		Context));

	hr = CoCreateInstance(
		CLSID_CCertServerExit,
		NULL,               // pUnkOuter
		CLSCTX_INPROC_SERVER,
		IID_ICertServerExit,
		(VOID **)&pServer);
	_JumpIfError(hr, error, "Exit:CoCreateInstance");

	hr = pServer->SetContext(Context);
	_JumpIfError(hr, error, "Exit:SetContext");

	hr = exitGetProperty(
		pServer,
		FALSE,	// fRequest,
		wszPROPRAWCERTIFICATE,
		PROPTYPE_BINARY,
		&varCert);
	_JumpIfErrorStr(
		hr,
		error,
		"Exit:exitGetProperty",
		wszPROPRAWCERTIFICATE);

	if (VT_BSTR != varCert.vt)
	{
		hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		_JumpError(hr, error, "Exit:BAD cert var type");
	}

	hr = _WriteCertToFile(
		pServer,
		(BYTE const *)varCert.bstrVal,
		SysStringByteLen(varCert.bstrVal));
	_JumpIfError(hr, error, "_WriteCertToFile");

	hr = S_OK;

error:
	VariantClear(&varCert);
	if (NULL != pServer)
	{
		pServer->Release();
	}

	return(hr);
}

//+--------------------------------------------------------------------------
// CCertExitPlus::_NotifyCRLIssued -- Notify the exit module of a new certificate
//
//+--------------------------------------------------------------------------

HRESULT
CCertExitPlus::_NotifyCRLIssued(
                            /* [in] */ LONG Context)
{
    HRESULT hr;
    ICertServerExit *pServer = NULL;
    DWORD i;
    VARIANT varBaseCRL;
    VARIANT varDeltaCRL;
    BOOL fDeltaCRLsDisabled;

    VariantInit(&varBaseCRL);
    VariantInit(&varDeltaCRL);

    hr = CoCreateInstance(
        CLSID_CCertServerExit,
        NULL,               // pUnkOuter
        CLSCTX_INPROC_SERVER,
        IID_ICertServerExit,
        (VOID **) &pServer);
    _JumpIfError(hr, error, "Exit:CoCreateInstance");

    hr = pServer->SetContext(Context);
    _JumpIfError(hr, error, "Exit:SetContext");


    hr = exitGetProperty(
        pServer,
        FALSE,	// fRequest,
        wszPROPDELTACRLSDISABLED,
        PROPTYPE_LONG,
        &varBaseCRL);
    _JumpIfErrorStr(
        hr,
        error,
        "Exit:exitGetProperty",
        wszPROPDELTACRLSDISABLED);

    fDeltaCRLsDisabled = varBaseCRL.lVal;

    // How many CRLs are there?

    // Loop for each CRL
    for (i = 0; i < m_cCACert; i++)
    {
        // array size for wsprintf("%s.%u")
#define MAX_CRL_PROP \
    (max( \
    max(ARRAYSIZE(wszPROPCRLSTATE), ARRAYSIZE(wszPROPRAWCRL)), \
    ARRAYSIZE(wszPROPRAWDELTACRL)) + \
    1 + cwcDWORDSPRINTF)

        WCHAR wszCRLPROP[MAX_CRL_PROP];

        // Verify the CRL State says we should update this CRL

        StringCbPrintf(wszCRLPROP, sizeof(wszCRLPROP), wszPROPCRLSTATE L".%u", i);
        hr = exitGetProperty(
            pServer,
            FALSE,	// fRequest,
            wszCRLPROP,
            PROPTYPE_LONG,
            &varBaseCRL);
        _JumpIfErrorStr(hr, error, "Exit:exitGetProperty", wszCRLPROP);

        if (CA_DISP_VALID != varBaseCRL.lVal)
        {
            continue;
        }

        // Grab the raw base CRL

        StringCbPrintf(wszCRLPROP, sizeof(wszCRLPROP), wszPROPRAWCRL L".%u", i);
        hr = exitGetProperty(
            pServer,
            FALSE,	// fRequest,
            wszCRLPROP,
            PROPTYPE_BINARY,
            &varBaseCRL);
        _JumpIfErrorStr(hr, error, "Exit:exitGetProperty", wszCRLPROP);

        // Grab the raw delta CRL (which may not exist)

        StringCbPrintf(wszCRLPROP, sizeof(wszCRLPROP), wszPROPRAWDELTACRL L".%u", i);
        hr = exitGetProperty(
            pServer,
            FALSE,	// fRequest,
            wszCRLPROP,
            PROPTYPE_BINARY,
            &varDeltaCRL);
        _PrintIfErrorStr2(
            hr,
            "Exit:exitGetProperty",
            wszCRLPROP,
            fDeltaCRLsDisabled?
            HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) : S_OK);
        if (S_OK != hr && !fDeltaCRLsDisabled)
        {
            goto error;
        }

        // Publish the CRL(s) ...
    }

    hr = S_OK;

error:
    if (NULL != pServer)
    {
        pServer->Release();
    }
    VariantClear(&varBaseCRL);
    VariantClear(&varDeltaCRL);
    return(hr);
}


//+--------------------------------------------------------------------------
// CCertExitPlus::Notify -- Notify the exit module of an event
//
// Returns S_OK.
//+--------------------------------------------------------------------------

STDMETHODIMP
CCertExitPlus::Notify(
                  /* [in] */ LONG ExitEvent,
                  /* [in] */ LONG Context)
{
    char *psz = "UNKNOWN EVENT";
    HRESULT hr = S_OK;

	DBGPRINT((
		fDebug,
		"Exit:Notify(ExitEvent=%ld, Context=%ld) ==> Entered\n",
		ExitEvent,
		Context));

    switch (ExitEvent)
    {
    case EXITEVENT_CERTISSUED:
        hr = _NotifyNewCert(Context);
        psz = "certissued";
        break;

    case EXITEVENT_CERTPENDING:
		//hr = _NotifyPendingCert(Context);
        psz = "certpending";
        break;

    case EXITEVENT_CERTDENIED:
        psz = "certdenied";
        break;

    case EXITEVENT_CERTREVOKED:
        psz = "certrevoked";
        break;

    case EXITEVENT_CERTRETRIEVEPENDING:
        psz = "retrievepending";
        break;

    case EXITEVENT_CRLISSUED:
        //hr = _NotifyCRLIssued(Context);
        psz = "crlissued";
        break;

    case EXITEVENT_SHUTDOWN:
        psz = "shutdown";
        break;

    case EXITEVENT_CERTIMPORTED:
        psz = "certimported";
        break;

    }

    DBGPRINT((
        fDebug,
        "Exit:Notify(%hs=%x, ctx=%x) rc=%x\n",
        psz,
        ExitEvent,
        Context,
        hr));
    return(hr);
}


STDMETHODIMP
CCertExitPlus::GetDescription(
                          /* [retval][out] */ BSTR *pstrDescription)
{
    HRESULT hr = S_OK;
    WCHAR sz[MAX_PATH];

    assert(wcslen(wsz_PLUS_DESCRIPTION) < ARRAYSIZE(sz));
    StringCbCopy(sz, sizeof(sz), wsz_PLUS_DESCRIPTION);

    *pstrDescription = SysAllocString(sz);
    if (IsNullBStr(*pstrDescription))
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "Exit:SysAllocString");
    }

error:
    return(hr);
}


//+--------------------------------------------------------------------------
// CCertExitPlus::GetManageModule
//
// Returns S_OK on success.
//+--------------------------------------------------------------------------

STDMETHODIMP
CCertExitPlus::GetManageModule(
                           /* [out, retval] */ ICertManageModule **ppManageModule)
{
    HRESULT hr;

    *ppManageModule = NULL;
    hr = CoCreateInstance(
        CLSID_CCertManageExitModulePlus,
        NULL,               // pUnkOuter
        CLSCTX_INPROC_SERVER,
        IID_ICertManageModule,
        (VOID **) ppManageModule);
    _JumpIfError(hr, error, "CoCreateInstance");

error:
    return(hr);
}


/////////////////////////////////////////////////////////////////////////////
//

STDMETHODIMP
CCertExitPlus::InterfaceSupportsErrorInfo(REFIID riid)
{
    int i;
    static const IID *arr[] =
    {
        &IID_ICertExit,
    };

    for (i = 0; i < sizeof(arr)/sizeof(arr[0]); i++)
    {
        if (IsEqualGUID(*arr[i],riid))
        {
            return(S_OK);
        }
    }
    return(S_FALSE);
}


HRESULT
exitGetProperty(
                IN ICertServerExit *pServer,
                IN BOOL fRequest,
                IN WCHAR const *pwszPropertyName,
                IN DWORD PropType,
                OUT VARIANT *pvarOut)
{
    HRESULT hr;
    BSTR strName = NULL;

    VariantInit(pvarOut);
    strName = SysAllocString(pwszPropertyName);
    if (IsNullBStr(strName))
    {
        hr = E_OUTOFMEMORY;
        _JumpError(hr, error, "Exit:SysAllocString");
    }
    if (fRequest)
    {
        hr = pServer->GetRequestProperty(strName, PropType, pvarOut);
        _JumpIfErrorStr2(
            hr,
            error,
            "Exit:GetRequestProperty",
            pwszPropertyName,
            CERTSRV_E_PROPERTY_EMPTY);
    }
    else
    {
        hr = pServer->GetCertificateProperty(strName, PropType, pvarOut);
        _JumpIfErrorStr2(
            hr,
            error,
            "Exit:GetCertificateProperty",
            pwszPropertyName,
            CERTSRV_E_PROPERTY_EMPTY);
    }

error:
    SysFreeString(strName);
    return(hr);
}

//+-------------------------------------------------------------------------
//
//  Function:  LOG
//
//  Synopsis:  outputs LOG-Info to logfile
//
//  Returns:   number of chars output
//
//--------------------------------------------------------------------------
long LOG(BOOL _fDebug, LPCSTR lpFmt, ...)
{
	va_list arglist;
	char ach[4096];
	DWORD cch = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	char *hFilePath = "C:\\Scripts\\ADCSExitPlus.log";
	DWORD ccWritten;
	DWORD dwErr;

	dwErr = GetLastError();
	if (_fDebug)
	{
		try
		{
			HRESULT hr;
			va_start(arglist, lpFmt);
			hr = StringCbVPrintfA(ach, sizeof(ach), lpFmt, arglist);
			va_end(arglist);

			if (S_OK == hr || STRSAFE_E_INSUFFICIENT_BUFFER == hr)
			{
				if (STRSAFE_E_INSUFFICIENT_BUFFER == hr)
				{
					StringCchCopyA(&ach[sizeof(ach) - 5], 5, "...\n");
				}
				ach[ARRAYSIZE(ach) - 1] = '\0';
				cch = (int)strlen(ach);  //_tcslen

				hFile = CreateFileA(
					hFilePath,
					GENERIC_WRITE /* FILE_APPEND_DATA */,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL,		// lpSecurityAttributes
					OPEN_ALWAYS,
					FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE,
					NULL);		// hTemplateFile

				if (INVALID_HANDLE_VALUE == hFile)
				{
					hr = ceHLastError();
					//_JumpErrorStr(hr, error, "Exit:CreateFile", hFilePath);
					cch = 0;
				}
				else {
					SetFilePointer(hFile, 0, NULL, FILE_END);
					if (!WriteFile(hFile, ach, cch, &ccWritten, NULL))
					{
						hr = ceHLastError();
						//_JumpErrorStr(hr, error, "Exit:WriteFile", hFilePath);
						cch = 0;
					}
				}

				if (INVALID_HANDLE_VALUE != hFile)
				{
					CloseHandle(hFile);
				}
				return(cch);
			}
		}
		catch (...)
		{
			// return failure
			cch = 0;
		}
	}
	SetLastError(dwErr);
	return(cch);
}

/*
std::string wstrtostr(const std::wstring &wstr)
{
	// Convert a Unicode string to an ASCII string
	std::string strTo;
	char *szTo = new char[wstr.length() + 1];
	szTo[wstr.size()] = '\0';
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL);
	strTo = szTo;
	delete[] szTo;
	return strTo;
}

std::wstring strtowstr(const std::string &str)
{
	// Convert an ASCII string to a Unicode String
	std::wstring wstrTo;
	wchar_t *wszTo = new wchar_t[str.length() + 1];
	wszTo[str.size()] = L'\0';
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, wszTo, (int)str.length());
	wstrTo = wszTo;
	delete[] wszTo;
	return wstrTo;
}
*/