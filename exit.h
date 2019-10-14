//+--------------------------------------------------------------------------
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved
// AGPLv3 2017 Martino Dell'Ambrogio
//
// File:        exit.h
//
// Contents:    CCertExitPlus definition
//
//---------------------------------------------------------------------------

//#include <string>
#include "adcsexitplus.h"
#include "resource.h"       // main symbols

#define BUFSIZE 4096
#define MINSTRSIZE	512

HRESULT GetServerCallbackInterface(
    OUT ICertServerExit** ppServer,
    IN LONG Context);

HRESULT exitGetProperty(
    IN ICertServerExit *pServer,
    IN BOOL fRequest,
    IN WCHAR const *pwszPropertyName,
    IN DWORD PropType,
    OUT VARIANT *pvarOut);

inline void WCS2CHAR(TCHAR *strValue);
DWORD WINAPI ProcessThread(void *lpParam);
BOOL CreateChildProcess(BOOL bWait4Proc, TCHAR *szCmdline);
void WriteToPipe(HANDLE hInputFile, HANDLE hChildStd_IN_Wr);
void ReadFromPipe(HANDLE hChildStd_OUT_Rd);
long LOG(BOOL fDebug, LPCSTR lpFmt, ...);
// std::string wstrtostr(const std::wstring &wstr);
// std::wstring strtowstr(const std::string &str);

/////////////////////////////////////////////////////////////////////////////
// certexit

class CCertExitPlus: 
    public CComDualImpl<ICertExit2, &IID_ICertExit2, &LIBID_CERTEXITPLUSLib>, 
    public ISupportErrorInfo,
    public CComObjectRoot,
    public CComCoClass<CCertExitPlus, &CLSID_CCertExitPlus>
{
public:
    CCertExitPlus() 
    { 
        m_strDescription = NULL;
        m_strCAName = NULL;
        m_pwszRegStorageLoc = NULL;
        m_hExitKey = NULL;
        m_dwExitPublishFlags = 0;
        m_cCACert = 0;
    }
    ~CCertExitPlus();

BEGIN_COM_MAP(CCertExitPlus)
    COM_INTERFACE_ENTRY(IDispatch)
    COM_INTERFACE_ENTRY(ICertExit)
    COM_INTERFACE_ENTRY(ICertExit2)
    COM_INTERFACE_ENTRY(ISupportErrorInfo)
END_COM_MAP()

DECLARE_NOT_AGGREGATABLE(CCertExitPlus) 

DECLARE_REGISTRY(
    CCertExitPlus,
    wszCLASS_CERTEXITPLUS TEXT(".1"),
    wszCLASS_CERTEXITPLUS,
    IDS_CERTEXIT_DESC,
    THREADFLAGS_BOTH)

    // ISupportsErrorInfo
    STDMETHOD(InterfaceSupportsErrorInfo)(REFIID riid);

    // ICertExit
public:
    STDMETHOD(Initialize)( 
            /* [in] */ BSTR const strConfig,
            /* [retval][out] */ LONG __RPC_FAR *pEventMask);

    STDMETHOD(Notify)(
            /* [in] */ LONG ExitEvent,
            /* [in] */ LONG Context);

    STDMETHOD(GetDescription)( 
            /* [retval][out] */ BSTR *pstrDescription);

// ICertExit2
public:
    STDMETHOD(GetManageModule)(
		/* [out, retval] */ ICertManageModule **ppManageModule);

private:
	HRESULT _NotifyNewCert(IN LONG Context);

	HRESULT _NotifyPendingCert(IN LONG Context);

	HRESULT _NotifyCRLIssued(IN LONG Context);

    HRESULT _WriteCertToFile(
	    IN ICertServerExit *pServer,
	    IN BYTE const *pbCert,
	    IN DWORD cbCert);

    HRESULT _ExpandEnvironmentVariables(
	    __in LPCWSTR pwszIn,
	    __out_ecount(cwcOut) LPWSTR pwszOut,
	    IN DWORD cwcOut);

    // Member variables & private methods here:
    BSTR           m_strDescription;
    BSTR           m_strCAName;
    LPWSTR         m_pwszRegStorageLoc;
    HKEY           m_hExitKey;
    DWORD          m_dwExitPublishFlags;
    DWORD          m_cCACert;

};
