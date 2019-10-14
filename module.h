//+--------------------------------------------------------------------------
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved
// AGPLv3 2017 Martino Dell'Ambrogio
//
// File:        module.h
//
// Contents:    CCertManageExitModulePlus definition
//
//---------------------------------------------------------------------------

#include "adcsexitplus.h"
#include "resource.h"       // main symbols


class CCertManageExitModulePlus: 
    public CComDualImpl<ICertManageModule, &IID_ICertManageModule, &LIBID_CERTEXITPLUSLib>, 
    public CComObjectRoot,
    public CComCoClass<CCertManageExitModulePlus, &CLSID_CCertManageExitModulePlus>
{
public:
    CCertManageExitModulePlus() {}
    ~CCertManageExitModulePlus() {}

BEGIN_COM_MAP(CCertManageExitModulePlus)
    COM_INTERFACE_ENTRY(IDispatch)
    COM_INTERFACE_ENTRY(ICertManageModule)
END_COM_MAP()

DECLARE_NOT_AGGREGATABLE(CCertManageExitModulePlus) 
// Remove the comment from the line above if you don't want your object to 
// support aggregation.  The default is to support it

// UNDONE UNDONE
DECLARE_REGISTRY(
    CCertManageExitModulePlus,
    wszCLASS_CERTMANAGEEXITMODULEPLUS TEXT(".1"),
    wszCLASS_CERTMANAGEEXITMODULEPLUS,
    IDS_CERTMANAGEEXITMODULE_DESC,    
    THREADFLAGS_BOTH)

// ICertManageModule
public:
    STDMETHOD (GetProperty) (
            /* [in] */ const BSTR strConfig,
            /* [in] */ BSTR strStorageLocation,
            /* [in] */ BSTR strPropertyName,
            /* [in] */ LONG dwFlags,
            /* [retval][out] */ VARIANT __RPC_FAR *pvarProperty);
        
    STDMETHOD (SetProperty)(
            /* [in] */ const BSTR strConfig,
            /* [in] */ BSTR strStorageLocation,
            /* [in] */ BSTR strPropertyName,
            /* [in] */ LONG dwFlags,
            /* [in] */ VARIANT const __RPC_FAR *pvarProperty);
        
    STDMETHOD (Configure)( 
            /* [in] */ const BSTR strConfig,
            /* [in] */ BSTR strStorageLocation,
            /* [in] */ LONG dwFlags);
};
