//+--------------------------------------------------------------------------
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved
// AGPLv3 2017 Martino Dell'Ambrogio
//
// File:        pch.cpp
//
// Contents:    Cert Server precompiled header
//
//---------------------------------------------------------------------------

#include <windows.h>

#pragma warning (disable:4068) // disable warning for unknown pragma for SDK

#include <atlbase.h>
#include <strsafe.h>

//You may derive a class from CComModule and use it if you want to override
//something, but do not change the name of _Module
extern CComModule _Module;

#include <atlcom.h>
#include <certsrv.h>

// include this here so managemodule and exitmodule get to see it

#define wszCLASS_CERTEXITPLUSPREFIX TEXT("CertAuthority_Plus")

#define wszCLASS_CERTEXITPLUS wszCLASS_CERTEXITPLUSPREFIX wszCERTEXITMODULE_POSTFIX
#define wszCLASS_CERTMANAGEEXITMODULEPLUS wszCLASS_CERTEXITPLUSPREFIX wszCERTMANAGEEXIT_POSTFIX

#define wsz_PLUS_NAME           L"Plus Exit Module"
#define wsz_PLUS_DESCRIPTION    L"Plus Exit Module"
#define wsz_PLUS_COPYRIGHT      L"(c)2017 Martino Dell'Ambrogio"
#define wsz_PLUS_FILEVER        L"v 1.0"
#define wsz_PLUS_PRODUCTVER     L"v 5.00"


#pragma hdrstop
