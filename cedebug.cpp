//+---------------------------------------------------------------------------
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved
// AGPLv3 2017 Martino Dell'Ambrogio
//
//	File:		cedebug.cpp
//
//	Contents:	Debug support
//
//----------------------------------------------------------------------------

#include <pch.cpp>

#pragma hdrstop

#include "celib.h"
#include <stdarg.h>


//+-------------------------------------------------------------------------
//
//  Function:  ceDbgPrintf
//
//  Synopsis:  outputs debug info to logfile and debugger
//
//  Returns:   number of chars output
//
//--------------------------------------------------------------------------

int WINAPIV
ceDbgPrintf(
    IN BOOL fDebug,
    IN LPCSTR lpFmt,
    ...)
{
    va_list arglist;
    CHAR ach[4096];
    DWORD cch = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPCWSTR hFilePath = L"C:\\Scripts\\ADCSExitPlus.log";
	DWORD ccWritten;
    DWORD dwErr;

    dwErr = GetLastError();
    if (fDebug)
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
		ach[ARRAYSIZE(ach) - 1] = L'\0';
		cch = (int)strlen(ach);

		if (!IsDebuggerPresent())
		{
			hFile = CreateFile(
				hFilePath,
				FILE_APPEND_DATA,
				FILE_SHARE_READ,
				NULL,		// lpSecurityAttributes
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);		// hTemplateFile

			if (INVALID_HANDLE_VALUE == hFile)
			{
				hr = ceHLastError();
				_JumpErrorStr(hr, error, "Exit:CreateFile", hFilePath);
			}
			if (!WriteFile(hFile, ach, cch, &ccWritten, NULL))
			{
				hr = ceHLastError();
				_JumpErrorStr(hr, error, "Exit:WriteFile", hFilePath);
			}
			if (ccWritten != cch)
			{
				hr = STG_E_WRITEFAULT;
				DBGPRINT((
					fDebug,
					"Exit:WriteFile(%ws): attempted %x, actual %x bytes: %x\n",
					hFilePath,
					cch,
					ccWritten,
					hr));
				goto error;
			}

		error:

			if (INVALID_HANDLE_VALUE != hFile)
			{
				CloseHandle(hFile);
			}

			// return failure
			cch = 0;

			return(cch);
		}
		OutputDebugStringA(ach);
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
