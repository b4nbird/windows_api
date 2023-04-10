/*
查询访问本机的网络资源时所创建的网络会话，进而获取域用户和IP信息
Using: FindADPC.exe \\dc1
*/
#include <iostream>
#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "Netapi32.lib")
#pragma warning(disable:4996)
#include <stdio.h>
#include <assert.h>
#include <windows.h> 
#include <lm.h>
#include <ctime>

int session_enum(LPTSTR pszServerName) {
    NET_API_STATUS nStatus;
    LPSESSION_INFO_10 pBuf = NULL;
    LPSESSION_INFO_10 pTmpBuf;
    DWORD dwLevel = 10;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD i;
    DWORD dwTotalCount = 0;

    do
    {
        nStatus = NetSessionEnum(pszServerName,
            NULL,
            NULL,
            dwLevel,
            (LPBYTE*)&pBuf,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle);

        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
        {
            if ((pTmpBuf = pBuf) != NULL)
            {

                for (i = 0; (i < dwEntriesRead); i++)
                {
                    assert(pTmpBuf != NULL);

                    if (pTmpBuf == NULL)
                    {
                        fprintf(stderr, "An access violation has occurred\n");
                        break;
                    }

                    SYSTEMTIME sys;
                    GetLocalTime(&sys);
                    char current_time[64] = { NULL };
                    sprintf(current_time, "%4d-%02d-%02d %02d:%02d:%02d ", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);

                    printf("[%s]  [%ws]  [%ws]  [%ws]\n", current_time, pszServerName, pTmpBuf->sesi10_cname, pTmpBuf->sesi10_username);

                    pTmpBuf++;
                    dwTotalCount++;
                }
            }
        }

        else
            fprintf(stderr, "A system error has occurred: %d\n", nStatus);

        if (pBuf != NULL)
        {
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    } while (nStatus == ERROR_MORE_DATA);

    if (pBuf != NULL)
        NetApiBufferFree(pBuf);
    return 0;
}
int wmain(int argc, wchar_t* argv[])
{

    if (argc == 1)
    {
        printf("\nUsing:\n\t FindADPC.exe \\\\dc1 \n");
        return 0;
    }

    while (true)
    {
        for (size_t i = 0; i < argc; i++)
        {
            if (i == 0)
            {
                continue;
            }
            session_enum(argv[i]);
        }
        Sleep(5000);
    }

    return 0;
}
