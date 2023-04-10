#include <iostream>
#include <Windows.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

int main()
{
    HANDLE hToken;
    DWORD dwLength;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
    {
        std::cerr << "Failed to open process token: " << GetLastError() << std::endl;
        return 1;
    }

    PTOKEN_USER pTokenUser;
    dwLength = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
    pTokenUser = (PTOKEN_USER)GlobalAlloc(GPTR, dwLength);
    if (!pTokenUser)
    {
        std::cerr << "Failed to allocate memory: " << GetLastError() << std::endl;
        return 1;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength))
    {
        std::cerr << "Failed to get token information: " << GetLastError() << std::endl;
        GlobalFree(pTokenUser);
        return 1;
    }

    LPTSTR strSid;
    if (!ConvertSidToStringSid(pTokenUser->User.Sid, &strSid))
    {
        std::cerr << "Failed to convert SID to string: " << GetLastError() << std::endl;
        GlobalFree(pTokenUser);
        return 1;
    }

    std::cout << "Current user SID: " << strSid << std::endl;

    PTOKEN_GROUPS pTokenGroups;
    dwLength = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwLength);
    pTokenGroups = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwLength);
    if (!pTokenGroups)
    {
        std::cerr << "Failed to allocate memory: " << GetLastError() << std::endl;
        GlobalFree(pTokenUser);
        LocalFree(strSid);
        return 1;
    }

    if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength))
    {
        std::cerr << "Failed to get token information: " << GetLastError() << std::endl;
        GlobalFree(pTokenUser);
        GlobalFree(pTokenGroups);
        LocalFree(strSid);
        return 1;
    }

    for (DWORD i = 0; i < pTokenGroups->GroupCount; ++i)
    {
        PSID pSid = pTokenGroups->Groups[i].Sid;
        TCHAR name[256];
        DWORD nameLength = 256;
        TCHAR domainName[256];
        DWORD domainNameLength = 256;
        SID_NAME_USE sidNameUse;

        if (LookupAccountSid(NULL, pSid, name, &nameLength, domainName, &domainNameLength, &sidNameUse))
        {
            LPTSTR strName = domainNameLength > 1 ? domainName : name;
            std::cout << "User: " << strName << std::endl;
        }
        else
        {
            std::cerr << "Failed to get account name for SID: " << GetLastError() << std::endl;
        }
    }

    GlobalFree(pTokenUser);
    GlobalFree(pTokenGroups);
    LocalFree(strSid);

    return 0;
}