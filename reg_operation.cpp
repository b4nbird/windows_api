#include <Windows.h>
#include <string>

//对比相应注册表值是否等于某个值
int reg_key_compare(HKEY hKeyRoot, char* lpSubKey, char* regVal, char* compare) {
    HKEY hKey = nullptr;
    LONG ret;
    char value[1024];
    DWORD size = sizeof(value);
    ret = RegOpenKeyExA(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, regVal, NULL, NULL, (LPBYTE)value, &size);
        if (ret == ERROR_SUCCESS) {
            if (strcmp(value, compare) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

//注册表的写入
int reg_key_write(){
    HKEY hkey = NULL;
	const char* exeName = "D:\\store\\a.exe";
	
	//add exeName to startup
	LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"xxXx", 0, KEY_WRITE, &hkey);
	if (res == ERROR_SUCCESS)
	{
		RegSetValueEx(hkey, (LPCSTR)"xxXx", 0, REG_SZ, (unsigned char*)exeName, strlen(exeName));
		RegCloseKey(hkey);
	}
	else
	{
		cout << "RegOpenKeyEx failed" << endl;
	}
}