// Restore.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <windows.h>
#include <iostream>
#include <vector>
#include <srrestoreptapi.h>
#include <vss.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <atlbase.h>
#include <regex>
#include <string>
#include <sstream>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "vssapi.lib")
using namespace std;

STATEMGRSTATUS sm;

int GetRestorePoints() {
    HRESULT hres;

    // 初始化COM库
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
        return 1;
    }

    // 设置COM安全级别
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // 获取IWbemLocator接口
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // 连接到WMI命名空间
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\DEFAULT"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        std::cerr << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // 设置安全级别
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM SystemRestore"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cerr << "Query for operating system name failed. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // 获取数据
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        // 获取还原点的序列号
        hr = pclsObj->Get(L"SequenceNumber", 0, &vtProp, 0, 0);
        std::wcout << "Sequence Number : " << vtProp.intVal << std::endl;
        VariantClear(&vtProp);
        // 获取还原点的描述
        hr = pclsObj->Get(L"Description", 0, &vtProp, 0, 0);
        std::wcout << "Description : " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // 获取还原点的创建时间
        hr = pclsObj->Get(L"CreationTime", 0, &vtProp, 0, 0);
        std::wcout << "Creation Time : " << vtProp.bstrVal << std::endl;
        VariantClear(&vtProp);

        // 获取还原点的类型
        hr = pclsObj->Get(L"RestorePointType", 0, &vtProp, 0, 0);
        std::wcout << "Restore Point Type : " << vtProp.intVal << std::endl;
        VariantClear(&vtProp);

        // 获取还原点的事件类型
        hr = pclsObj->Get(L"EventType", 0, &vtProp, 0, 0);
        std::wcout << "Event Type : " << vtProp.intVal << std::endl;
        VariantClear(&vtProp);

        pclsObj->Release();
    }
    // 清理
    if(pSvc) pSvc->Release();
    if(pLoc) pLoc->Release();
    if(pEnumerator) pEnumerator->Release();
    CoUninitialize();

    return 0;
}

/*
 *   对指定盘开启系统还原或者关闭(isEnable=false)
 */
bool  SetRestoreDriver(std::wstring driver,bool isEnable=true) {
    HRESULT hres;

    // 初始化COM库
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
        return false;
    }

    // 设置COM安全级别
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return false;
    }

    // 获取IWbemLocator接口
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return false;
    }

    // 连接到WMI命名空间
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\DEFAULT"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        std::cerr << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // 设置安全级别
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // 获取SystemRestore类的实例
    IWbemClassObject* pClass = NULL;
    hres = pSvc->GetObject(_bstr_t(L"SystemRestore"), 0, NULL, &pClass, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to get SystemRestore class. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    auto doFunction = isEnable ? L"Enable": L"Disable";
    // 调用Enable方法创建还原点
    IWbemClassObject* pInParams = NULL;
    hres = pClass->GetMethod(doFunction, 0, &pInParams, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to get Enable method. Error code = 0x" << std::hex << hres << std::endl;
        pClass->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    VARIANT var;
    VariantInit(&var);

    V_VT(&var) = VT_BSTR;
    V_BSTR(&var) = _bstr_t(driver.c_str());


    hres = pInParams->Put(L"Drive", 0, &var, 0);
    VariantClear(&var);

    IWbemClassObject* pOutParams = NULL;
    hres = pSvc->ExecMethod(_bstr_t(L"SystemRestore"), _bstr_t(doFunction), 0, NULL, pInParams, &pOutParams, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to execute Enable method. Error code = 0x" << std::hex << hres << std::endl;
        pInParams->Release();
        pClass->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // 检查结果
    VARIANT varReturnValue;
    VariantInit(&varReturnValue);
    hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);
    if (SUCCEEDED(hres) && V_I4(&varReturnValue) == 0) {
        std::wcout << driver << doFunction << L" Success" << std::endl;
    }
    else {
        std::wcout << driver << doFunction << L" Failed" << std::endl;
    }
    VariantClear(&varReturnValue);

    // 释放资源
    if(pOutParams) pOutParams->Release();
    if(pInParams) pInParams->Release();
    if(pClass) pClass->Release();
    if(pSvc) pSvc->Release();
    if(pLoc) pLoc->Release();
    CoUninitialize();

    return true;
}


bool RemoveRestorePoint(int seq) {
    // 初始化SRRemoveRestorePoint函数指针
    bool bRet = false;
    typedef BOOL(WINAPI* SRREMOVERESTOREPOINT)(DWORD);
    HINSTANCE hinstLib = LoadLibrary(TEXT("srclient.dll"));
    if (hinstLib == NULL) {
        return bRet;
    }
    SRREMOVERESTOREPOINT SRRemoveRestorePoint = (SRREMOVERESTOREPOINT)GetProcAddress(hinstLib, "SRRemoveRestorePoint");
    if (SRRemoveRestorePoint == NULL) {
        FreeLibrary(hinstLib);
        return bRet;
    }

    // 删除还原点
    if(SRRemoveRestorePoint(seq)== ERROR_SUCCESS) {
        std::cout << "[+] Remove Success! " << endl;
        bRet = true;
    }
    // 释放SRRemoveRestorePoint函数指针
    FreeLibrary(hinstLib);
    return bRet;
}

bool CreateRestorePoint(std::wstring snapName) {
    typedef BOOL(WINAPI* SRSETRESTOREPOINT)(PRESTOREPOINTINFOW, PSTATEMGRSTATUS);
    HINSTANCE hinstLib = LoadLibrary(TEXT("srclient.dll"));
    if (hinstLib == NULL) {
        return 1;
    }
    SRSETRESTOREPOINT SRSetRestorePoint = (SRSETRESTOREPOINT)GetProcAddress(hinstLib, "SRSetRestorePointW");
    if (SRSetRestorePoint == NULL) {
        FreeLibrary(hinstLib);
        return 1;
    }
    // 设置还原点
    RESTOREPOINTINFO rpi;
    ZeroMemory(&rpi, sizeof(rpi));
    rpi.dwEventType = BEGIN_SYSTEM_CHANGE;
    rpi.dwRestorePtType = MANUAL_CHECKPOINT;
    rpi.llSequenceNumber = 0;
    //rpi.szDescription = ;
    wcscpy_s(rpi.szDescription, snapName.c_str());
    /*SRP_INFO srpInfo = { 0 };
    srpInfo.dwEventType = BEGIN_SYSTEM_CHANGE;
    srpInfo.llSequenceNumber = 0;
    srpInfo.szDescription = L"My Restore Point";
    SRP_INFO_STATUS srpInfoStatus = { 0 };*/
    bool result = SRSetRestorePoint(&rpi, &sm);
    rpi.dwEventType = END_SYSTEM_CHANGE;
    rpi.llSequenceNumber = sm.llSequenceNumber;
    result = SRSetRestorePoint(&rpi, &sm);
    FreeLibrary(hinstLib);
    if (result == true) {
        std::cout << "[+] Success! " <<  "快照序号:" << sm.llSequenceNumber << "\n";
        return true;
    }
    else {
        std::cout << "[-] Failed!" << sm.nStatus << endl; //ERROR_SERVICE_DISABLED
        return false;
    }
}

BOOL EnableShutDownPriv()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tkp = { 0 };
    //打开当前程序的权限令牌  
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }
    //获得某一特定权限的权限标识LUID，保存在tkp中  
    if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    //调用AdjustTokenPrivileges来提升我们需要的系统权限  
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        CloseHandle(hToken);
        return FALSE;
    }
    return TRUE;
}


int DoRestore(DWORD seq) {
    HRESULT hres;

    // 初始化COM库
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
        return 1;
    }

    // 设置COM安全级别
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // 获取IWbemLocator接口
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // 连接到WMI命名空间
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\DEFAULT"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        std::cerr << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // 设置安全级别
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // 要还原的还原点序列号
    int restorePointSequenceNumber = seq; // 请将此值替换为要还原的还原点序列号

    // 创建输入参数
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInParamsDefinition = NULL;
    IWbemClassObject* pInParams = NULL;
    hres = pSvc->GetObject(_bstr_t("SystemRestore"), 0, NULL, &pClass, NULL);
    hres = pClass->GetMethod(L"Restore", 0, &pInParamsDefinition, NULL);
    hres = pInParamsDefinition->SpawnInstance(0, &pInParams);
    VARIANT var;
    var.vt = VT_I4;
    var.intVal = restorePointSequenceNumber;
    hres = pInParams->Put(L"SequenceNumber", 0, &var, 0);

    // 执行Restore方法
    IWbemClassObject* pOutParams = NULL;
    hres = pSvc->ExecMethod(_bstr_t("SystemRestore"), _bstr_t("Restore"), 0, NULL, pInParams, &pOutParams, NULL);

    if (FAILED(hres)) {
        std::cerr << "Restore method execution failed. Error code = 0x" << std::hex << hres << std::endl;
    }
    else {
        std::cout << "Restore method executed successfully." << std::endl;
        // 重启电脑
        EnableShutDownPriv();
        if (!ExitWindowsEx(EWX_REBOOT, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED)) {
            cout << "Failed to reboot computer. Error code: " << GetLastError() << endl;
            return 1;
        }
    }

    // 清理
    VariantClear(&var);
    if(pOutParams) pOutParams->Release();
    if(pInParams) pInParams->Release();
    if(pInParamsDefinition) pInParamsDefinition->Release();
    if(pClass) pClass->Release();
    if(pSvc) pSvc->Release();
    if(pLoc) pLoc->Release();
    CoUninitialize();

}

bool EnableRestorePolicy(bool isEnable=TRUE) {  //  启用系统还原,有可能被管理员禁用
    CRegKey regKey;
    LPCWSTR subKey = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore";
    LPCWSTR valueSR = L"DisableSR";
    LPCWSTR valueConfig = L"DisableConfig";
    DWORD valueData = isEnable ? 0:1;
    bool  bRet = FALSE;
    // 打开或创建注册表键
    if (regKey.Create(HKEY_LOCAL_MACHINE, subKey) == ERROR_SUCCESS) {
        // 设置键值
        if (regKey.SetDWORDValue(valueSR, valueData) != ERROR_SUCCESS ||
            regKey.SetDWORDValue(valueConfig, valueData) != ERROR_SUCCESS)
        {
            bRet = TRUE;
        }
        
    }
    return bRet;
}


/*
 * 开发人员可以在注册表项 HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore 下编写创建 DWORD 值 SystemRestorePointCreationFrequency 的应用程序。
 * 此注册表项的值可以更改还原点创建的频率。 此注册表项的值可以更改还原点创建的频率。

如果应用程序调用 CreateRestorePoint 来创建还原点，并且注册表项值为 0，则系统还原不会跳过创建新还原点。

如果应用程序调用 CreateRestorePoint 来创建还原点，并且注册表项值为整数 N，则系统还原将跳过创建新还原点（如果前 N 分钟创建了任何还原点）。
 */
bool DiableRestoreFreq(bool isDisable = TRUE) {  //  
    CRegKey regKey;
    LPCWSTR subKey = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore";
    LPCWSTR valueFreq = L"SystemRestorePointCreationFrequency";
    DWORD valueData = isDisable ? 0 : 24 * 60;
    bool  bRet = FALSE;
    // 打开或创建注册表键
    if (regKey.Create(HKEY_LOCAL_MACHINE, subKey) == ERROR_SUCCESS) {
        // 设置键值
        if (regKey.SetDWORDValue(valueFreq, valueData) != ERROR_SUCCESS)
        {
            std::cout << "[+] 禁用频率限制" << endl;
            bRet = TRUE;
        }

    }
    return bRet;
}
std::vector<std::string> split(const std::string& s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter))
    {
        tokens.push_back(token);
    }
    return tokens;
}

auto GetFixedDrivers() {
    const DWORD bufferSize = 1024;
    WCHAR buffer[bufferSize]={0};
    DWORD length = GetLogicalDriveStrings(bufferSize, buffer);
    std::vector<std::wstring> drives;
    std::wstring sDirver(buffer, length);
    const wstring delimit(L"\0",1);
    //WCHAR* p = buffer;
    if (length > 0) {
        try
        {
            std::wregex rx{ delimit };
            drives = vector<wstring>{ std::wsregex_token_iterator(sDirver.begin(), sDirver.end(), rx, -1),
                std::wsregex_token_iterator()
            };
            drives.erase(std::remove_if(drives.begin(), drives.end(), [&](const std::wstring& token) {
                bool bRet = false;
                UINT type = GetDriveType(token.c_str());
                if (type == DRIVE_FIXED) {
                    WCHAR volumeFileSystem[128] = { 0 };
                    GetVolumeInformation(token.c_str(), NULL, 0, NULL, NULL, NULL, volumeFileSystem, sizeof(volumeFileSystem));
                    if(wcscmp(volumeFileSystem,L"NTFS")==0) {
                        bRet = false;
                    }else {
                        bRet = true;
                    }
                }
                else {
                    bRet = true;
                }
                return bRet;
                }), drives.end());
        }
        catch (const std::exception e)
        {
            //cout << __FUNCTION__ << " exception: " << e.what() << endl;
        }
    }

    return drives;
}

int main()
{
    auto drivers = GetFixedDrivers();
    while(true) {
        int choice = 0;
        int seq = 0;
        std::wstring driverC(L"C:\\");
        std::wstring driverD(L"D:\\");
        std::wstring snapName;
        std::cout << "\n1.枚举快照;2.创建快照;3.还原快照4.删除快照--->:";
        cin >> choice;
        cout << choice;
        switch (choice) {
        case 1:
            GetRestorePoints();
            break;
        case 2:
            EnableRestorePolicy(TRUE);
            DiableRestoreFreq();
            for(auto d : drivers) {
                SetRestoreDriver(d, true);
            }
            std::wcout << "输入快照名:";
            std::wcin >> snapName;
            std::cout << "[+] create restore 请等待..." << sm.nStatus << endl; //ERROR_SERVICE_DISABLED
            CreateRestorePoint(snapName);
            break;
        case 3:
            cout << "输入打快照时的序号:";
            cin >> seq;
            cout << seq;
            std::cout << "[+] do restore ..." << sm.nStatus << endl;
            EnableRestorePolicy(TRUE);
            DoRestore(seq);
            break;
        case 4:
            cout << "输入打快照时的序号:";
            cin >> seq;
            cout << seq;
            std::cout << "[+] delete restore ..." << sm.nStatus << endl;
            RemoveRestorePoint(seq);
            break;
        }
    }
    //
    //std::cout << "Hello World!\n";
    getchar();
}

