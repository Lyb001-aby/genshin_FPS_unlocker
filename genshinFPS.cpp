// GenshinFPSUnlocker_Console.cpp - 控制台版本
// 这是一个用于解锁《原神》FPS限制的工具，通过修改游戏内存中的FPS变量来实现
// 配置文件 fps_config.txt 格式：
// FPS=120
// Path=C:\Program Files\Genshin Impact\YuanShen.exe

#define DEFAULT_FPS 120  // 默认FPS值，如果配置文件中没有指定或解析失败时使用
#define _CRT_SECURE_NO_WARNINGS  // 禁用安全警告，允许使用传统的C函数（如strcpy等）

// Windows API头文件，提供了Windows编程所需的函数和数据结构
#include <Windows.h>      // Windows核心API，包括进程、内存、文件操作等
#include <TlHelp32.h>     // 工具帮助库，提供进程、线程、模块快照功能
#include <vector>         // STL动态数组容器
#include <string>         // STL字符串处理类
#include <thread>         // C++11线程支持
#include <Psapi.h>        // 进程状态API，用于获取进程信息
#include <fstream>        // 文件输入输出流
#include <sstream>        // 字符串流，用于字符串解析
#include <atomic>         // 原子操作，用于线程安全的数据访问
#include <iostream>       // 标准输入输出流

// 全局变量 - 这些变量在程序的不同部分共享，需要谨慎访问
std::string GamePath{};           // 游戏可执行文件的完整路径
int FpsValue = DEFAULT_FPS;       // 当前的FPS目标值
std::atomic<bool> g_Running{ true }; // 原子布尔值，控制程序是否继续运行（线程安全）
HANDLE g_hProcess = NULL;          // 游戏进程的句柄，用于后续的进程操作
uintptr_t g_pfps = 0;              // 游戏中FPS变量的内存地址（这是我们要修改的目标）
uintptr_t g_patch_addr = 0;        // 注入的shellcode中用于写入FPS值的地址
HANDLE g_job = NULL;               // Job对象句柄，用于将游戏进程加入作业，实现进程组管理
const char* CONFIG_FILE = "fps_config.txt"; // 配置文件名，默认为当前目录下的fps_config.txt

/**
 * 检查是否已有相同名称的其它进程在运行（排除当前进程）
 * 这是防止程序多开的重要功能，避免多个实例同时操作游戏导致冲突
 * @param exeName 要检查的可执行文件名
 * @return 存在其他同名进程返回true，否则返回false
 */
static bool IsAnotherInstanceRunning(const std::string& exeName)
{
    DWORD currentPid = GetCurrentProcessId();  // 获取当前进程ID
    PROCESSENTRY32 pe32{};  // 进程入口结构，用于存储快照中的进程信息
    pe32.dwSize = sizeof(pe32);
    // 创建系统进程快照，TH32CS_SNAPPROCESS表示只捕获进程信息
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    // 遍历进程快照中的所有进程
    for (BOOL ok = Process32First(snap, &pe32); ok; ok = Process32Next(snap, &pe32))
    {
        // 比较进程名（不区分大小写）且排除当前进程
        if (_stricmp(pe32.szExeFile, exeName.c_str()) == 0 && pe32.th32ProcessID != currentPid)
        {
            CloseHandle(snap);
            return true;  // 发现其他同名进程
        }

    }

    CloseHandle(snap);
    return false;  // 未发现其他同名进程
}

/**
 * 这段代码用于修改文件具有隐藏属性，显性则不使用
 * @param path 文件路径
 */
static void EnsureHiddenAttribute(const std::string& path)
{
    DWORD attrs = GetFileAttributesA(path.c_str());  // 获取当前文件属性
    if (attrs != INVALID_FILE_ATTRIBUTES)  // 如果文件存在

    {
        if (!(attrs & FILE_ATTRIBUTE_HIDDEN))  // 如果不是隐藏文件
            SetFileAttributesA(path.c_str(), attrs | FILE_ATTRIBUTE_HIDDEN); // 添加隐藏属性
    }
}

/**
 * 控制台事件处理函数
 * 当用户关闭控制台或按下Ctrl+C时调用，负责清理资源
 * 这是一个回调函数，由Windows在控制台事件发生时调用
 * @param ctrlType 控制台事件类型
 * @return TRUE表示已处理，FALSE表示未处理
 */
BOOL WINAPI ConsoleHandler(DWORD ctrlType)
{
    switch (ctrlType)
    {
    case CTRL_C_EVENT:      // 用户按下Ctrl+C
    case CTRL_CLOSE_EVENT:  // 用户关闭控制台窗口
    case CTRL_BREAK_EVENT:  // 用户按下Ctrl+Break
    case CTRL_LOGOFF_EVENT: // 用户注销系统
    case CTRL_SHUTDOWN_EVENT: // 系统关机
        if (g_hProcess)
        {
            // 尝试强制结束游戏进程（暴力方式）
            TerminateProcess(g_hProcess, 0);
        }
        // 如果创建了Job对象，关闭它会触发KILL_ON_JOB_CLOSE标志
        if (g_job)
        {
            CloseHandle(g_job);
            g_job = NULL;
        }
        Sleep(200); // 给系统一点时间完成终止操作
        return TRUE;  // 表示已处理该事件
    default:
        return FALSE; // 其他未处理的事件
    }
}

/**
 * Shellcode - 这是要注入到游戏进程中的机器码
 * 它的作用是在游戏进程中创建一个线程，实时监控FPS值的变化
 *
 * Shellcode布局说明：
 * [0-4]:    解锁器进程的PID（供shellcode识别父进程）
 * [4-8]:    时间戳，标记shellcode编译时间
 * [8-16]:   解锁器中FpsValue变量的地址（供shellcode读取）
 * [16-24]:  OpenProcess函数地址
 * [24-32]:  ReadProcessMemory函数地址
 * [32-40]:  Sleep函数地址
 * [40-48]:  MessageBoxA函数地址（用于显示错误信息）
 * [48-56]:  CloseHandle函数地址
 * [56-64]:  空闲区域，预留
 * [64-80]:  int3指令（调试断点，填充用）
 * [80-208]: _sync_thread函数 - 主循环，从解锁器读取FPS值
 * [208-224]: hook_fps_set函数 - 拦截游戏设置FPS的代码
 * [224-240]: hook_fps_get函数 - 拦截游戏读取FPS的代码
 * [240-256]: Sync_auto函数 - 自动同步FPS
 * [256-288]: 错误处理和消息框显示
 * [288-304]: 字符串"Sync failed!"（错误信息）
 * [304-320]: 字符串"Error"（对话框标题）
 * [320-324]: Game_Current_set - 当前设置的FPS
 * [324-328]: Readmem_buffer - 读取的内存缓冲区
 * [328-336]: 预留空间
 */
const BYTE _shellcode_genshin_Const[] =
{
    // ... [Shellcode内容保持不变，上面已经说明了布局]
};


/**
 * 从TXT配置文件加载配置
 * 读取FPS值和游戏路径，如果文件不存在或格式错误，返回false
 * @return 配置加载成功返回true，失败返回false
 */
bool LoadTXTConfig()
{
    std::ifstream file(CONFIG_FILE);  // 打开配置文件
    if (!file.is_open())        return false;  // 文件不存在或无法打开

    std::string line;
    while (std::getline(file, line))  // 逐行读取
    {
        if (line.empty())
            continue;  // 跳过空行

        size_t pos = line.find('=');  // 查找等号位置，分割键值对
        if (pos == std::string::npos)
            continue;  // 没有等号，不是有效的配置行，跳过

        std::string key = line.substr(0, pos);    // 键名（等号左边）
        std::string value = line.substr(pos + 1); // 键值（等号右边）

        // 去除键名和键值的首尾空白字符（空格、制表符、回车、换行）
        key.erase(0, key.find_first_not_of(" \t\r\n"));
        key.erase(key.find_last_not_of(" \t\r\n") + 1);
        value.erase(0, value.find_first_not_of(" \t\r\n"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);

        if (key == "FPS" || key == "fps")  // 不区分大小写匹配FPS键
        {
            // 解析FPS值，处理可能的错误
            try
            {

                size_t idx = 0;
                int v = std::stoi(value, &idx);  // 字符串转整数
                if (idx != value.size())  // 如果解析后还有多余的字符，说明格式不对
                    v = DEFAULT_FPS;
                if (v < 24) v = 24;   // 最小FPS限制，防止设置过低导致游戏异常
                if (v > 240) v = 240; // 最大FPS限制，防止设置过高导致硬件过载
                FpsValue = v;
            }
            catch (...) {
                FpsValue = DEFAULT_FPS;  // 解析失败时使用默认值
            }
        }
        else if (key == "Path" || key == "path")  // 匹配路径键
        {
            GamePath = value;  // 保存游戏路径
        }
    }

    file.close();
    // 必须同时有路径和有效的FPS值才认为配置加载成功
    return !GamePath.empty() && FpsValue > 0;
}

/**
 * 保存配置到TXT文件
 * 首次运行时会调用此函数保存检测到的游戏路径
 * @param path 游戏路径
 * @param fps FPS值
 * @return 保存成功返回true
 */
bool SaveTXTConfig(const std::string& path, int fps)
{
    std::ofstream file(CONFIG_FILE);
    if (!file.is_open())
        return false;

    file << "FPS=" << fps << "\n";

    file << "Path=" << path << "\n";

    file.close();

    // 注释这个函数，生成的txt配置文件则为显性
    //EnsureHiddenAttribute(CONFIG_FILE);

    return true;
}

/**
 * 从配置文件中只读取FPS值（不读取路径）
 * 这是一个专门用于监控线程的函数，只关心FPS值的变化

 * 如果文件不存在，返回false
 * 如果文件存在但没有FPS值，使用默认值并返回true
 * @param out 输出参数，接收读取的FPS值
 * @return 文件存在并读取成功返回true
 */
static bool TryReadFPSFromTXT(int& out)
{
    DWORD attrs = GetFileAttributesA(CONFIG_FILE);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return false; // 文件不存在

    std::ifstream file(CONFIG_FILE);
    if (!file.is_open())
        return false;

    std::string line;
    while (std::getline(file, line))
    {
        if (line.empty())
            continue;

        size_t pos = line.find('=');
        if (pos == std::string::npos)
            continue;

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        // 去除首尾空格
        key.erase(0, key.find_first_not_of(" \t\r\n"));

        key.erase(key.find_last_not_of(" \t\r\n") + 1);
        value.erase(0, value.find_first_not_of(" \t\r\n"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);

        if (key == "FPS" || key == "fps")

        {
            try

            {
                size_t idx = 0;
                int v = std::stoi(value, &idx);
                // 确保整个字符串都是数值（排除尾随字符）

                if (idx != value.size())
                {
                    out = DEFAULT_FPS;
                }
                else
                {
                    out = v;
                }
            }
            catch (...) {
                out = DEFAULT_FPS;
            }

            // 强制范围检查，确保FPS值在安全范围内
            if (out < 24) out = 24;

            if (out > 240) out = 240;

            file.close();
            return true;
        }
    }

    file.close();
    // 文件存在但没有找到FPS键，视为有效文件，返回默认值
    out = DEFAULT_FPS;
    return true;
}

/**
 * 兼容旧接口的函数，直接返回FPS值
 * 这是为可能存在的旧代码提供的兼容性函数
 * @return 读取的FPS值，读取失败时返回当前保存的FPS值
 */
int ReadFPSFromTXT()
{
    int v = 0;
    if (!TryReadFPSFromTXT(v))
        return FpsValue; // 文件不存在，保持当前值
    return v;
}

/**
 * 将Windows错误码转换为可读的字符串
 * 用于调试和错误报告，让用户更容易理解错误原因
 * @param code 错误码（通常来自GetLastError()）
 * @return 错误描述字符串
 */
std::string GetLastErrorAsString(DWORD code)
{
    LPSTR buf = nullptr;
    // FormatMessage可以获取系统错误信息的文本描述
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);

    std::string ret = buf;
    LocalFree(buf);  // 释放FormatMessage分配的缓冲区
    return ret;
}

/**
 * 通过进程名查找进程ID
 * 遍历系统中所有进程，查找指定名称的进程
 * @param ProcessName 要查找的进程名（如"YuanShen.exe"）
 * @return 找到的进程ID，未找到则返回0
 */
DWORD GetPID(const std::string& ProcessName)
{
    DWORD pid = 0;
    PROCESSENTRY32 pe32{};  // 进程入口结构
    pe32.dwSize = sizeof(pe32);
    // 创建进程快照，TH32CS_SNAPPROCESS表示捕获所有进程
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    // 遍历所有进程    for (BOOL success = Process32First(snap, &pe32); success; success = Process32Next(snap, &pe32))
    {
        if (_stricmp(pe32.szExeFile, ProcessName.c_str()) == 0)  // 不区分大小写比较
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }


    CloseHandle(snap);
    return pid;
}


/**
 * 获取指定进程中的模块信息
 * 模块是加载到进程地址空间的可执行文件或DLL

 * @param pid 进程ID
 * @param ModuleName 模块名（如"YuanShen.exe"）
 * @param entry 输出参数，接收模块信息
 * @return 找到模块返回true

 */
static bool GetModule(DWORD pid, const std::string& ModuleName, MODULEENTRY32& entry)
{
    MODULEENTRY32 mod32{};
    mod32.dwSize = sizeof(mod32);
    // 创建指定进程的模块快照
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

    if (snap == INVALID_HANDLE_VALUE)
        return false;

    bool found = false;
    // 遍历进程的所有模块
    for (BOOL success = Module32First(snap, &mod32); success; success = Module32Next(snap, &mod32))
    {
        if (mod32.th32ProcessID == pid && _stricmp(mod32.szModule, ModuleName.c_str()) == 0)
        {
            entry = mod32;
            found = true;
            break;
        }
    }

    CloseHandle(snap);
    return found;
}

/**
 * 等待进程的主模块加载完成
 * 游戏启动后需要一定时间加载主模块，这个函数等待直到模块可用
 * 这是必要的，因为CreateProcess返回时模块可能还未完全加载
 * @param pid 进程ID
 * @param procname 进程名
 * @param out 输出参数，接收模块信息
 * @param timeout_ms 超时时间（毫秒），默认50秒
 * @return 在超时前找到模块返回true
 */

static bool WaitForBaseModule(DWORD pid, const std::string& procname, MODULEENTRY32& out, DWORD timeout_ms = 50000)
{
    const DWORD step = 50;  // 每次检查间隔50ms，避免过于频繁的查询
    DWORD waited = 0;
    while (waited < timeout_ms)
    {
        if (GetModule(pid, procname, out))
            return true;  // 模块已加载

        Sleep(step);      // 等待一小段时间再检查
        waited += step;
    }
    return false;  // 超时，模块仍未加载
}

/**
 * 在内存区域中搜索特征码
 * 这是逆向工程中常用的技术，通过已知的指令序列定位代码位置
 * 特征码可以包含通配符"?"，表示任意字节
 * @param startAddress 搜索起始地址
 * @param regionSize 搜索区域大小
 * @param signature 特征码字符串（如"8B 0D ?? ?? ?? ?? EB ?? 33 C0"）
 * @return 找到的特征码地址，未找到返回0
 */
static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    // 将特征码字符串转换为字节数组，-1表示通配符
    auto pattern_to_byte = [](const char* pattern)
        {
            std::vector<int> bytes;  // 使用int可以存储-1表示通配符
            const char* current = pattern;

            while (*current)
            {
                if (*current == ' ' || *current == '\t')
                {
                    current++;
                    continue;  // 跳过空白字符
                }

                if (*current == '?')
                {
                    bytes.push_back(-1);  // 通配符，可以匹配任意字节
                    current++;
                    if (*current == '?')
                        current++;  // 跳过第二个?（如果存在）
                }
                else
                {
                    // 解析十六进制字节（如"8B"）
                    unsigned long val = strtoul(current, (char**)&current, 16);
                    bytes.push_back((int)val);
                }
            }
            return bytes;
        };

    std::vector<int> patternBytes = pattern_to_byte(signature);
    if (patternBytes.empty())
        return 0;

    if (regionSize < patternBytes.size())
        return 0;  // 搜索区域太小，不可能找到匹配

    auto scanBytes = reinterpret_cast<uint8_t*>(startAddress);

    // 逐字节匹配，允许通配符

    for (size_t i = 0; i <= regionSize - patternBytes.size(); i++)
    {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); j++)
        {
            int b = patternBytes[j];
            if (b != -1 && scanBytes[i + j] != (uint8_t)b)
            {
                found = false;
                break;
            }
        }
        if (found)
            return (uintptr_t)&scanBytes[i];  // 返回匹配到的地址
    }

    return 0;  // 未找到匹配
}

/**
 * 将shellcode注入到目标进程
 * 这是核心功能：在目标进程中分配内存，写入shellcode，并创建远程线程执行
 * shellcode会创建一个线程，定期从解锁器读取FPS值并写入游戏内存
 * @param pfps 游戏中FPS变量的地址
 * @param target_handle 目标进程的句柄
 * @return shellcode中用于写入FPS值的地址，失败返回0
 */
static uintptr_t inject_patch(uintptr_t pfps, HANDLE target_handle)
{
    // 第一步：在本进程分配内存，准备shellcode
    // 0x1000 = 4KB，是Windows内存页的标准大小
    uint64_t _shellcode_buffer = (uint64_t)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!_shellcode_buffer)
    {
        printf("本地内存分配失败\n");
        return 0;
    }


    // 复制shellcode模板到本地缓冲区
    memcpy((void*)_shellcode_buffer, &_shellcode_genshin_Const, sizeof(_shellcode_genshin_Const));

    /**
     * 第二步：填充shellcode中的动态数据
     * 这些地址在编译时未知，需要在运行时获取并写入shellcode
     * shellcode需要这些信息才能与解锁器进程通信
     */
    *(uint32_t*)_shellcode_buffer = GetCurrentProcessId();  // 当前进程ID，供shellcode识别父进程
    *(uint64_t*)(_shellcode_buffer + 8) = (uint64_t)(&FpsValue);  // FPS变量在解锁器中的地址
    *(uint64_t*)(_shellcode_buffer + 16) = (uint64_t)(&OpenProcess);  // Windows API函数地址
    *(uint64_t*)(_shellcode_buffer + 24) = (uint64_t)(&ReadProcessMemory);
    *(uint64_t*)(_shellcode_buffer + 32) = (uint64_t)(&Sleep);
    *(uint64_t*)(_shellcode_buffer + 40) = (uint64_t)(&MessageBoxA);
    *(uint64_t*)(_shellcode_buffer + 48) = (uint64_t)(&CloseHandle);

    // 以下是一些预设值，用于shellcode中的特定位置
    *(uint32_t*)(_shellcode_buffer + 0xE4) = 1000;  // 可能是某些循环的计数值
    *(uint32_t*)(_shellcode_buffer + 0xEC) = 60;    // 可能是默认FPS值
    *(uint64_t*)(_shellcode_buffer + 0x110) = 0xB848;
    *(uint64_t*)(_shellcode_buffer + 0x118) = 0x741D8B0000;
    *(uint64_t*)(_shellcode_buffer + 0x120) = 0xCCCCCCCCCCC31889;

    *(uint64_t*)(_shellcode_buffer + 0x112) = pfps;  // 设置游戏中FPS变量的地址
    *(uint64_t*)(_shellcode_buffer + 0x15C) = 0x5C76617E8834858;
    *(uint64_t*)(_shellcode_buffer + 0x164) = 0xE0FF21EBFFFFFF16;

    // 第三步：在目标进程分配内存
    // PAGE_EXECUTE_READWRITE权限允许执行代码，这是shellcode运行所必需的
    LPVOID remote_buffer = VirtualAllocEx(target_handle, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_buffer)
    {
        printf("目标进程内存分配失败\n");
        VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
        return 0;
    }

    // 第四步：将shellcode写入目标进程
    if (!WriteProcessMemory(target_handle, remote_buffer, (void*)_shellcode_buffer, sizeof(_shellcode_genshin_Const), 0))
    {
        printf("写入shellcode失败\n");
        VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
        return 0;
    }

    // 释放本地缓冲区
    VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
    // 第五步：在目标进程创建远程线程执行shellcode
    // 线程入口点是remote_buffer + 0x50，这是_sync_thread函数的起始位置
    HANDLE temp = CreateRemoteThread(target_handle, 0, 0, (LPTHREAD_START_ROUTINE)((uint64_t)remote_buffer + 0x50), 0, 0, 0);
    if (!temp)
    {
        printf("创建远程线程失败\n");
        return 0;
    }


    CloseHandle(temp);  // 不需要等待线程结束，让它在后台运行
    printf("Shellcode注入成功\n");
    return ((uint64_t)remote_buffer + 0x194);  // 返回FPS补丁地址，用于后续写入
}


/**
 * 配置文件监控线程
 * 定期读取配置文件中的FPS值，实时更新目标FPS
 * 当配置文件丢失时锁定为最后一次有效值，防止游戏异常
 * @param p 指向原子整数（目标FPS）的指针
 * @return 线程返回值（未使用）
 */
DWORD __stdcall ConfigMonitorThread(LPVOID p)
{
    std::atomic<int>* pTargetFPS = (std::atomic<int>*)p;
    int lastFPS = pTargetFPS->load();  // 当前FPS值
    int last_valid_fps = lastFPS;      // 最后一次有效值，用于文件丢失时恢复
    bool locked = false;  // 是否处于锁定状态（配置文件丢失）

    while (true)  // 无限循环，直到程序结束
    {
        Sleep(500);  // 每500ms检查一次，既及时响应变化，又不会过于频繁

        // 检查配置文件是否存在

        DWORD attrs = GetFileAttributesA(CONFIG_FILE);        if (attrs == INVALID_FILE_ATTRIBUTES)
        {
            if (!locked)
            {
                // 文件丢失，锁定为最后一次有效值
                // 这样可以防止因文件被误删而导致FPS突然变回默认值
                int lockVal = last_valid_fps;
                if (lockVal <= 0) lockVal = DEFAULT_FPS;
                pTargetFPS->store(lockVal);
                FpsValue = lockVal;
                lastFPS = lockVal;
                locked = true;
                printf("配置文件丢失，已锁定FPS为 %d\n", lockVal);
            }
            continue;  // 继续循环并保持锁定
        }

        // 配置文件存在，尝试读取
        int newFPS = 0;
        bool ok = TryReadFPSFromTXT(newFPS);
        if (!ok)
        {
            continue;  // 读取失败，跳过本次循环
        }

        // 如果之前处于锁定状态，现在文件恢复了，解除锁定
        if (locked)
        {            locked = false;
            printf("配置文件恢复，解除锁定\n");
        }

        // 如果FPS值有变化，更新目标
        if (newFPS != lastFPS)
        {
            pTargetFPS->store(newFPS);
            FpsValue = newFPS;
            lastFPS = newFPS;
        }

        // 更新最后一次有效值，用于文件丢失时恢复
        last_valid_fps = newFPS;
    }
    return 0;
}

/**
 * 主监控线程
 * 监控游戏进程状态，定期写入新的FPS值
 * 当游戏退出时，自动结束本程序
 * @param p 指向原子整数（目标FPS）的指针
 * @return 线程返回值（未使用）
 */
DWORD __stdcall MainMonitorThread(LPVOID p)
{
    std::atomic<int>* pTargetFPS = (std::atomic<int>*)p;

    DWORD dwExitCode = STILL_ACTIVE;
    while (dwExitCode == STILL_ACTIVE)
    {
        if (g_hProcess)
        {
            // 检查游戏进程是否还在运行
            GetExitCodeProcess(g_hProcess, &dwExitCode);

            int current_fps = 0;
            SIZE_T bytesRead = 0;
            // 读取游戏中当前的FPS值，验证是否需要更新
            if (ReadProcessMemory(g_hProcess, (LPVOID)g_pfps, &current_fps, sizeof(current_fps), &bytesRead) && bytesRead == sizeof(current_fps))
            {
                int target = pTargetFPS->load();  // 获取目标FPS
                if (current_fps != -1 && current_fps != target)  // 如果值不同，需要更新
                {
                    SIZE_T written = 0;
                    int value = target;
                    // 通过shellcode中的地址写入新FPS值
                    // 注意：这里写入的是g_patch_addr，而不是g_pfps
                    // g_patch_addr指向shellcode中的某个位置，shellcode会负责实际写入

                    BOOL ok = WriteProcessMemory(g_hProcess, (LPVOID)g_patch_addr, &value, sizeof(value), &written);
                    if (!ok || written != sizeof(value))
                    {
                        DWORD err = GetLastError();
                        printf("写入目标进程失败: %lu (%s)\n", err, GetLastErrorAsString(err).c_str());
                    }
                }
            }
        }
        Sleep(2000);  // 每2秒检查一次，避免过于频繁的读写
    }

    // 游戏进程已退出，本程序也应该退出
    printf("检测到游戏进程已退出，辅助程序即将退出。\n");
    if (g_job)
    {
        CloseHandle(g_job);
        g_job = NULL;
    }

    ExitProcess(0);  // 强制退出本程序

    return 0;
}

/**
 * 主函数
 * 程序入口点，包含完整的执行流程：
 * 1. 检查是否已运行
 * 2. 加载配置或首次运行设置
 * 3. 启动游戏
 * 4. 定位FPS变量
 * 5. 注入shellcode
 * 6. 启动监控线程
 * 7. 等待游戏退出
 */
int main()
{
    SetConsoleTitleA("Genshin FPS Unlocker");  // 设置控制台窗口标题

    // 检查是否已有同名进程在运行，避免多开
    // 注意：这里硬编码了"genshinFPS.exe"，应与实际编译出的文件名一致
    if (IsAnotherInstanceRunning("genshinFPS.exe"))
    {
        printf("检测到已存在同名进程，程序将于 2 秒后退出...\n");
        Sleep(2000);
        return 0;
    }

    printf("====================================\n");
    printf("   原神 FPS 解锁器 - TXT配置版\n");
    printf("====================================\n\n");

    // 第一步：加载配置
    if (!LoadTXTConfig())
    {
        /**
         * 首次运行，配置不存在
         * 这种情况下，我们引导用户手动启动游戏，然后自动检测路径

         */
        printf("首次运行，请手动启动游戏以获取路径...\n");
        printf("等待游戏启动...\n");

        // 等待游戏启动（检测YuanShen.exe或GenshinImpact.exe）
        DWORD pid = 0;
        while (!(pid = GetPID("YuanShen.exe")) && !(pid = GetPID("GenshinImpact.exe")))
            Sleep(200);

        // 打开进程以获取完整路径
        // PROCESS_QUERY_LIMITED_INFORMATION权限足够查询进程信息，不需要完全控制
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess)
        {
            printf("无法打开进程！错误码: %lu\n", GetLastError());
            system("pause");
            return 0;
        }

        // 获取进程的完整路径
        char szPath[MAX_PATH]{};
        DWORD length = sizeof(szPath);
        QueryFullProcessImageNameA(hProcess, 0, szPath, &length);
        CloseHandle(hProcess);

        GamePath = szPath;
        SaveTXTConfig(GamePath, DEFAULT_FPS);  // 保存配置

        printf("已保存游戏路径到 fps_config.txt\n");
        printf("请关闭游戏后重新运行本程序\n");

        /**
         * 等待用户手动关闭游戏
         * 因为我们需要在游戏未运行时启动它，所以要求用户先关闭游戏
         */
        HWND hwnd = nullptr;
        // FindWindowA查找窗口类名为"UnityWndClass"的窗口（Unity游戏的标准窗口类）
        while (!(hwnd = FindWindowA("UnityWndClass", nullptr)))
            Sleep(200);

        DWORD ExitCode = STILL_ACTIVE;
        while (ExitCode == STILL_ACTIVE)
        {
            SendMessageA(hwnd, WM_CLOSE, 0, 0);  // 发送关闭窗口消息
            GetExitCodeProcess(hProcess, &ExitCode);
            Sleep(200);
        }

        system("pause");
        return 0;
    }

    // 显示配置信息，让用户确认
    printf("配置文件加载成功\n");
    printf("游戏路径: %s\n", GamePath.c_str());
    printf("目标FPS: %d\n\n", FpsValue);

    // 解析路径，分离出目录和文件名
    std::string ProcessPath = GamePath;
    std::string ProcessDir = ProcessPath.substr(0, ProcessPath.find_last_of("\\"));
    std::string procname = ProcessPath.substr(ProcessPath.find_last_of("\\") + 1);

    // 检查游戏是否已在运行
    DWORD pid = GetPID(procname);
    if (pid)
    {
        printf("检测到游戏已在运行！请手动关闭游戏\n");
        system("pause");
        return 0;
    }

    // 第二步：启动游戏进程
    printf("启动游戏中...\n");
    STARTUPINFOA si{};  // 启动信息结构体，初始化为0
    PROCESS_INFORMATION pi{};  // 进程信息结构体，用于接收新进程的信息

    if (!CreateProcessA(ProcessPath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, ProcessDir.c_str(), &si, &pi))
    {
        DWORD code = GetLastError();
        printf("启动游戏失败 (%lu): %s\n", code, GetLastErrorAsString(code).c_str());
        system("pause");
        return 0;
    }

    CloseHandle(pi.hThread);  // 不需要线程句柄，关闭它以释放资源
    g_hProcess = pi.hProcess;  // 保存进程句柄供后续使用
    printf("游戏启动成功，PID: %d\n", pi.dwProcessId);

    // 注册控制台事件处理函数
    // 这样当用户关闭控制台时，我们可以尝试结束游戏进程
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    /**
     * 创建Job对象并设置KILL_ON_JOB_CLOSE标志
     * Job对象是Windows提供的一种进程组管理机制
     * 将游戏进程加入Job后，当本程序被强制结束时，游戏也会随之结束
     * 防止留下孤立的游戏进程（这是内存修改工具应该注意的）
     */
    g_job = CreateJobObjectA(NULL, NULL);

    if (g_job)
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
        // 设置标志：当Job对象的最后一个句柄关闭时，终止所有关联进程
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(g_job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli)))

        {
            printf("设置 JobObject 信息失败: %s\n", GetLastErrorAsString(GetLastError()).c_str());
            CloseHandle(g_job);
            g_job = NULL;
        }
        else
        {
            if (!AssignProcessToJobObject(g_job, pi.hProcess))
            {
                printf("将游戏加入 JobObject 失败: %s\n", GetLastErrorAsString(GetLastError()).c_str());
                CloseHandle(g_job);
                g_job = NULL;
            }
            else
            {

                printf("已将游戏进程加入 JobObject (进程退出时会随 Job 关闭而被终止)\n");
            }
        }
    }

    // 设置游戏进程优先级为高，提高游戏性能
    SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);

    // 第三步：等待游戏主模块加载完成
    MODULEENTRY32 hBaseModule{};
    if (!WaitForBaseModule(pi.dwProcessId, procname, hBaseModule))
    {
        printf("获取模块基址失败！\n");        CloseHandle(pi.hProcess);
        system("pause");
        return 0;
    }

    uintptr_t baseAddr = (uintptr_t)hBaseModule.modBaseAddr;
    printf("模块基址: 0x%llX\n", baseAddr);


    // 第四步：读取PE头，定位.text节
    // PE（Portable Executable）是Windows可执行文件格式
    // .text节通常包含程序的执行代码
    LPVOID pe_buffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pe_buffer)
    {
        printf("分配PE缓冲区失败\n");
        CloseHandle(pi.hProcess);

        system("pause");
        return 0;
    }

    // 读取进程内存中的PE头（前0x1000字节通常包含DOS头和PE头）
    if (!ReadProcessMemory(pi.hProcess, (LPVOID)baseAddr, pe_buffer, 0x1000, 0))
    {
        printf("读取PE头失败\n");
        VirtualFree(pe_buffer, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        system("pause");
        return 0;
    }

    /**
     * 解析PE结构
     * PE文件格式结构：
     * - DOS头（包含"e_lfanew"指向PE头）
     * - PE头（包含文件头、可选头）
     * - 节表（描述各节的属性、位置）
     */
    uintptr_t e_lfanew = (uintptr_t)pe_buffer + 0x3C;  // e_lfanew字段在DOS头中的偏移
    uintptr_t pe_header = (uintptr_t)pe_buffer + *(uint32_t*)e_lfanew;  // PE头起始位置
    IMAGE_NT_HEADERS64 nt_headers = *(IMAGE_NT_HEADERS64*)pe_header;

    uint32_t text_rva = 0;   // .text节的相对虚拟地址
    uint32_t text_size = 0;  // .text节的大小

    if (nt_headers.Signature == 0x00004550)  // 检查PE签名"PE\0\0"
    {
        DWORD section_count = nt_headers.FileHeader.NumberOfSections;
        IMAGE_SECTION_HEADER section_header;

        // 遍历所有节，找到.text节
        for (DWORD i = 0; i < section_count; i++)
        {
            section_header = *(IMAGE_SECTION_HEADER*)(pe_header + sizeof(IMAGE_NT_HEADERS64) + i * sizeof(IMAGE_SECTION_HEADER));

            if (memcmp(section_header.Name, ".text", 5) == 0)  // 节名以.text开头
            {
                text_rva = section_header.VirtualAddress;
                text_size = section_header.Misc.VirtualSize;
                break;
            }
        }    }

    if (text_rva == 0 || text_size == 0)
    {
        printf("找不到.text节\n");
        VirtualFree(pe_buffer, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        system("pause");
        return 0;
    }

    uintptr_t text_remote = baseAddr + text_rva;  // .text节在目标进程中的实际地址

    // 第五步：读取.text节到本地进行分析
    LPVOID text_local = VirtualAlloc(0, text_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!text_local)
    {
        printf("分配.text缓冲区失败\n");
        VirtualFree(pe_buffer, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        system("pause");
        return 0;
    }

    if (!ReadProcessMemory(pi.hProcess, (void*)text_remote, text_local, text_size, 0))
    {
        printf("读取.text节失败\n");
        VirtualFree(pe_buffer, 0, MEM_RELEASE);
        VirtualFree(text_local, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        system("pause");
        return 0;
    }

    printf("搜索特征码...\n");

    /**
     * 第六步：搜索特征码定位FPS变量
     * 特征码 "8B 0D ?? ?? ?? ?? EB ?? 33 C0" 对应指令：
     * 8B 0D ????????    mov ecx, dword ptr [????????]  ; 读取FPS值到ecx寄存器
     * EB ??              jmp                           ; 无条件跳转
     * 33 C0              xor eax, eax                   ; eax寄存器清零
     *
     * 这个模式在原神代码中很常见，用于读取FPS限制值
     * ?? 表示通配符，因为具体地址每次编译都可能不同
     */
    uintptr_t pattern_addr = PatternScan_Region((uintptr_t)text_local, text_size, "8B 0D ?? ?? ?? ?? EB ?? 33 C0");
    if (!pattern_addr)
    {
        printf("特征码过期，请更新\n");
        VirtualFree(pe_buffer, 0, MEM_RELEASE);
        VirtualFree(text_local, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        system("pause");
        return 0;
    }
    /**
     * 计算FPS变量的实际内存地址
     * 在x64指令中，mov ecx, [rip + offset] 这样的指令使用相对寻址
     * 偏移量是相对于下一条指令的地址
     *
     * 指令格式：8B 0D [4字节偏移量]
     * 有效地址 = RIP（下一条指令地址） + 偏移量
     */
    uintptr_t rip = pattern_addr + 6;  // 下一条指令的地址（当前指令长度6字节）
    int32_t offset = *(int32_t*)(pattern_addr + 2);  // 指令中的4字节偏移量（从第3字节开始）
    uintptr_t local_fps_addr = rip + offset;  // 在本地缓冲区中的地址
    // 转换为目标进程中的实际地址：本地地址 - 本地基址 + 远程基址
    g_pfps = local_fps_addr - (uintptr_t)text_local + text_remote;

    printf("FPS变量地址: 0x%llX\n", g_pfps);


    // 第七步：注入shellcode
    g_patch_addr = inject_patch(g_pfps, pi.hProcess);
    if (!g_patch_addr)
    {
        printf("注入失败\n");
    }
    // 清理本地缓冲区
    VirtualFree(pe_buffer, 0, MEM_RELEASE);
    VirtualFree(text_local, 0, MEM_RELEASE);

    printf("\n解锁成功！\n\n");
    printf("配置文件监控已启动 (每0.5秒读取 fps_config.txt)\n");
    printf("直接编辑配置文件中的FPS值即可调整\n\n");

    // 第八步：创建监控线程
    std::atomic<int> current_target(FpsValue);  // 线程安全的FPS目标值
    HANDLE hMonitor = CreateThread(nullptr, 0, ConfigMonitorThread, &current_target, 0, nullptr);
    HANDLE hMainMonitor = CreateThread(nullptr, 0, MainMonitorThread, &current_target, 0, nullptr);
    // 第九步：主监控循环
    printf("监控游戏进程...\n");
    DWORD dwExitCode = STILL_ACTIVE;
    while (dwExitCode == STILL_ACTIVE)
    {
        GetExitCodeProcess(pi.hProcess, &dwExitCode);  // 检查游戏是否还在运行
        Sleep(2000);

        // 显示当前FPS，使用\r实现同一行更新
        printf("\r当前目标FPS: %d    ", current_target.load());
    }

    printf("\n游戏已关闭，退出程序\n");
    CloseHandle(pi.hProcess);  // 清理进程句柄

    return 0;
}
