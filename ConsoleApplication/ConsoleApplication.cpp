// ConsoleApplication.cpp : 定义控制台应用程序的入口点。
// https://msdn.microsoft.com/en-us/library/hskdteyh(v=vs.100).aspx

#include "stdafx.h"

#include <stdio.h>
#include <string.h>
#include <intrin.h>

int _tmain(int argc, _TCHAR* argv[])
{
    char CPUString[0x20];
    int CPUInfo[4] = {-1};
    unsigned    nIds;

    // __cpuid with an InfoType argument of 0 returns the number of valid Ids in CPUInfo[0] and the CPU identification string in the other three array elements.
    // The CPU identification string is not in linear order. The code below arranges the information in a human readable form.
    __cpuid(CPUInfo, 0);
    nIds = CPUInfo[0];
    memset(CPUString, 0, sizeof(CPUString));
    *((int*)CPUString) = CPUInfo[1];
    *((int*)(CPUString+4)) = CPUInfo[3];
    *((int*)(CPUString+8)) = CPUInfo[2];

    printf_s("CPU String: %s\n", CPUString);

    return 0;
}