// 1021_PE.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "CPE.h"

int main()
{
    std::cout << "Hello World!\n";
    CPE fpe;
    fpe.Init();
    fpe.GetNTHeadInfo(true);
    fpe.RvaToFoa(0x0019CE90, true);
    fpe.GetExportInfo(true);
    fpe.GetImportInfo(true);
}

