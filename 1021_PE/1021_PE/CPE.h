#pragma once
#include <iostream>
#include <Windows.h>
#include <time.h>
using std::cout;
using std::endl;


#include "CData.h"

class CPE
{
public:
	~CPE();
	bool Init();
	bool IsPE(char* lpImage);
	bool GetNTHeadInfo(bool isPrint = false);
	bool GetExportInfo(bool isPrint = false);
	bool GetImportInfo(bool isPrint = false);

	bool PrintFileHeader(PIMAGE_FILE_HEADER& pFileHeader);
	bool PrintOptionalHeader(PIMAGE_OPTIONAL_HEADER& pOptiHeader);
	DWORD RvaToFoa(DWORD dwRva, bool isPrint = false);
private:
	WORD misEXE32 = 0;
	IMAGE_DATA_DIRECTORY mTables[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	char* mFileData = nullptr;
};

/*	区段名说明
.text	段_一般时代码段

*/
