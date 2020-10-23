#include "CPE.h"

CPE::~CPE()
{
	if (mFileData != nullptr)
		delete[] mFileData;
}

bool CPE::Init()
{
	//1 打开文件
	HANDLE hFile = CreateFile(
		PATH,
		GENERIC_ALL,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (INVALID_HANDLE_VALUE == hFile) {
		printf_s("打开文件失败，错误码%ld\n", GetLastError());
		return false;
	}
	BOOL ret = FALSE;
	DWORD dwFileSize = GetFileSize(hFile, NULL);	//2 获取文件大小
	if (0 == dwFileSize) return false;			//文件长0则返回
	mFileData = new char[dwFileSize] {0};		//3 申请空间并初始化
	if (mFileData == nullptr) return false;		//申请失败
	DWORD dwRealSize = 0;						//4 读取文件
	ret = ReadFile(hFile, mFileData, dwFileSize, &dwRealSize, NULL);
	CloseHandle(hFile);
	if (FALSE == ret) {
		delete[] mFileData; mFileData = nullptr;
		return false;
	}
	if (!IsPE(mFileData))
	{
		std::cout << "这不是一个PE文件" << std::endl;
		return false;
	}
	return true;
}

bool CPE::IsPE(char* lpImage)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpImage;
	if (pDos == nullptr) {
		printf_s("检测Dos头失败，错误码%ld\n", GetLastError());
		return false;
	}
	if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
	{
		printf_s("检测到Dos头，指向PE偏移0x%Xh\n", (DWORD)pDos->e_lfanew);
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + lpImage);
		if (pNt->Signature == IMAGE_NT_SIGNATURE)
		{
			return true;
		}
	}
	return false;
}

bool CPE::GetNTHeadInfo(bool isPrint)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mFileData;					//1.找到DOS头
	if (pDos == nullptr)	return false;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + mFileData);//  偏移NT头
/*
typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;	//指向NT头标志：0x0000 4550 [PE..]
						//==宏[IMAGE_NT_SIGNATURE]
	IMAGE_FILE_HEADER FileHeader;			//指向[文件头]的结构体[IMAGE_FILE_HEADER]
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;	//指向[扩展头]的结构体[IMAGE_OPTIONAL_HEADER]
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
*/
	PIMAGE_FILE_HEADER pFileHeader = &pNt->FileHeader;
/*
typedef struct _IMAGE_FILE_HEADER {	//[文件头]结构体
	WORD    Machine;				//文件运行的平台[i386/014C]
	WORD    NumberOfSections;		//★区段数量
	DWORD   TimeDateStamp;			//文件创建时间
	DWORD   PointerToSymbolTable;	//符号表偏移
	DWORD   NumberOfSymbols;		//符号个数
	WORD    SizeOfOptionalHeader;	//扩展头的大小[32/00E0][64/00F0]
	WORD    Characteristics;		//PE文件的属性
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;
*/
	PIMAGE_OPTIONAL_HEADER pOption = &pNt->OptionalHeader;
	CopyMemory(&mTables, pOption->DataDirectory, sizeof(mTables));
/*
typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;	//★文件类型[32/010B][64/020B][ROM镜像/0170]
	BYTE    MajorLinkerVersion;		// 无用 连接器主版本
	BYTE    MinorLinkerVersion;		// 无用 连接器次版本
	DWORD   SizeOfCode;				//[有用]所有代码区段(节)的总大小
	DWORD   SizeOfInitializedData;	//[有用]已初始化数据的总大小
	DWORD   SizeOfUninitializedData;	//[有用]未初始化数据的总大小，
									//在磁盘中不占用空间，在加载进内存之后，
									//会预留这么大的空间，一般存储在.bss区段中
	DWORD   AddressOfEntryPoint;	//【★】程序开始执行的相对虚拟地(RVA),
								//也叫OEP，Orginal，Entry，Point，源入口点
	DWORD   BaseOfCode;			//[有用]起始代码的相对虚拟地址(RVA)
	DWORD   BaseOfData;			//[有用]起始数据的相对虚拟地址(RVA)

	//
	// NT additional fields.
	//

	DWORD   ImageBase;			//【★】默认加载基址(如果没有加载则为重定位)
	DWORD   SectionAlignment;	//【重】块对齐数，一般为0x1000
	DWORD   FileAlignment;		//【重】PE对齐数，一般为0x200
	WORD    MajorOperatingSystemVersion;	// 无用 主操作系统版本号
	WORD    MinorOperatingSystemVersion;	// 无用 次操作系统版本号
	WORD    MajorImageVersion;			// 无用 主映像版本
	WORD    MinorImageVersion;			// 无用 次映像版本
	WORD    MajorSubsystemVersion;		// 无用 主子系统版本
	WORD    MinorSubsystemVersion;		// 无用 次子系统版本
	DWORD   Win32VersionValue;		// 无用 保留值 一般为0
	DWORD   SizeOfImage;			//【重】要把文件加载进内存，
							//所需要的内存大小，注意是进行了块对齐之后
	DWORD   SizeOfHeaders;		//【重】所有头部大小
	DWORD   CheckSum;			// 无用 校验和
	WORD    Subsystem;			//[有用]子系统
	WORD    DllCharacteristics;	//[有用]指示DLL特征的标志
	DWORD   SizeOfStackReserve;	//[有用]表示进程中栈最大值,一般为1MB
	DWORD   SizeOfStackCommit;	//[有用]表示进程中栈初始值,一般为4KB
	DWORD   SizeOfHeapReserve;	//[有用]表示进程中堆最大值,一般为1MB
	DWORD   SizeOfHeapCommit;	//[有用]表示进程中堆初始值
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;	//[有用]数据目录的个数，也就是↓数组元素的个数
									//【★】数据目录表，最大为16
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
*/
	if (isPrint) {
		printf_s("_\t开始打印文件头\n");	//2 开始解析文件头
		PrintFileHeader(pFileHeader);
		printf_s("_\t开始打印扩展头\n");	//3 开始解析扩展
		PrintOptionalHeader(pOption);
		printf_s("\n_\t开始打印目录索引，共%ld\n",	//4 开始解析区段
			pOption->NumberOfRvaAndSizes);
		if (mTables == nullptr) return false;
		for (DWORD i = 0, j = 0; i < pOption->NumberOfRvaAndSizes; ++i) {
			IMAGE_DATA_DIRECTORY& tmp = pOption->DataDirectory[i];
			if (tmp.Size == 0)	continue;
			printf_s("目录ID=%2ld\tRVA=0x%Xh\t大小0x%Xh\n", i,
				tmp.VirtualAddress, tmp.Size);
		}
	}
	return true;
}

bool CPE::GetExportInfo(bool isPrint)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mFileData;
	if (nullptr == pDos) {
		printf_s("函数[GetExportInfo]错误，pDos=空指针");
		return false;
	}
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + mFileData);
	//1 获取到导出表的数据目录结构
	PIMAGE_DATA_DIRECTORY pExportDir = &pNt->OptionalHeader.DataDirectory[0];
	//1 导出表的数据目录结构中，有导出表的RVA，咱们需要将其转换为FOA，才能在文件中使用
	DWORD dwExportFOA = RvaToFoa(pExportDir->VirtualAddress);
	//1 已经得到了FOA，直接就能够找到导出表的结构
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(mFileData + dwExportFOA);
/*	导出表结构体
typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;	//1 没用 为0
	DWORD   TimeDateStamp;		//2 没用 和文件头时间一样
	WORD    MajorVersion;		//3 没用 主版本号
	WORD    MinorVersion;		//4 没用 次版本号
	DWORD   Name;				//5[有用]模块DLL名
	DWORD   Base;				//6[有用]函数的起始序号
	DWORD   NumberOfFunctions;	//7【★】函数数量
	DWORD   NumberOfNames;		//8【★】函数名数量
	DWORD   AddressOfFunctions;		//09【★】函数地址表RVA
	DWORD   AddressOfNames;			//10【★】函数名称表RVA
	DWORD   AddressOfNameOrdinals;	//11【★】函数序号表RVA
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/
	//2 得到地址表，名称表，序号表的 FOA
	DWORD EatFoa = RvaToFoa( pExport->AddressOfFunctions);
	DWORD EntFoa = RvaToFoa( pExport->AddressOfNames);
	DWORD EotFoa = RvaToFoa( pExport->AddressOfNameOrdinals);
	//3 得到地址表，名称表，序号表在文件中的位置
	//导出函数地址表
	//导出函数名称表
	//导出函数序号表
	PDWORD	pEat = (PDWORD)(mFileData + EatFoa);
	PDWORD	pEnt = (PDWORD)(mFileData + EntFoa);
	PWORD	pEot = (PWORD)(mFileData + EotFoa);
	char&	cName = mFileData[RvaToFoa(pExport->Name)];
	printf_s("\n**\t取得导出表\t名称0x%Xh %s\t入口(基址)0x%X\n",
		pExport->Name, &cName, pExport->Base);
	printf_s("\t其中函数%2ld个，函数名%2ld个\n",
		pExport->NumberOfFunctions, pExport->NumberOfNames);
	for (DWORD i = 0; i < pExport->NumberOfFunctions; i++)
	{
		printf_s("%04ld\tRVA=0x%08X\t偏移%0X\t",
			i + 1, pEat[i], RvaToFoa(pEat[i]));
		if (pEat[i] == 0) {
			cout << '\n';
			continue;
		}
		UINT ot_i = 0, isName = FALSE;
		for (; ot_i < pExport->NumberOfNames; ot_i++)
		{
			if (i == pEot[ot_i])
			{
				isName = TRUE;
				break;
			}
		}
		//4.2.1 找到了，就是有名字的函数
		if (isName == TRUE)
		{
			//名称表中，存储的是RVA，需要转为FOA
			DWORD dwFunNameFOA = RvaToFoa(pEnt[ot_i]);
			char* pFunName = mFileData + dwFunNameFOA;
			printf("名称:%s\n", pFunName);
		}
		//4.2.2 没有找到，就是没有名字的函数，虚序号
		else
		{
			printf("名称:NULL\n");
		}
	}
	return true;
}

bool CPE::GetImportInfo(bool isPrint)
{
	if (mFileData == nullptr)	return false;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mFileData;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + mFileData);
	//1 获取到导入表的数据目录结构
	PIMAGE_DATA_DIRECTORY dwImportDir = &pNt->OptionalHeader.DataDirectory[1];
	//1 导入表的数据目录结构中，有导出表的RVA，咱们需要将其转换为FOA，才能在文件中使用
	DWORD dwImportFOA = RvaToFoa(dwImportDir->VirtualAddress);
	//1 已经得到了FOA，直接就能够找到导出表的结构
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)
		(mFileData + dwImportFOA);
/*
typedef struct _IMAGE_IMPORT_DESCRIPTOR {	//导出表结构体
	union {
		DWORD   Characteristics;
		DWORD   OriginalFirstThunk;		//1【★】指向结构体数组的RVA，结构体叫做
										//输入名称表[INT:Import Name Table]
										//结构体[IMAGE_THUNK_DATA]
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;			//当可执行文件不与被输入的DLL进行绑定时,此字段为0
	DWORD   ForwarderChain;			// -1 if no forwarders	转发机制用到
									//第一个被转向的api的索引
	DWORD   Name;					//4[有用]导入的PE文件的名字RVA
	DWORD   FirstThunk;				//5【★】指向一个结构体数组的RVA，结构体叫做
									//输入地址表[IAT:Import Address Table]
									//与INT共用结构体[IMAGE_THUNK_DATA]
									//在磁盘文件中与INT相同,可以看作INT是IAT的备份
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

//3.在有些文件中输入名称表是空的，全零，什么都没有。
//	这说明输入地址表有时没有备份。所以解析输入表时用IAT解析。

typedef struct _IMAGE_THUNK_DATA32 {
	union {
		DWORD ForwarderString;		//转发时用到
		DWORD Function;				//导入函数的地址，在加载到内存后起作用
		DWORD Ordinal;				//假如是序号导入的，用到这里
		DWORD AddressOfData;		//假如是函数名导入的，用这里，
	} u1;							//指向一个结构体[IMAGE_IMPORT_BY_NAME]
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD    Hint;
	CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
*/
	//2 开始解析
	cout << "\n***\t开始打印导入表：\n";
	while (pImportTable->Name != 0)
	{
		//2.1 先解析DLL的名字
		DWORD dwNameFoa = RvaToFoa(pImportTable->Name);
		char* pDllName = (char*)(dwNameFoa + mFileData);
		printf_s("DllName\t%s\tINT=%X\tIAT=%X\n", pDllName,
			pImportTable->OriginalFirstThunk, pImportTable->FirstThunk);
		PIMAGE_THUNK_DATA pNameTable = NULL;
		DWORD Foa = RvaToFoa(pImportTable->FirstThunk);		//使用IAT解析
		pNameTable = (PIMAGE_THUNK_DATA32)(mFileData + Foa);
		while (pNameTable->u1.Ordinal != 0)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal) == 1)
			{
				//只有序号
				printf_s("\t序号:%ld,名称:NULL\n",
					pNameTable->u1.Ordinal & 0x7FFFFFFF);
			}
			else
			{
				//既有名字，又有序号
				DWORD dwNameFoa = RvaToFoa(pNameTable->u1.AddressOfData);
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(dwNameFoa + mFileData);
				printf("  %4X\t%s\n", pName->Hint, pName->Name);
			}
			pNameTable++;
		}
		pImportTable++;
	}
	cout << "------------方法1结束" << endl;
	//遍历导入表中的INT修复IAT
	/*
	while (exeimport->Name != NULL) //遍历模块
	{
		HMODULE h_dllModule = apis.pfnLoadLibraryA((char*)(exeimport->Name + ImageBase));
		PIMAGE_THUNK_DATA  import_Int = (PIMAGE_THUNK_DATA)(exeimport->OriginalFirstThunk + ImageBase);
		PIMAGE_THUNK_DATA  import_IAT = (PIMAGE_THUNK_DATA)(exeimport->FirstThunk + ImageBase);

		while (import_Int->u1.Ordinal != 0) //遍历函数
		{
			UCHAR* buf = (UCHAR*)apis.pfnHeapAlloc(heap, HEAP_ZERO_MEMORY, 10);
			buf[0] = 0xb8;
			buf[5] = 0xff;
			buf[6] = 0xe0;
			//new char[20]{ "\xB8\x00\x00\x00\0x00\0xff\0xe0" };
			DWORD opl = 0;
			apis.pfnVirtualProtect((LPVOID)buf, 20, PAGE_EXECUTE_READWRITE, &opl);
			if (import_Int->u1.Ordinal & 0x80000000) //这里是重点！！！序号导出, 最高位为1,这里是获取最高位,如果最高位为1,就执行下面里面的语句,即
			//以序号导入 ，否则以名称导入,执行else中的语句
			{
				//获取序号函数
				LPVOID apiaddr =apis.pfnGetProcAddress(h_dllModule,
					(char*)(import_Int->u1.Ordinal & 0xFFFF));
				*(DWORD*)&buf[1] = (DWORD)apiaddr;  //函数写入shellcode
				//DWORD funaddr = ;
				apis.pfnVirtualProtect((LPVOID)(import_IAT), 4, PAGE_EXECUTE_READWRITE, &opl);
				*(DWORD*)((DWORD)import_IAT) = (DWORD)buf; //将函数写入到iat
			}
			else
			{
				//DWORD Faddr = *(DWORD*)(import_Int->u1.AddressOfData + ImageBase);
				PIMAGE_IMPORT_BY_NAME funname = (PIMAGE_IMPORT_BY_NAME)
					(import_Int->u1.AddressOfData + ImageBase);
				LPVOID apiaddr =
					apis.pfnGetProcAddress(h_dllModule, funname->Name);
				*(DWORD*)&buf[1] = (DWORD)apiaddr;  //函数写入shellcode
				apis.pfnVirtualProtect((LPVOID)(import_IAT), 4, PAGE_EXECUTE_READWRITE, &opl);
				*(DWORD*)((DWORD)import_IAT) = (DWORD)buf; //将函数写入到iat
				//              DWORD funaddr =import_IAT->u1.Function  ;  //获取iat地址
				//
				//              apis.pfnVirtualProtect((LPVOID)funaddr, 4, PAGE_EXECUTE_READWRITE, &opl);
				//              *(DWORD*)(funaddr) = (DWORD)buf; //将函数写入到iat
			}
			import_Int++;
			import_IAT++;
		}
		exeimport++;
	}*/
	return false;
}

bool CPE::PrintFileHeader(PIMAGE_FILE_HEADER& pFileHeader)
{
	printf("运行平台:\t0x%X\n", pFileHeader->Machine);
	printf("区段数量:\t0x%X\n", pFileHeader->NumberOfSections);
	printf("扩展头大小:\t0x%X\n", pFileHeader->SizeOfOptionalHeader);
	printf("时间戳:\t\t0x%X\n", pFileHeader->TimeDateStamp);

	/*
	* 【PE结构】中TimeDateStamp的时间戳与标准时间转换
	* https://www.cnblogs.com/17bdw/p/6412158.html
	*/

	//gmtime_s显示文件创建时间，年数需要加上1900，月数要加上1，小时要加上8
	struct tm test_gmtime_s;
	errno_t err = gmtime_s(&test_gmtime_s, (time_t*)&pFileHeader->TimeDateStamp);
	printf("时间转换1:\t%d年 %d月 %d日 ", test_gmtime_s.tm_year + 1900, test_gmtime_s.tm_mon + 1, test_gmtime_s.tm_mday);
	printf("周%d %02d时 %02d分 %02d秒\n", test_gmtime_s.tm_wday, test_gmtime_s.tm_hour + 8, test_gmtime_s.tm_min, test_gmtime_s.tm_sec);
	//strftime格式化时间显示
	struct tm p;
	errno_t err1;
	err1 = gmtime_s(&p, (time_t*)&pFileHeader->TimeDateStamp);
	char s[100];
	strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", &p);
	printf_s("时间转换2\t%s\n", s);
	//	时间END结束
	printf("属性:\t\t0x%X\n", pFileHeader->Characteristics);
	return true;
}

bool CPE::PrintOptionalHeader(PIMAGE_OPTIONAL_HEADER& pOptiHeader)
{
	printf_s("入口点\t\t%X\n", pOptiHeader->AddressOfEntryPoint);
	printf_s("镜像基址\t%X\n", pOptiHeader->ImageBase);
	printf_s("镜像大小\t%X\n", pOptiHeader->SizeOfImage);
	printf_s("节总大小\t%X\n", pOptiHeader->SizeOfCode);

	printf_s("代码基址\t%X\n", pOptiHeader->BaseOfCode);
	printf_s("数据基址\t%X\n", pOptiHeader->BaseOfData);
	printf_s("块对齐\t\t%X\n", pOptiHeader->SectionAlignment);
	printf_s("PE对齐\t\t%X\n", pOptiHeader->FileAlignment);
	printf_s("标志字\t\t%X", pOptiHeader->Magic);
	if (0x10B == pOptiHeader->Magic)
		cout << "\t这是32位程序\n\n";
	else if (0x20B == pOptiHeader->Magic)
		cout << "\t这是64位程序\n\n";
	else	cout << "\n\n";
	printf_s("子系统\t\t%X\n", pOptiHeader->Subsystem);
	printf_s("首部大小\t%X\n", pOptiHeader->SizeOfHeaders);
	printf_s("校验和\t\t%X\n", pOptiHeader->CheckSum);
	printf_s("RVA 数\t\t%X\n", pOptiHeader->NumberOfRvaAndSizes);
	return true;
}

DWORD CPE::RvaToFoa(DWORD dwRva, bool isPrint)
{
	if (dwRva == 0) return dwRva;
	else if (dwRva == 1) return 1;
	//1 获取区段表的起始位置
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mFileData;
	if (nullptr == pDos)	return 0;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + mFileData);
	PIMAGE_SECTION_HEADER pHeader = IMAGE_FIRST_SECTION(pNt);
/*
typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];	//块名
	union {
			DWORD   PhysicalAddress;	//NULL
			DWORD   VirtualSize;		//2[有用]区块没有对齐前的实际大小
	} Misc;
	DWORD   VirtualAddress;			//3【★】段RVA
	DWORD   SizeOfRawData;			//4【★】段大小	+ RVA =段尾
	DWORD   PointerToRawData;		//5【★】段FOA	段FOA-段RVA=目标FOA-目标RVA
	DWORD   PointerToRelocations;	//6 没用 区段重定位信息的文件偏移
	DWORD   PointerToLinenumbers;	//7 没用 COFF行号信息的偏移
	WORD    NumberOfRelocations;	//8 没用 重定位信息的数目
	WORD    NumberOfLinenumbers;	//9 没用 行号信息的数目，只有COFF行号时才有用
	DWORD   Characteristics;		//10【★】区段属性：可读写执行
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
*/
	if (dwRva < pNt->OptionalHeader.SizeOfHeaders)
	{
		return dwRva;
	}
	for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		//该段的第一个字节的地址（当加载到内存中时），相对于映像库。
		DWORD &dwSectionRva = pHeader[i].VirtualAddress;
		//计算段尾Rva，由		[段初始值]	+	[磁盘上已初始化的大小]
		DWORD dwSectionEndRva = dwSectionRva + pHeader[i].SizeOfRawData;
		//指向COFF文件内第一页的文件指针。
		DWORD &dwSectionFOA = pHeader[i].PointerToRawData;
		/*
		目标FOA=目标RVA-段RVA+段FOA
		变形：段FOA-段RVA=目标FOA-目标RVA
		原型：原始VA - 默认基址   =  新VA -  新基址
		*/
		DWORD dwFOA = dwRva - dwSectionRva + dwSectionFOA;
		if (isPrint)
			printf_s("目标\tRva=0x%Xh\t结果0x%X\t源FOA=%04X\t节头=%X\t节尾=%X\t名%s\n",
				dwRva, dwFOA, dwSectionFOA, dwSectionRva, dwSectionEndRva, pHeader[i].Name);
		if (dwRva >= dwSectionRva && dwRva < dwSectionEndRva)
		{
			if(isPrint)
				printf_s("目标\t中标↑↑↑\n");
			return dwFOA;
		}
	}
	return 0;
}
