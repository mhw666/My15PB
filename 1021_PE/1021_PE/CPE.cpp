#include "CPE.h"

CPE::~CPE()
{
	if (mFileData != nullptr)
		delete[] mFileData;
}

bool CPE::Init()
{
	//1 ���ļ�
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
		printf_s("���ļ�ʧ�ܣ�������%ld\n", GetLastError());
		return false;
	}
	BOOL ret = FALSE;
	DWORD dwFileSize = GetFileSize(hFile, NULL);	//2 ��ȡ�ļ���С
	if (0 == dwFileSize) return false;			//�ļ���0�򷵻�
	mFileData = new char[dwFileSize] {0};		//3 ����ռ䲢��ʼ��
	if (mFileData == nullptr) return false;		//����ʧ��
	DWORD dwRealSize = 0;						//4 ��ȡ�ļ�
	ret = ReadFile(hFile, mFileData, dwFileSize, &dwRealSize, NULL);
	CloseHandle(hFile);
	if (FALSE == ret) {
		delete[] mFileData; mFileData = nullptr;
		return false;
	}
	if (!IsPE(mFileData))
	{
		std::cout << "�ⲻ��һ��PE�ļ�" << std::endl;
		return false;
	}
	return true;
}

bool CPE::IsPE(char* lpImage)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpImage;
	if (pDos == nullptr) {
		printf_s("���Dosͷʧ�ܣ�������%ld\n", GetLastError());
		return false;
	}
	if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
	{
		printf_s("��⵽Dosͷ��ָ��PEƫ��0x%Xh\n", (DWORD)pDos->e_lfanew);
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
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mFileData;					//1.�ҵ�DOSͷ
	if (pDos == nullptr)	return false;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + mFileData);//  ƫ��NTͷ
/*
typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;	//ָ��NTͷ��־��0x0000 4550 [PE..]
						//==��[IMAGE_NT_SIGNATURE]
	IMAGE_FILE_HEADER FileHeader;			//ָ��[�ļ�ͷ]�Ľṹ��[IMAGE_FILE_HEADER]
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;	//ָ��[��չͷ]�Ľṹ��[IMAGE_OPTIONAL_HEADER]
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
*/
	PIMAGE_FILE_HEADER pFileHeader = &pNt->FileHeader;
/*
typedef struct _IMAGE_FILE_HEADER {	//[�ļ�ͷ]�ṹ��
	WORD    Machine;				//�ļ����е�ƽ̨[i386/014C]
	WORD    NumberOfSections;		//����������
	DWORD   TimeDateStamp;			//�ļ�����ʱ��
	DWORD   PointerToSymbolTable;	//���ű�ƫ��
	DWORD   NumberOfSymbols;		//���Ÿ���
	WORD    SizeOfOptionalHeader;	//��չͷ�Ĵ�С[32/00E0][64/00F0]
	WORD    Characteristics;		//PE�ļ�������
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;
*/
	PIMAGE_OPTIONAL_HEADER pOption = &pNt->OptionalHeader;
	CopyMemory(&mTables, pOption->DataDirectory, sizeof(mTables));
/*
typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;	//���ļ�����[32/010B][64/020B][ROM����/0170]
	BYTE    MajorLinkerVersion;		// ���� ���������汾
	BYTE    MinorLinkerVersion;		// ���� �������ΰ汾
	DWORD   SizeOfCode;				//[����]���д�������(��)���ܴ�С
	DWORD   SizeOfInitializedData;	//[����]�ѳ�ʼ�����ݵ��ܴ�С
	DWORD   SizeOfUninitializedData;	//[����]δ��ʼ�����ݵ��ܴ�С��
									//�ڴ����в�ռ�ÿռ䣬�ڼ��ؽ��ڴ�֮��
									//��Ԥ����ô��Ŀռ䣬һ��洢��.bss������
	DWORD   AddressOfEntryPoint;	//�������ʼִ�е���������(RVA),
								//Ҳ��OEP��Orginal��Entry��Point��Դ��ڵ�
	DWORD   BaseOfCode;			//[����]��ʼ�������������ַ(RVA)
	DWORD   BaseOfData;			//[����]��ʼ���ݵ���������ַ(RVA)

	//
	// NT additional fields.
	//

	DWORD   ImageBase;			//���Ĭ�ϼ��ػ�ַ(���û�м�����Ϊ�ض�λ)
	DWORD   SectionAlignment;	//���ء����������һ��Ϊ0x1000
	DWORD   FileAlignment;		//���ء�PE��������һ��Ϊ0x200
	WORD    MajorOperatingSystemVersion;	// ���� ������ϵͳ�汾��
	WORD    MinorOperatingSystemVersion;	// ���� �β���ϵͳ�汾��
	WORD    MajorImageVersion;			// ���� ��ӳ��汾
	WORD    MinorImageVersion;			// ���� ��ӳ��汾
	WORD    MajorSubsystemVersion;		// ���� ����ϵͳ�汾
	WORD    MinorSubsystemVersion;		// ���� ����ϵͳ�汾
	DWORD   Win32VersionValue;		// ���� ����ֵ һ��Ϊ0
	DWORD   SizeOfImage;			//���ء�Ҫ���ļ����ؽ��ڴ棬
							//����Ҫ���ڴ��С��ע���ǽ����˿����֮��
	DWORD   SizeOfHeaders;		//���ء�����ͷ����С
	DWORD   CheckSum;			// ���� У���
	WORD    Subsystem;			//[����]��ϵͳ
	WORD    DllCharacteristics;	//[����]ָʾDLL�����ı�־
	DWORD   SizeOfStackReserve;	//[����]��ʾ������ջ���ֵ,һ��Ϊ1MB
	DWORD   SizeOfStackCommit;	//[����]��ʾ������ջ��ʼֵ,һ��Ϊ4KB
	DWORD   SizeOfHeapReserve;	//[����]��ʾ�����ж����ֵ,һ��Ϊ1MB
	DWORD   SizeOfHeapCommit;	//[����]��ʾ�����жѳ�ʼֵ
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;	//[����]����Ŀ¼�ĸ�����Ҳ���ǡ�����Ԫ�صĸ���
									//�������Ŀ¼�����Ϊ16
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
*/
	if (isPrint) {
		printf_s("_\t��ʼ��ӡ�ļ�ͷ\n");	//2 ��ʼ�����ļ�ͷ
		PrintFileHeader(pFileHeader);
		printf_s("_\t��ʼ��ӡ��չͷ\n");	//3 ��ʼ������չ
		PrintOptionalHeader(pOption);
		printf_s("\n_\t��ʼ��ӡĿ¼��������%ld\n",	//4 ��ʼ��������
			pOption->NumberOfRvaAndSizes);
		if (mTables == nullptr) return false;
		for (DWORD i = 0, j = 0; i < pOption->NumberOfRvaAndSizes; ++i) {
			IMAGE_DATA_DIRECTORY& tmp = pOption->DataDirectory[i];
			if (tmp.Size == 0)	continue;
			printf_s("Ŀ¼ID=%2ld\tRVA=0x%Xh\t��С0x%Xh\n", i,
				tmp.VirtualAddress, tmp.Size);
		}
	}
	return true;
}

bool CPE::GetExportInfo(bool isPrint)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mFileData;
	if (nullptr == pDos) {
		printf_s("����[GetExportInfo]����pDos=��ָ��");
		return false;
	}
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + mFileData);
	//1 ��ȡ�������������Ŀ¼�ṹ
	PIMAGE_DATA_DIRECTORY pExportDir = &pNt->OptionalHeader.DataDirectory[0];
	//1 �����������Ŀ¼�ṹ�У��е������RVA��������Ҫ����ת��ΪFOA���������ļ���ʹ��
	DWORD dwExportFOA = RvaToFoa(pExportDir->VirtualAddress);
	//1 �Ѿ��õ���FOA��ֱ�Ӿ��ܹ��ҵ�������Ľṹ
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(mFileData + dwExportFOA);
/*	������ṹ��
typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;	//1 û�� Ϊ0
	DWORD   TimeDateStamp;		//2 û�� ���ļ�ͷʱ��һ��
	WORD    MajorVersion;		//3 û�� ���汾��
	WORD    MinorVersion;		//4 û�� �ΰ汾��
	DWORD   Name;				//5[����]ģ��DLL��
	DWORD   Base;				//6[����]��������ʼ���
	DWORD   NumberOfFunctions;	//7�����������
	DWORD   NumberOfNames;		//8�������������
	DWORD   AddressOfFunctions;		//09���������ַ��RVA
	DWORD   AddressOfNames;			//10����������Ʊ�RVA
	DWORD   AddressOfNameOrdinals;	//11���������ű�RVA
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/
	//2 �õ���ַ�����Ʊ���ű�� FOA
	DWORD EatFoa = RvaToFoa( pExport->AddressOfFunctions);
	DWORD EntFoa = RvaToFoa( pExport->AddressOfNames);
	DWORD EotFoa = RvaToFoa( pExport->AddressOfNameOrdinals);
	//3 �õ���ַ�����Ʊ���ű����ļ��е�λ��
	//����������ַ��
	//�����������Ʊ�
	//����������ű�
	PDWORD	pEat = (PDWORD)(mFileData + EatFoa);
	PDWORD	pEnt = (PDWORD)(mFileData + EntFoa);
	PWORD	pEot = (PWORD)(mFileData + EotFoa);
	char&	cName = mFileData[RvaToFoa(pExport->Name)];
	printf_s("\n**\tȡ�õ�����\t����0x%Xh %s\t���(��ַ)0x%X\n",
		pExport->Name, &cName, pExport->Base);
	printf_s("\t���к���%2ld����������%2ld��\n",
		pExport->NumberOfFunctions, pExport->NumberOfNames);
	for (DWORD i = 0; i < pExport->NumberOfFunctions; i++)
	{
		printf_s("%04ld\tRVA=0x%08X\tƫ��%0X\t",
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
		//4.2.1 �ҵ��ˣ����������ֵĺ���
		if (isName == TRUE)
		{
			//���Ʊ��У��洢����RVA����ҪתΪFOA
			DWORD dwFunNameFOA = RvaToFoa(pEnt[ot_i]);
			char* pFunName = mFileData + dwFunNameFOA;
			printf("����:%s\n", pFunName);
		}
		//4.2.2 û���ҵ�������û�����ֵĺ����������
		else
		{
			printf("����:NULL\n");
		}
	}
	return true;
}

bool CPE::GetImportInfo(bool isPrint)
{
	if (mFileData == nullptr)	return false;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mFileData;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + mFileData);
	//1 ��ȡ������������Ŀ¼�ṹ
	PIMAGE_DATA_DIRECTORY dwImportDir = &pNt->OptionalHeader.DataDirectory[1];
	//1 ����������Ŀ¼�ṹ�У��е������RVA��������Ҫ����ת��ΪFOA���������ļ���ʹ��
	DWORD dwImportFOA = RvaToFoa(dwImportDir->VirtualAddress);
	//1 �Ѿ��õ���FOA��ֱ�Ӿ��ܹ��ҵ�������Ľṹ
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)
		(mFileData + dwImportFOA);
/*
typedef struct _IMAGE_IMPORT_DESCRIPTOR {	//������ṹ��
	union {
		DWORD   Characteristics;
		DWORD   OriginalFirstThunk;		//1���ָ��ṹ�������RVA���ṹ�����
										//�������Ʊ�[INT:Import Name Table]
										//�ṹ��[IMAGE_THUNK_DATA]
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;			//����ִ���ļ����뱻�����DLL���а�ʱ,���ֶ�Ϊ0
	DWORD   ForwarderChain;			// -1 if no forwarders	ת�������õ�
									//��һ����ת���api������
	DWORD   Name;					//4[����]�����PE�ļ�������RVA
	DWORD   FirstThunk;				//5���ָ��һ���ṹ�������RVA���ṹ�����
									//�����ַ��[IAT:Import Address Table]
									//��INT���ýṹ��[IMAGE_THUNK_DATA]
									//�ڴ����ļ�����INT��ͬ,���Կ���INT��IAT�ı���
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

//3.����Щ�ļ����������Ʊ��ǿյģ�ȫ�㣬ʲô��û�С�
//	��˵�������ַ����ʱû�б��ݡ����Խ��������ʱ��IAT������

typedef struct _IMAGE_THUNK_DATA32 {
	union {
		DWORD ForwarderString;		//ת��ʱ�õ�
		DWORD Function;				//���뺯���ĵ�ַ���ڼ��ص��ڴ��������
		DWORD Ordinal;				//��������ŵ���ģ��õ�����
		DWORD AddressOfData;		//�����Ǻ���������ģ������
	} u1;							//ָ��һ���ṹ��[IMAGE_IMPORT_BY_NAME]
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD    Hint;
	CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
*/
	//2 ��ʼ����
	cout << "\n***\t��ʼ��ӡ�����\n";
	while (pImportTable->Name != 0)
	{
		//2.1 �Ƚ���DLL������
		DWORD dwNameFoa = RvaToFoa(pImportTable->Name);
		char* pDllName = (char*)(dwNameFoa + mFileData);
		printf_s("DllName\t%s\tINT=%X\tIAT=%X\n", pDllName,
			pImportTable->OriginalFirstThunk, pImportTable->FirstThunk);
		PIMAGE_THUNK_DATA pNameTable = NULL;
		DWORD Foa = RvaToFoa(pImportTable->FirstThunk);		//ʹ��IAT����
		pNameTable = (PIMAGE_THUNK_DATA32)(mFileData + Foa);
		while (pNameTable->u1.Ordinal != 0)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal) == 1)
			{
				//ֻ�����
				printf_s("\t���:%ld,����:NULL\n",
					pNameTable->u1.Ordinal & 0x7FFFFFFF);
			}
			else
			{
				//�������֣��������
				DWORD dwNameFoa = RvaToFoa(pNameTable->u1.AddressOfData);
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(dwNameFoa + mFileData);
				printf("  %4X\t%s\n", pName->Hint, pName->Name);
			}
			pNameTable++;
		}
		pImportTable++;
	}
	cout << "------------����1����" << endl;
	//����������е�INT�޸�IAT
	/*
	while (exeimport->Name != NULL) //����ģ��
	{
		HMODULE h_dllModule = apis.pfnLoadLibraryA((char*)(exeimport->Name + ImageBase));
		PIMAGE_THUNK_DATA  import_Int = (PIMAGE_THUNK_DATA)(exeimport->OriginalFirstThunk + ImageBase);
		PIMAGE_THUNK_DATA  import_IAT = (PIMAGE_THUNK_DATA)(exeimport->FirstThunk + ImageBase);

		while (import_Int->u1.Ordinal != 0) //��������
		{
			UCHAR* buf = (UCHAR*)apis.pfnHeapAlloc(heap, HEAP_ZERO_MEMORY, 10);
			buf[0] = 0xb8;
			buf[5] = 0xff;
			buf[6] = 0xe0;
			//new char[20]{ "\xB8\x00\x00\x00\0x00\0xff\0xe0" };
			DWORD opl = 0;
			apis.pfnVirtualProtect((LPVOID)buf, 20, PAGE_EXECUTE_READWRITE, &opl);
			if (import_Int->u1.Ordinal & 0x80000000) //�������ص㣡������ŵ���, ���λΪ1,�����ǻ�ȡ���λ,������λΪ1,��ִ��������������,��
			//����ŵ��� �����������Ƶ���,ִ��else�е����
			{
				//��ȡ��ź���
				LPVOID apiaddr =apis.pfnGetProcAddress(h_dllModule,
					(char*)(import_Int->u1.Ordinal & 0xFFFF));
				*(DWORD*)&buf[1] = (DWORD)apiaddr;  //����д��shellcode
				//DWORD funaddr = ;
				apis.pfnVirtualProtect((LPVOID)(import_IAT), 4, PAGE_EXECUTE_READWRITE, &opl);
				*(DWORD*)((DWORD)import_IAT) = (DWORD)buf; //������д�뵽iat
			}
			else
			{
				//DWORD Faddr = *(DWORD*)(import_Int->u1.AddressOfData + ImageBase);
				PIMAGE_IMPORT_BY_NAME funname = (PIMAGE_IMPORT_BY_NAME)
					(import_Int->u1.AddressOfData + ImageBase);
				LPVOID apiaddr =
					apis.pfnGetProcAddress(h_dllModule, funname->Name);
				*(DWORD*)&buf[1] = (DWORD)apiaddr;  //����д��shellcode
				apis.pfnVirtualProtect((LPVOID)(import_IAT), 4, PAGE_EXECUTE_READWRITE, &opl);
				*(DWORD*)((DWORD)import_IAT) = (DWORD)buf; //������д�뵽iat
				//              DWORD funaddr =import_IAT->u1.Function  ;  //��ȡiat��ַ
				//
				//              apis.pfnVirtualProtect((LPVOID)funaddr, 4, PAGE_EXECUTE_READWRITE, &opl);
				//              *(DWORD*)(funaddr) = (DWORD)buf; //������д�뵽iat
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
	printf("����ƽ̨:\t0x%X\n", pFileHeader->Machine);
	printf("��������:\t0x%X\n", pFileHeader->NumberOfSections);
	printf("��չͷ��С:\t0x%X\n", pFileHeader->SizeOfOptionalHeader);
	printf("ʱ���:\t\t0x%X\n", pFileHeader->TimeDateStamp);

	/*
	* ��PE�ṹ����TimeDateStamp��ʱ������׼ʱ��ת��
	* https://www.cnblogs.com/17bdw/p/6412158.html
	*/

	//gmtime_s��ʾ�ļ�����ʱ�䣬������Ҫ����1900������Ҫ����1��СʱҪ����8
	struct tm test_gmtime_s;
	errno_t err = gmtime_s(&test_gmtime_s, (time_t*)&pFileHeader->TimeDateStamp);
	printf("ʱ��ת��1:\t%d�� %d�� %d�� ", test_gmtime_s.tm_year + 1900, test_gmtime_s.tm_mon + 1, test_gmtime_s.tm_mday);
	printf("��%d %02dʱ %02d�� %02d��\n", test_gmtime_s.tm_wday, test_gmtime_s.tm_hour + 8, test_gmtime_s.tm_min, test_gmtime_s.tm_sec);
	//strftime��ʽ��ʱ����ʾ
	struct tm p;
	errno_t err1;
	err1 = gmtime_s(&p, (time_t*)&pFileHeader->TimeDateStamp);
	char s[100];
	strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", &p);
	printf_s("ʱ��ת��2\t%s\n", s);
	//	ʱ��END����
	printf("����:\t\t0x%X\n", pFileHeader->Characteristics);
	return true;
}

bool CPE::PrintOptionalHeader(PIMAGE_OPTIONAL_HEADER& pOptiHeader)
{
	printf_s("��ڵ�\t\t%X\n", pOptiHeader->AddressOfEntryPoint);
	printf_s("�����ַ\t%X\n", pOptiHeader->ImageBase);
	printf_s("�����С\t%X\n", pOptiHeader->SizeOfImage);
	printf_s("���ܴ�С\t%X\n", pOptiHeader->SizeOfCode);

	printf_s("�����ַ\t%X\n", pOptiHeader->BaseOfCode);
	printf_s("���ݻ�ַ\t%X\n", pOptiHeader->BaseOfData);
	printf_s("�����\t\t%X\n", pOptiHeader->SectionAlignment);
	printf_s("PE����\t\t%X\n", pOptiHeader->FileAlignment);
	printf_s("��־��\t\t%X", pOptiHeader->Magic);
	if (0x10B == pOptiHeader->Magic)
		cout << "\t����32λ����\n\n";
	else if (0x20B == pOptiHeader->Magic)
		cout << "\t����64λ����\n\n";
	else	cout << "\n\n";
	printf_s("��ϵͳ\t\t%X\n", pOptiHeader->Subsystem);
	printf_s("�ײ���С\t%X\n", pOptiHeader->SizeOfHeaders);
	printf_s("У���\t\t%X\n", pOptiHeader->CheckSum);
	printf_s("RVA ��\t\t%X\n", pOptiHeader->NumberOfRvaAndSizes);
	return true;
}

DWORD CPE::RvaToFoa(DWORD dwRva, bool isPrint)
{
	if (dwRva == 0) return dwRva;
	else if (dwRva == 1) return 1;
	//1 ��ȡ���α����ʼλ��
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)mFileData;
	if (nullptr == pDos)	return 0;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + mFileData);
	PIMAGE_SECTION_HEADER pHeader = IMAGE_FIRST_SECTION(pNt);
/*
typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];	//����
	union {
			DWORD   PhysicalAddress;	//NULL
			DWORD   VirtualSize;		//2[����]����û�ж���ǰ��ʵ�ʴ�С
	} Misc;
	DWORD   VirtualAddress;			//3�����RVA
	DWORD   SizeOfRawData;			//4����δ�С	+ RVA =��β
	DWORD   PointerToRawData;		//5�����FOA	��FOA-��RVA=Ŀ��FOA-Ŀ��RVA
	DWORD   PointerToRelocations;	//6 û�� �����ض�λ��Ϣ���ļ�ƫ��
	DWORD   PointerToLinenumbers;	//7 û�� COFF�к���Ϣ��ƫ��
	WORD    NumberOfRelocations;	//8 û�� �ض�λ��Ϣ����Ŀ
	WORD    NumberOfLinenumbers;	//9 û�� �к���Ϣ����Ŀ��ֻ��COFF�к�ʱ������
	DWORD   Characteristics;		//10����������ԣ��ɶ�дִ��
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
*/
	if (dwRva < pNt->OptionalHeader.SizeOfHeaders)
	{
		return dwRva;
	}
	for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		//�öεĵ�һ���ֽڵĵ�ַ�������ص��ڴ���ʱ���������ӳ��⡣
		DWORD &dwSectionRva = pHeader[i].VirtualAddress;
		//�����βRva����		[�γ�ʼֵ]	+	[�������ѳ�ʼ���Ĵ�С]
		DWORD dwSectionEndRva = dwSectionRva + pHeader[i].SizeOfRawData;
		//ָ��COFF�ļ��ڵ�һҳ���ļ�ָ�롣
		DWORD &dwSectionFOA = pHeader[i].PointerToRawData;
		/*
		Ŀ��FOA=Ŀ��RVA-��RVA+��FOA
		���Σ���FOA-��RVA=Ŀ��FOA-Ŀ��RVA
		ԭ�ͣ�ԭʼVA - Ĭ�ϻ�ַ   =  ��VA -  �»�ַ
		*/
		DWORD dwFOA = dwRva - dwSectionRva + dwSectionFOA;
		if (isPrint)
			printf_s("Ŀ��\tRva=0x%Xh\t���0x%X\tԴFOA=%04X\t��ͷ=%X\t��β=%X\t��%s\n",
				dwRva, dwFOA, dwSectionFOA, dwSectionRva, dwSectionEndRva, pHeader[i].Name);
		if (dwRva >= dwSectionRva && dwRva < dwSectionEndRva)
		{
			if(isPrint)
				printf_s("Ŀ��\t�б������\n");
			return dwFOA;
		}
	}
	return 0;
}
