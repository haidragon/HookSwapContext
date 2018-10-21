#ifndef _Hash_H
#define _Hash_H

typedef unsigned char BYTE;
typedef unsigned long DWORD;
typedef unsigned short WORD;

typedef struct _DATA
{
	unsigned int threadID;
	unsigned int processID;
	BYTE *imageName;
	unsigned xlow;
	unsigned xhigh;
} DATA, *PDATA;

typedef struct _ELEMENT
{
	unsigned int threadID;
	unsigned int processID;
	unsigned xlow;
	unsigned xhigh;
	BYTE imageName[16];
} ELEMENT, *PELEMENT;

typedef struct _TWOWAY
{
	DWORD key;
	ELEMENT data;
	LIST_ENTRY linkfield;
} TWOWAY, *PTWOWAY;

typedef struct _HASHTABLE
{
	unsigned int tableSize;
	PLIST_ENTRY *pListHeads;
} HASHTABLE, *PHASHTABLE;
typedef struct _HASHTABLE HASHTABLE, *PHASHTABLE;

PHASHTABLE InitializeTable(unsigned int tableSize);
void Insert(DWORD key, PDATA pData, PHASHTABLE pHashTable);
void Remove(DWORD key, PHASHTABLE pHashTable);
void DestroyTable(PHASHTABLE pHashTable);
ULONG DumpTable(PHASHTABLE pHashTable);

#endif // _Hash_H
