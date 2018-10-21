

typedef struct _ProcessList
{
	PVOID NextItem;
	PVOID pEPROCESS;
} TProcessList, *PProcessList;


BOOLEAN IsAdded(PProcessList List, PVOID pEPROCESS)
{
	PProcessList Item = List;
	while (Item)
	{
		if (pEPROCESS == Item->pEPROCESS) return TRUE;
		Item = (PProcessList)Item->NextItem;
	}
	return FALSE;
}

void DelItem(PProcessList *List, PVOID pEPROCESS)
{
	PProcessList Item = *List;
	PProcessList Prev = NULL;
	while (Item)
	{
	    if (pEPROCESS == Item->pEPROCESS)
		{
	    	if (Prev) Prev->NextItem = Item->NextItem; else *List =(PProcessList) Item->NextItem;
			ExFreePool(Item);
			return;
		}
		Prev = Item;
		Item =(PProcessList) Item->NextItem;
	}
	return;
}


void FreePointers(PProcessList List)
{
    PProcessList Item = List;
	PVOID Mem;
	while (Item)
	{
		Mem = Item;	
		Item =(PProcessList) Item->NextItem;
		ExFreePool(Mem);
	}
	return;
}


void AddItem(PProcessList *List, PVOID pEPROCESS)
{
	PProcessList wNewItem;
	wNewItem =(PProcessList) ExAllocatePool(NonPagedPool, sizeof(TProcessList));
	wNewItem->NextItem = *List;
	*List = wNewItem;
	wNewItem->pEPROCESS = pEPROCESS;
	return;
}