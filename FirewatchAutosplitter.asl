state("Firewatch") {}

startup {
 
    refreshRate = 0.5;

	vars.ReadPointers = (Func<Process, IntPtr, int[], IntPtr>)((proc, basePtr, offsets) => {
        IntPtr ptr = basePtr;

        for (int i = 0; i < offsets.Count() - 1; i++)
        {
			//print("Read from: " + (ptr+offsets[i]).ToString("X16"));

            if (!proc.ReadPointer(ptr + offsets[i], true, out ptr)
				|| ptr == IntPtr.Zero)
            {
				return IntPtr.Zero;
            }

			//print("Result: " + ptr.ToString("X16"));
         }

         ptr = ptr + offsets[offsets.Count() - 1];
         return ptr;
    });

    vars.TryFindSigs = (Func<Process, long, bool>)((proc, baseAddress) => {   
       
		//vgLoadManager
        IntPtr scanOffset = vars.SigScan(proc, 0, "55 48 8B EC 56 48 83 EC 08 48 8B F1 48 8B 0C 25 ?? ?? ?? ?? 33 D2 48 83 EC 20 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF D3 48 83 C4 20 85 C0 0F 84 5D 00 00 00 48 8B 0C 25 ?? ?? ?? ?? 48 8B D6 48 83 EC 20 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF D3 48 83 C4 20 85 C0 0F 84 35 00 00 00 48 8B CE 48 83 EC 20 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF D3 48 83 C4 20 48 8B C8 48 83 EC 20 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF D3 48 83 C4 20 E9 4D 00 00 00 B8 ?? ?? ?? ?? 48 89 30 48 8B CE 48 83 EC 20 49 BB");
       
        if (scanOffset == IntPtr.Zero) {
			return false;
		}

		print("Scan offset loadManager: " + scanOffset.ToString("X16"));

        vars.vgLoadManagerPtr = (IntPtr)(proc.ReadValue<long>((IntPtr)(baseAddress + (long)scanOffset + 0x37)) & 0xFFFFFFFF); //Initial ptr is the only one that's 4 bytes (32 bit)

        if (vars.vgLoadManagerPtr == IntPtr.Zero) {
			return false;
        }

		//vgEventManager98
		scanOffset = vars.SigScan(proc, 0, "55 48 8B EC 56 48 83 EC 18 48 8B F1 48 8B 0C 25 ?? ?? ?? ?? 33 D2 48 83 EC 20 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF D3 48 83 C4 20 85 C0 0F 84 5D 00 00 00 48 8B 0C 25 ?? ?? ?? ?? 48 8B D6 48 83 EC 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 FF D3 48 83 C4 20 85 C0 0F 84 35 00 00 00 48 8B CE 48 83 EC 20 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF D3 48 83 C4 20 48 8B C8 48 83 EC 20 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF D3 48 83 C4 20 E9 63 01 00 00 B8 ?? ?? ?? ?? 48 89 30 48 83 EC 20 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF D3 48 83 C4 20 85 C0 0F 84 51 00 00 00 48 8B CE 48 83 EC 20");
       
        if (scanOffset == IntPtr.Zero) {
			return false;
		}

		print("Scan offset eventManager: " + scanOffset.ToString("X16"));

        vars.vgEventManagerPtr = (IntPtr)(proc.ReadValue<long>((IntPtr)(baseAddress + (long)scanOffset + 0x37)) & 0xFFFFFFFF); //Initial ptr is the only one that's 4 bytes (32 bit)

        if (vars.vgEventManagerPtr == IntPtr.Zero) {
			return false;
        }
		
        return true;
    });

	vars.ResetFactsListVars = (Func<bool>)(() => {
		vars.currentTimeListOffset = 0;
		vars.currentDayListOffset = 0;

		vars.factsListIntegrityCount = -1;
		vars.factsListIntegrityFirstElementPtr = 0;

		return true;
	});

	vars.VerifyFactsIntegrity = (Func<Process, IntPtr, bool>)((proc, globalBlackboardFactsListPtr) => {
       
		int factsListCount = proc.ReadValue<int>((IntPtr)((long)globalBlackboardFactsListPtr + 0x18));
		vars.factsListLastCount = factsListCount;

		//Count can be 0, means we are on the menu
		if (factsListCount < 1) {
			return false;
		}

		//Confirm it still matches the last size we have on record
		if (vars.factsListIntegrityCount == -1) {
			return false;
		}

		if (factsListCount != vars.factsListIntegrityCount) {
			print("List size changed, reset!");
			return false;
		}

		long factsListDataPtr = proc.ReadValue<long>((IntPtr)((long)globalBlackboardFactsListPtr + 0x10));
		long firstFactEntryPtr = proc.ReadValue<long>((IntPtr)(factsListDataPtr + 0x20));

		//Confirm it still matches the last first list entry we have on record
		if (firstFactEntryPtr == 0 || firstFactEntryPtr != vars.factsListIntegrityFirstElementPtr) {
			print("List contents changed, reset!");
			return false;
		}
		
        return true;
    });

	vars.TryFindFacts = (Func<Process, IntPtr, bool>)((proc, globalBlackboardFactsListPtr) => {
       
		int factsListCount = proc.ReadValue<int>((IntPtr)((long)globalBlackboardFactsListPtr + 0x18));
		//print("global facts count:" + factsListCount.ToString());

		//Count can be 0, wait until it is not for init
		if (factsListCount < 1) {
			return false;
		}

		//Notes:
		//Count is exactly 51 and the final fact is RadioDisabled with a value of 1 as soon as you see the "You see Julia" text during the intro
		//After intro count rises to 117 and the quest and tasks are filled in as booleans
		//In real game count reaches over 500

		long factsListDataPtr = proc.ReadValue<long>((IntPtr)((long)globalBlackboardFactsListPtr + 0x10));

		int foundFacts = 0;
		int requiredFacts = 2;

		//Loop all entries
		for (int i = 0; i < factsListCount; i++)
		{
			int factEntryOffset = 0x20 + (i * 8);
			long factEntryPtr = proc.ReadValue<long>((IntPtr)(factsListDataPtr + factEntryOffset));

			long factEntryNamePtr = proc.ReadValue<long>((IntPtr)(factEntryPtr + 0x10));
			int factEntryNameLength = proc.ReadValue<int>((IntPtr)(factEntryNamePtr + 0x10));
			string factEntryName = proc.ReadString((IntPtr)(factEntryNamePtr + 0x14), factEntryNameLength * 2);

			//Debug output
			//float factEntryValue = proc.ReadValue<float>((IntPtr)(factEntryPtr + 0x18));
			//print("Fact Offset: " + i.ToString() + " Fact Name: " + factEntryName + " Fact Value: " + factEntryValue.ToString());

			if (factEntryName == "CurrentTime") {
				print("Found current time");
				foundFacts++;
				vars.currentTimeListOffset = factEntryOffset;
			}
			else if (factEntryName == "CurrentDay") {
				print("Found current day");
				foundFacts++;
				vars.currentDayListOffset = factEntryOffset;
			}

			if (foundFacts == requiredFacts) {
				break;
			}
		}

        if (foundFacts == requiredFacts) {
			vars.factsListIntegrityCount = factsListCount;
			
			long firstFactEntryPtr = proc.ReadValue<long>((IntPtr)(factsListDataPtr + 0x20));
			vars.factsListIntegrityFirstElementPtr = firstFactEntryPtr;

			return true;
		}

		return false;
    });

    vars.SigScan = (Func<Process, int, string, IntPtr>)((proc, offset, signature) => {
        var target = new SigScanTarget(offset, signature);
        IntPtr result = IntPtr.Zero;
        foreach (var page in proc.MemoryPages(true)) {
            var scanner = new SignatureScanner(proc, page.BaseAddress, (int)page.RegionSize);
            if ((result = scanner.Scan(target)) != IntPtr.Zero) {
                break;
            }
        }

        return result;
    });
}

init { 
	vars.vgLoadManagerPtr = (IntPtr)0;
	vars.vgEventManagerPtr = (IntPtr)0;
	vars.currentTimeListOffset = (int)0;
	vars.currentDayListOffset = (int)0;
	
	vars.factsListLastCount = (int)0;
	vars.factsListIntegrityCount = (int)-1;
	vars.factsListIntegrityFirstElementPtr = (long)0;

    if (!vars.TryFindSigs(game, 0x0)) {
        throw new Exception("[Autosplitter] Game memory not yet initialized!");
    } else {
        refreshRate = 60;
    }
}

update {
    
	IntPtr currLoadManagerPtr = vars.ReadPointers(game, vars.vgLoadManagerPtr, new int[] {0x00, 0x00});

	//Read all loadManager values
	if (currLoadManagerPtr != IntPtr.Zero) {
		current.loadState = memory.ReadValue<byte>(currLoadManagerPtr + 0x68);
		//current.loadProgress = memory.ReadValue<float>(currLoadManagerPtr + 0x64); //Not used atm

		//print("Load Manager Ptr: " + vars.vgLoadManagerPtr.ToString("X16") + " Out: " + currLoadManagerPtr.ToString("X16"));
	}
	else {
		print("Load Manager ptr no longer valid! " + vars.vgLoadManagerPtr.ToString("X16"));
	}
  
    IntPtr currEventManagerPtr = vars.ReadPointers(game, vars.vgEventManagerPtr, new int[] {0x00, 0x00});

	//Read all eventManager values
	if (currEventManagerPtr != IntPtr.Zero) {

		//Find global facts list
		IntPtr globalBlackboardFactsListPtr = vars.ReadPointers(game, currEventManagerPtr, new int[] {0x20, 0x18, 0x00});

		if (!vars.VerifyFactsIntegrity(game, globalBlackboardFactsListPtr)) {
			vars.ResetFactsListVars();
		}

		//Try to resolve fact list if still needed
		if (vars.factsListIntegrityCount == -1) {
			if (!vars.TryFindFacts(game, globalBlackboardFactsListPtr)) {
				vars.ResetFactsListVars();
			}
		}

		current.eventDayValue = memory.ReadValue<float>(currEventManagerPtr + 0x98); //Still used for resets
		//current.eventIndex = memory.ReadValue<int>(currEventManagerPtr + 0x9C); //Not used atm

		if (vars.currentDayListOffset != 0) {
			IntPtr currentDayValuePtr = vars.ReadPointers(game, globalBlackboardFactsListPtr, new int[] {0x10, vars.currentDayListOffset, 0x18});
			current.eventFactCurrentDay = memory.ReadValue<float>(currentDayValuePtr);
		}

		if (vars.currentTimeListOffset != 0) {
			IntPtr currentTimeValuePtr = vars.ReadPointers(game, globalBlackboardFactsListPtr, new int[] {0x10, vars.currentTimeListOffset, 0x18});
			current.eventFactCurrentTime = memory.ReadValue<float>(currentTimeValuePtr);
		}
	}
	else {
		print("Event Manager ptr no longer valid! " + vars.vgEventManagerPtr.ToString("X16"));
		vars.ResetFactsListVars();
	}
}

start {
}

reset {
	bool isReset = current.eventDayValue == -1 && vars.factsListLastCount == 0;

	//Reset current values on reset as the list can not be initialized on the menu
	if (isReset) {
		current.eventFactCurrentDay = -1;
		current.eventFactCurrentTime = -1;
	}

    return isReset;
}

split {
	//Note: Check CurrentTime > 21.9 for Day 77 Night Time
	return current.eventFactCurrentDay != -1 && ((current.eventFactCurrentDay > old.eventFactCurrentDay) || (current.eventFactCurrentDay == 77 && current.eventFactCurrentTime > 21.9f && old.eventFactCurrentTime <= 21.9f));
}

isLoading {
    return current.loadState != 7;
}

exit {
    refreshRate = 0.5;
}

shutdown {
}