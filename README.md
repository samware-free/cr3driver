ADD TO USERMODE SELF LEAK

drv.h coms


ADD OT USERMODE

  if (mem::find_driver()) {
            
            SPOOF_CALL(printf)(_("\nDriver was initialized!\n"));
        }
        else {
            SPOOF_CALL(printf)(_("\nDriver was not initialized!\n"));
           
            SPOOF_CALL(Sleep)(10000);
            SPOOF_CALL(exit)(0);
        }

 const wchar_t* processName = L"EasyAntiCheat_EOS.exe";
        if (IsProcessRunning(processName)) {
            std::wcout << L"The process is running." << std::endl;
            EAC = true;
        }
        else {
            std::wcout << L"The process is not running." << std::endl;
            EAC = false;
        }

        if (!mem::CR3())
        {
            SPOOF_CALL(printf)(_("\nCR3 not good!...\n"));
            SPOOF_CALL(Sleep)(-1);
        }
