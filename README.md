ADD TO USERMODE SELF LEAK



drv.h driver coms


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


 you will have to change codes       
#define code_rDTB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x91, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x92, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x93, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_get_guarded_region CTL_CODE(FILE_DEVICE_UNKNOWN, 0x94, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_move CTL_CODE(FILE_DEVICE_UNKNOWN, 0x95, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_spoof CTL_CODE(FILE_DEVICE_UNKNOWN, 0x96, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_unlock CTL_CODE(FILE_DEVICE_UNKNOWN, 0x97, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_security 0x76

make sure you make them the same in usermode and driver 




        
