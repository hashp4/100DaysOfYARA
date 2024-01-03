rule SUS_Keylogging {
   meta:
      description = "Detection of potential keylogging Windows malware"
      author = "hashp4"
      version = "1.0"
      date = "2024-01-03"
      reference1 = "https://attack.mitre.org/techniques/T1056/001/"
      reference2 = "https://malapi.io/"
      DaysofYARA = "3/100"

   strings:
      $api_call1 = "SetWindowsHook" fullword ascii 
      $api_call2 = "GetKeyState" fullword ascii
      $api_call3 = "GetAsyncKeyState" fullword ascii
      $api_call4 = "GetKeyboardState" fullword ascii
      $api_call5 = "GetRawInputData" fullword ascii
      $api_call6 = "GetMessageA" fullword ascii
      $api_call7 = "MapVirtualKeyA" fullword ascii
      $api_call8 = "MapVirtualKeyExA" fullword ascii

      $window_name1 = "GetForegroundWindow" fullword ascii
      $window_name2 = "GetWindowDC" fullword ascii

      $persistance1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
      $persistance2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" fullword ascii

   condition:
      uint16(0) == 0x5A4D and //MZ header detection
      2 of ($api_call*) and
      any of ($window_name*) and
      any of ($persistance*) and
      filesize < 1000KB
}