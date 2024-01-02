rule SUS_Process_Hollowing {
   meta:
      description = "Detection of process hollowing"
      author = "hashp4"
      version = "1.0"
      date = "2024-01-02"
      reference = "https://attack.mitre.org/techniques/T1055/012/"
      DaysofYARA = "2/100"

   strings:
      $api_call1 = "CreateProcess" fullword ascii 
      $api_call2 = "VirtualAlloc" fullword ascii
      $api_call3 = "VirtualAllocEx" fullword ascii
      $api_call4 = "VirtualProtect" fullword ascii
      $api_call5 = "WriteProcessMemory" fullword ascii
      $api_call6 = "SetThreadContext" fullword ascii
      $api_call7 = "ResumeThread" fullword ascii
      $api_call8 = "SuspendThread" fullword ascii
      $api_call9 = "CreateRemoteThread" fullword ascii

   condition:
      uint16(0) == 0x5A4D and //MZ header detection
      2 of ($api_call*) and
      filesize < 1000KB
}