rule MAL_RANSOM_Wannacry {
   meta:
      description = "YARA Rule for WannaCry detection"
      author = "hashp4 (inspired by Florian Roth)"
      date = "2023-11-27"
      hash = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
   strings:
      $string1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $string2 = "tasksche.exe" fullword ascii
      $string3 = "attrib +h ." fullword ascii
      $string5 = "WNcry@2ol7" fullword ascii
      $string6 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
      $string8 = "C:\\%s\\qeriuwjhrf" fullword ascii

      $unc1 = "\\\\192.168.56.20\\IPC$" fullword wide
      $unc2 = "\\\\172.16.99.5\\IPC$" fullword wide
   condition:
      ( 1 of ($string*) and 1 of ($unc*) ) and filesize < 10000KB
}