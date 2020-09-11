rule AgentTeslaV3 {
    meta:
      author = "ditekshen"
      description = "AgentTeslaV3 infostealer payload"
      cape_type = "AgentTeslaV3 payload"
    strings:
      $s1 = "get_kbok" fullword ascii
      $s2 = "get_CHoo" fullword ascii
      $s3 = "set_passwordIsSet" fullword ascii
      $s4 = "get_enableLog" fullword ascii
      $s5 = "bot%telegramapi%" wide
      $s6 = "KillTorProcess" fullword ascii 
      $s7 = "GetMozilla" ascii
      $s8 = "torbrowser" wide
      $s9 = "%chatid%" wide
      $s10 = "logins" fullword wide
      $s11 = "credential" fullword wide
      $s12 = "AccountConfiguration+" wide
      $s13 = "<a.+?href\\s*=\\s*([\"'])(?<href>.+?)\\1[^>]*>" fullword wide
    condition:
      uint16(0) == 0x5a4d and 8 of them
}
