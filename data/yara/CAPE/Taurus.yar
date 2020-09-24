rule Taurus {
    meta:
      author = "ditekshen"
      description = "Taurus infostealer payload"
      cape_type = "Taurus payload"
    strings:
      $s1 = "t.me/taurus_se" ascii
      $s2 = "rus_seller@explo" ascii
      $s3 = "/c timeout /t 3  & del /f /q" ascii
      $s4 = "MyAwesomePrefix" ascii

      $txt1 = "LogInfo.txt" fullword ascii
      $txt2 = "Information.txt" fullword ascii
      $txt3 = "General\\passwords.txt" fullword ascii
      $txt4 = "General\\forms.txt" fullword ascii
      $txt5 = "General\\cards.txt" fullword ascii
      $txt6 = "Installed Software.txt" fullword ascii
      $txt7 = "Crypto Wallets\\WalletInfo.txt" fullword ascii
      $txt8 = "cookies.txt" fullword ascii

      $url1 = "/cfg/" wide
      $url2 = "/loader/complete/" wide
      $url3 = "/log/" wide
      $url4 = "/dlls/" wide

      $upat = /\.exe;;;\d;\d;\d\]\|\[http/
    condition:
      3 of ($s*) or (6 of ($txt*) and 2 of ($s*)) or ($upat and 1 of ($s*) and 2 of ($txt*)) or (all of ($url*) and (2 of ($txt*) or 1 of ($s*)))
}
