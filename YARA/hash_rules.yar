rule MALWARE_Akira_Filecryptor_Teafortwo_MD5
{
  meta:
    description = "Known Akira/filecryptor sample teafortwo.exe by MD5"
    ioc_type = "md5"
    sample = "teafortwo.exe"
    confidence = "high"

  strings:
    // md5("ae454079c93a7a1ce276756b9d62d196") in little-endian 16 bytes
    $md5 = { 96 D1 62 9D 6B 75 76 E2 1C 7A A7 C9 79 40 45 AE }

  condition:
    filesize > 50KB and filesize < 50MB and hash.md5(0, filesize) == "ae454079c93a7a1ce276756b9d62d196"
}

rule MALWARE_HavocC2_BackupTool_SHA256
{
  meta:
    description = "Known Havoc C2 persistence binary backupTool.exe by SHA256"
    ioc_type = "sha256"
    sample = "backupTool.exe"
    confidence = "high"

  condition:
    filesize > 50KB and filesize < 50MB and
    hash.sha256(0, filesize) == "c9a38fa7b619a1bc814fcf381a940245dfa8d24ae51e7ec22f9461eae288ede3"
}

rule MALWARE_BrowserExtension_SHA1
{
  meta:
    description = "Malicious browser extension package/content by SHA1"
    ioc_type = "sha1"
    sample = "extension.zip (or extracted payload)"
    confidence = "high_if_hash_matches_correct_object"

  condition:
    filesize > 1KB and filesize < 200MB and
    hash.sha1(0, filesize) == "0b7fc40a15b5f471261dd76a16c6acd20e055373"
}
