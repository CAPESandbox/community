rule UNK_DeadDrop_Overlord_Wallet_Agent_Experimental
{
    meta:
        description = "ELF Overlord wallet-agent marker conjunction; static hunting only"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/12-framework-and-collection-boundary/"
        source_note = "https://github.com/KrasForge/unk-deaddrop-companion/blob/main/docs/actual-artifact-validation.md"
        status = "experimental"
        scope = "marker conjunction; not campaign attribution"
        license = "MIT"
    strings:
        $elf = { 7F 45 4C 46 }
        $framework = "overlord-client/cmd/agent" ascii wide
        $env = "OVERLORD_SERVER_RAW" ascii wide
        $wallet1 = "OVERLORD_COMPANY_WALLET_EP" ascii wide
        $wallet2 = "X-Company-Wallet-Client-Id" ascii wide
        $wallet3 = "/api/company-wallet/upload" ascii wide
    condition:
        filesize < 64MB and $elf at 0 and $framework and $env and 2 of ($wallet*)
}

rule UNK_DeadDrop_ClickFix_Stage1_Dropper_Experimental
{
    meta:
        description = "ClickFix first-stage dropper with recovered installer telemetry and launcher guards"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "https://github.com/KrasForge/unk-deaddrop-companion/blob/main/docs/actual-artifact-validation.md"
        status = "experimental"
        scope = "small Windows or Unix first-stage files; names and lure brands are not required"
        license = "MIT"
        validation = "https://github.com/KrasForge/unk-deaddrop-companion/blob/main/docs/actual-artifact-validation.md"
    strings:
        $telemetry = "guard-launcher-result" ascii wide
        $platform = "X-Guard-Platform" ascii wide
        $guard = "deepfake_guard" ascii wide
        $detached = "NVDG_DETACHED" ascii wide
        $hidden = "NVDG_HIDDEN" ascii wide
    condition:
        filesize < 1MB and $telemetry and 1 of ($detached, $hidden) and
        1 of ($platform, $guard)
}

rule UNK_DeadDrop_ClickFix_Stage2_Installer_Experimental
{
    meta:
        description = "ClickFix second-stage installer or a first-stage file carrying its encoded body"
        author = "UNK_DeadDrop research contributors"
        date = "2026-10-26"
        evidence_cutoff = "2026-07-24"
        reference = "https://krasforge.github.io/UNK_DeadDrop/articles/01-clickfix-clipboard-manipulation/"
        source_note = "https://github.com/KrasForge/unk-deaddrop-companion/blob/main/docs/actual-artifact-validation.md"
        status = "experimental"
        scope = "plaintext installer or a small wrapper embedding the known base64 anchors"
        license = "MIT"
        validation = "https://github.com/KrasForge/unk-deaddrop-companion/blob/main/docs/actual-artifact-validation.md"
    strings:
        $work = "deepfake_guard_work" ascii wide
        $fallback = "GUARD_STORE_FALLBACK" ascii wide
        $runner = "deepfake_guard_run.sh" ascii wide
        $log = "guard-install-log" ascii wide
        $encoded_guard = "ZGVlcGZha2VfZ3VhcmQ" ascii
        $encoded_fallback = "R1VBUkRfU1RPUkVfRkFMTEJBQ0s" ascii
    condition:
        filesize < 2MB and (2 of ($work, $fallback, $runner, $log) or
                            all of ($encoded_guard, $encoded_fallback))
}
