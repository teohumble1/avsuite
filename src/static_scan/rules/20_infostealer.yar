// Infostealer indicators: the actual, current, stable filenames/folder names
// real software uses to store credentials/sessions/wallets (Chrome's "Login
// Data", Firefox's logins.json/key4.db, Telegram's tdata folder, Bitcoin
// Core's wallet.dat), combined with an access or exfiltration API -- these
// are standing software artifacts, not guessed historical campaign IOCs.

rule Infostealer_Chrome_Credential_Store_Access
{
    meta:
        description = "Chrome's actual credential SQLite database filename ('Login Data') combined with the DPAPI decrypt call used to unwrap Chrome's stored secrets"
        severity = "malicious"
    strings:
        $login_data = "Login Data" ascii
        $dpapi      = "CryptUnprotectData" ascii
    condition:
        all of them
}

rule Infostealer_Firefox_Credential_Store_Access
{
    meta:
        description = "Firefox's actual stored-logins filename (logins.json) combined with its NSS key database filename (key4.db) -- both required to decrypt Firefox-saved passwords"
        severity = "malicious"
    strings:
        $logins_json = "logins.json" nocase
        $key4db      = "key4.db" nocase
    condition:
        all of them
}

rule Infostealer_Discord_Token_Storage_Access
{
    meta:
        description = "Reference to Discord combined with the Electron 'Local Storage\\leveldb' path where Discord's desktop client persists its auth token -- moderate-confidence combo, both terms individually common enough that this is a lead rather than a certainty"
        severity = "suspicious"
    strings:
        $discord = "discord" nocase
        $leveldb_path = "Local Storage\\leveldb" nocase
    condition:
        all of them
}

rule Infostealer_Crypto_Wallet_File_Targeting
{
    meta:
        description = "Bitcoin Core's actual wallet filename (wallet.dat) or an Electrum wallet reference, combined with a file-copy API -- consistent with exfiltrating a cryptocurrency wallet file"
        severity = "malicious"
    strings:
        $wallet_dat = "wallet.dat" nocase
        $electrum   = "electrum" nocase
        $copyfile   = "CopyFileW" ascii
    condition:
        ($wallet_dat or $electrum) and $copyfile
}

rule Infostealer_Telegram_Session_Theft
{
    meta:
        description = "Telegram Desktop's actual session-data folder name (\\tdata\\) combined with directory enumeration and an outbound HTTP send call -- consistent with locating and exfiltrating a live Telegram session. Anchored with path separators after the System32 audit showed the bare word 'tdata' is a substring of common unrelated words (metadata, outdata, updata, ...) and false-positived on appraiser.dll/cdp.dll"
        severity = "malicious"
    strings:
        $tdata    = "\\tdata\\" nocase
        $findfile = "FindFirstFileW" ascii
        $exfil    = "WinHttpSendRequest" ascii
    condition:
        all of them
}

rule Infostealer_Clipboard_Crypto_Address_Swap
{
    meta:
        description = "A binary that both reads AND overwrites clipboard contents, and separately embeds a literal Bitcoin or Ethereum address pattern -- consistent with 'clipper' malware that silently swaps a copied crypto address for the attacker's own"
        severity = "suspicious"
    strings:
        $get_cb = "GetClipboardData" ascii
        $set_cb = "SetClipboardData" ascii
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $eth = /0x[a-fA-F0-9]{40}/ ascii
    condition:
        $get_cb and $set_cb and ($btc or $eth)
}
