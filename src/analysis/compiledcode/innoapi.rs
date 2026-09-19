//! Lookup table mapping Inno-registered PascalScript external
//! names to short descriptions.
//!
//! Inno's `Setup.exe` registers ~200 functions / procedures that
//! `[Code]` scripts can call. The canonical inventory lives in
//! `research/issrc/Projects/Src/Shared.ScriptFunc.pas` -
//! `ScriptFuncTables[sftScriptDlg]`, `[sftCommonFunc]`,
//! `[sftPathFunc]`, `[sftInstall]`, `[sftInstFunc]`,
//! `[sftMainFunc]`, etc. - plus the `DelphiScriptFuncTable` of
//! pre-registered runtime helpers.
//!
//! This table covers the security-relevant subset analysts care
//! about most: registry mutations, command execution, file
//! operations, network downloads, and privilege checks. It is
//! curated rather than exhaustive - adding remaining categories
//! is mechanical (transcribe the names + write one-liner
//! descriptions) and tracked separately. Lookups are by exact
//! ASCII name, case-sensitive (PascalScript identifiers
//! collide-detect on hash, but the wire form preserves the
//! author's casing).

/// One row of the lookup table - name + short, single-line
/// description.
type Row = (&'static str, &'static str);

/// Curated mapping of Inno API name → analyst-friendly summary.
///
/// Grouped by category (registry, process exec, file ops, network,
/// privilege, path constants, hashing, INI, logging). Lookups go
/// through [`inno_api_description`], a case-insensitive linear
/// scan; the `no_duplicate_keys` test catches accidental
/// case-insensitive collisions.
pub const INNO_API: &[Row] = &[
    (
        "RegDeleteKeyIfEmpty",
        "Deletes a registry key only if it has no remaining values or subkeys.",
    ),
    (
        "RegDeleteKeyIncludingSubkeys",
        "Recursively deletes a registry key and all of its subkeys.",
    ),
    (
        "RegDeleteValue",
        "Deletes a single named value from a registry key.",
    ),
    (
        "RegGetSubkeyNames",
        "Enumerates the immediate subkey names under a registry key.",
    ),
    (
        "RegGetValueNames",
        "Enumerates the value names under a registry key.",
    ),
    ("RegKeyExists", "Tests whether a registry key exists."),
    (
        "RegQueryBinaryValue",
        "Reads a REG_BINARY value into an AnsiString buffer.",
    ),
    (
        "RegQueryDWordValue",
        "Reads a REG_DWORD value into a Cardinal.",
    ),
    (
        "RegQueryMultiStringValue",
        "Reads a REG_MULTI_SZ value into a string.",
    ),
    (
        "RegQueryStringValue",
        "Reads a REG_SZ / REG_EXPAND_SZ value into a string.",
    ),
    (
        "RegValueExists",
        "Tests whether a named value exists under a registry key.",
    ),
    ("RegWriteBinaryValue", "Writes a REG_BINARY value."),
    ("RegWriteDWordValue", "Writes a REG_DWORD value."),
    (
        "RegWriteExpandStringValue",
        "Writes a REG_EXPAND_SZ value (envvar-expandable string).",
    ),
    (
        "RegWriteMultiStringValue",
        "Writes a REG_MULTI_SZ value (multi-string list).",
    ),
    (
        "RegWriteStringValue",
        "Writes a REG_SZ value (plain string).",
    ),
    (
        "Exec",
        "Spawns a child process with full command line + working directory + show-cmd, blocking until exit.",
    ),
    (
        "ExecAsOriginalUser",
        "Same as `Exec` but runs under the original (non-elevated) user when Setup is elevated.",
    ),
    (
        "ExecAndCaptureOutput",
        "Runs a process and captures stdout / stderr into AnsiString buffers.",
    ),
    (
        "ExecAndLogOutput",
        "Runs a process and pipes its stdout to Setup's log file.",
    ),
    (
        "ShellExec",
        "Wraps `ShellExecuteEx` - opens a file or URL via the shell's verb dispatcher.",
    ),
    (
        "ShellExecAsOriginalUser",
        "`ShellExec` under the original (non-elevated) user.",
    ),
    (
        "CopyFile",
        "Copies a file from `ExistingFile` to `NewFile`, optionally failing if the destination exists.",
    ),
    ("DeleteFile", "Deletes a file."),
    (
        "DelTree",
        "Recursively deletes a directory tree (toggleable: include files / include subdirs).",
    ),
    ("DirExists", "Tests whether a directory exists."),
    ("FileCopy", "Older alias for `CopyFile`."),
    ("FileExists", "Tests whether a file exists."),
    (
        "FileOrDirExists",
        "Tests whether a file OR directory exists at the given path.",
    ),
    (
        "FileSize",
        "Returns the size of a file in bytes (Integer-truncated; see `FileSize64`).",
    ),
    ("FileSize64", "Returns the size of a file as Int64."),
    ("RenameFile", "Renames a file."),
    (
        "ForceDirectories",
        "Creates a directory and any missing parent directories.",
    ),
    (
        "CreateDir",
        "Creates a single directory (parents must exist).",
    ),
    ("RemoveDir", "Removes an empty directory."),
    (
        "ExtractTemporaryFile",
        "Extracts a `[Files]` entry into Setup's temporary directory.",
    ),
    (
        "ExtractTemporaryFiles",
        "Extracts every `[Files]` entry matching a pattern into Setup's temp dir.",
    ),
    (
        "DownloadTemporaryFile",
        "Downloads a URL into Setup's temp dir, verified by SHA-256.",
    ),
    (
        "DownloadTemporaryFileWithISSigVerify",
        "Downloads a URL and verifies via Inno's signature (.issig) format.",
    ),
    (
        "DownloadTemporaryFileSize",
        "HEAD request - returns the Content-Length of a remote resource.",
    ),
    (
        "DownloadTemporaryFileDate",
        "HEAD request - returns the Last-Modified header of a remote resource.",
    ),
    (
        "SetDownloadCredentials",
        "Stores HTTP basic-auth credentials for subsequent download calls.",
    ),
    (
        "IsAdmin",
        "Returns True when Setup is running with administrative privileges.",
    ),
    ("IsAdminLoggedOn", "Older alias for `IsAdmin`."),
    (
        "IsAdminInstallMode",
        "Returns True when Setup is running in admin install mode (per-machine).",
    ),
    (
        "IsPowerUserLoggedOn",
        "Returns True when the current user is a member of the Power Users group.",
    ),
    (
        "UsingWinNT",
        "Returns True on Windows NT family OSes (effectively always True today).",
    ),
    (
        "GetWindowsVersionEx",
        "Fills a `TWindowsVersion` record with the running OS version.",
    ),
    ("GetUILanguage", "Returns the user's UI-language LCID."),
    (
        "ExpandConstant",
        "Expands `{constants}` like `{app}`, `{tmp}`, `{userdocs}` in a path.",
    ),
    (
        "ExpandConstantEx",
        "`ExpandConstant` with custom `{custom}` constant resolver.",
    ),
    ("GetEnv", "Reads an environment variable."),
    (
        "GetCmdTail",
        "Returns the command-line arguments Setup itself was launched with.",
    ),
    (
        "ParamCount",
        "Returns the count of command-line parameters Setup received.",
    ),
    ("ParamStr", "Returns the Nth command-line parameter."),
    (
        "GetMD5OfFile",
        "Returns the lowercase-hex MD5 of a file's contents.",
    ),
    (
        "GetMD5OfString",
        "Returns the lowercase-hex MD5 of an AnsiString.",
    ),
    (
        "GetSHA1OfFile",
        "Returns the lowercase-hex SHA-1 of a file's contents.",
    ),
    (
        "GetSHA1OfString",
        "Returns the lowercase-hex SHA-1 of an AnsiString.",
    ),
    (
        "GetSHA256OfFile",
        "Returns the lowercase-hex SHA-256 of a file's contents.",
    ),
    (
        "GetSHA256OfString",
        "Returns the lowercase-hex SHA-256 of an AnsiString.",
    ),
    (
        "DeleteIniEntry",
        "Removes a named entry from a section in an INI file.",
    ),
    (
        "DeleteIniSection",
        "Removes an entire section from an INI file.",
    ),
    ("GetIniBool", "Reads a Boolean value from an INI file."),
    (
        "GetIniInt",
        "Reads a LongInt value from an INI file with min/max clamping.",
    ),
    ("GetIniString", "Reads a string value from an INI file."),
    (
        "IniKeyExists",
        "Tests whether a key exists in an INI section.",
    ),
    (
        "IsIniSectionEmpty",
        "Tests whether an INI section has any entries.",
    ),
    ("SetIniBool", "Writes a Boolean value to an INI file."),
    ("SetIniInt", "Writes a LongInt value to an INI file."),
    ("SetIniString", "Writes a string value to an INI file."),
    ("Log", "Writes a line to Setup's log file."),
    ("LogFmt", "Formatted variant of `Log` (Format-style)."),
    (
        "MsgBox",
        "Shows a message box and returns the IDOK / IDCANCEL / etc. result.",
    ),
    (
        "SuppressibleMsgBox",
        "`MsgBox` that respects Setup's `/SUPPRESSMSGBOXES` flag.",
    ),
    (
        "WizardForm",
        "Returns the running `TWizardForm` instance - exposes the live install UI.",
    ),
];

/// Looks up `name` in [`INNO_API`] via binary search and returns
/// the short description if found.
///
/// Returns `None` for names not in the table - this includes both
/// genuinely-unknown imports and the long tail of registered
/// helpers that aren't worth a description for analyst purposes
/// (sorting, string-mangling, math, etc.).
pub fn inno_api_description(name: &str) -> Option<&'static str> {
    // Lookup is **case-insensitive ASCII**. PascalScript hashes
    // identifiers via `MakeHash` (`uPSUtils.pas:701-708`), which
    // is itself case-sensitive - but Inno's own registration path
    // upper-cases names before they hit the wire, so a `[Code]`
    // import for `ShellExec` materializes as `SHELLEXEC`. The
    // table is hand-keyed mixed-case for readability; the
    // comparison folds both sides to upper.
    INNO_API
        .iter()
        .find(|&&(n, _)| n.eq_ignore_ascii_case(name))
        .map(|&(_, desc)| desc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_duplicate_keys() {
        // Lookup is case-insensitive linear scan; duplicate keys
        // would give the wrong description silently. Catch
        // that here.
        for (i, (name_a, _)) in INNO_API.iter().enumerate() {
            for (name_b, _) in INNO_API.iter().skip(i + 1) {
                assert!(
                    !name_a.eq_ignore_ascii_case(name_b),
                    "duplicate INNO_API key: {name_a:?} vs {name_b:?}",
                );
            }
        }
    }

    #[test]
    fn looks_up_known_name() {
        let desc = inno_api_description("RegWriteStringValue").unwrap();
        assert!(desc.contains("REG_SZ"));
    }

    #[test]
    fn lookup_is_case_insensitive() {
        // PascalScript wire form is upper-cased.
        assert!(inno_api_description("SHELLEXEC").is_some());
        assert!(inno_api_description("shellexec").is_some());
        assert!(inno_api_description("ShellExec").is_some());
    }

    #[test]
    fn returns_none_for_unknown() {
        assert!(inno_api_description("ThisIsNotARealApi").is_none());
    }
}
