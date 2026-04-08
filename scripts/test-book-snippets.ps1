param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoCheckArgs
)

$ErrorActionPreference = 'Stop'

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

$HostTriple = (cargo -vV | Select-String '^host:' | ForEach-Object {
    $_.ToString().Split()[1]
})
$BookSnippetsTargetDir = "target/book-snippets-check-$HostTriple"

if (Test-Path $BookSnippetsTargetDir) {
    Remove-Item -LiteralPath $BookSnippetsTargetDir -Recurse -Force
}

Invoke-Native cargo check -p rust-secure-systems-book --target-dir $BookSnippetsTargetDir @CargoCheckArgs
Invoke-Native mdbook test -L "$BookSnippetsTargetDir/debug/deps"
