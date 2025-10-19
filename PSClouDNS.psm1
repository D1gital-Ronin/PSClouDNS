<#
.SYNOPSIS
    PowerShell module for interacting with the ClouDNS API.
.DESCRIPTION
    Lightweight wrapper for common ClouDNS API calls ported from a Python client.
#>

<#
.SYNOPSIS
    Create a SecureString from a plaintext string (convenience helper).
.DESCRIPTION
    Returns a SecureString created from the provided plaintext. Useful
    for quickly converting a test password to a SecureString for
    `Set-ClouDNSCredentials` when running examples or tests.
.PARAMETER Plain
    Plaintext string to convert to SecureString.
.OUTPUTS
    System.Security.SecureString
.EXAMPLE
    $s = Convert-To-SecureString 'secret'
#>
function Convert-To-SecureString([string]$Plain) {
    if (-not $Plain) { return $null }
    # Convenience wrapper that creates a SecureString from plaintext.
    return ConvertTo-SecureString -String $Plain -AsPlainText -Force
}

<#
.SYNOPSIS
    Build the authentication parameters for API calls.
.DESCRIPTION
    Reads module-scoped credentials set by `Set-ClouDNSCredentials` and
    returns a hashtable with 'auth-id' and 'auth-password'. The function
    converts a SecureString password to plain text only in-memory for
    submission to the API.
.OUTPUTS
    Hashtable
#>
function Get-ClouDNSAuthParams {
    <#
    .SYNOPSIS
        Build authentication parameters for ClouDNS API calls.
    .DESCRIPTION
        Reads credentials from the global module credential store if available
        otherwise throws. For local testing credentials are documented in the
        module docs but are not stored in files.
    .OUTPUTS
        Hashtable
    #>
    param()

    if (-not $script:ClouDNS_AuthId -or -not $script:ClouDNS_AuthPassword) {
        throw "ClouDNS credentials not configured. Use Set-ClouDNS-Credentials or set the module-scoped variables." 
    }

    # Convert SecureString password to plain text for API submission
    $plainPassword = $script:ClouDNS_AuthPassword
    if ($plainPassword -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($plainPassword)
        try { $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    return @{
        'auth-id'       = $script:ClouDNS_AuthId
        'auth-password' = $plainPassword
    }
}

<#
.SYNOPSIS
    Store ClouDNS credentials in-session for the current module.
.DESCRIPTION
    Saves the provided AuthId and SecureString Password as module-scoped
    variables. These values are kept only in memory for the current
    PowerShell session and are not persisted to disk by the module.
.PARAMETER AuthId
    The ClouDNS authentication id (string or integer).
.PARAMETER Password
    The ClouDNS password as a SecureString.
.EXAMPLE
    $pwd = ConvertTo-SecureString -String 'pass' -AsPlainText -Force
    Set-ClouDNSCredentials -AuthId '45874' -Password $pwd
#>
function Set-ClouDNSCredentials {
    <#
    .SYNOPSIS
        Set module-scoped credentials for ClouDNS API calls (in-memory only).
    .DESCRIPTION
        Stores the provided auth-id and password as module-scoped variables
        for the current PowerShell session. These are not persisted to disk by
        the module.
    .PARAMETER AuthId
        ClouDNS auth id (integer or string)
    .PARAMETER Password
        ClouDNS auth password
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AuthId,
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Password
    )

    # Store credentials in module-scoped variables for the session only.
    # These are not written to disk by this module.
    $script:ClouDNS_AuthId = $AuthId
    $script:ClouDNS_AuthPassword = $Password

    return $true
}

<#
.SYNOPSIS
    Low-level helper to perform GET or POST requests to the ClouDNS API.
.DESCRIPTION
    Builds authentication parameters, merges user-supplied parameters,
    and performs an HTTP request to the specified endpoint. Results are
    returned as parsed JSON objects from Invoke-RestMethod.
.PARAMETER Method
    HTTP method: 'GET' or 'POST'.
.PARAMETER Endpoint
    API endpoint path (example: '/dns/list-zones.json').
.PARAMETER Params
    Hashtable of query/body parameters to send to the API.
.OUTPUTS
    PSCustomObject / hashtable representing parsed JSON response.
.EXAMPLE
    Invoke-ClouDNSApi -Method GET -Endpoint '/dns/login.json'
#>
function Invoke-ClouDNSApi {
    <#
    .SYNOPSIS
        Perform a ClouDNS API GET or POST request and return parsed JSON.
    .PARAMETER Method
        GET or POST
    .PARAMETER Endpoint
        API endpoint path (e.g. '/dns/list-zones.json')
    .PARAMETER Params
        Hashtable of query parameters
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [Parameter(Mandatory = $false)]
        [hashtable]$Params = @{}
    )

    $base = 'https://api.cloudns.net'
    $url = "$base$Endpoint"

    $auth = Get-ClouDNSAuthParams
    $queryParams = @{}
    $auth.Keys | ForEach-Object { $queryParams[$_] = $auth[$_] }
    foreach ($k in $Params.Keys) { $queryParams[$k] = $Params[$k] }

    # Helper: Convert a hashtable of params into an application/x-www-form-urlencoded
    # query string. Arrays are joined with commas to match the Python client behavior.
    function Convert-ClouDNS-ParamsToQueryString([hashtable]$p) {
        $pairs = @()
        foreach ($kk in $p.Keys) {
            $val = $p[$kk]
            if ($null -eq $val) { continue }
            if ($val -is [System.Array]) { $val = ($val -join ',') }
            $pairs += ([uri]::EscapeDataString($kk) + '=' + [uri]::EscapeDataString([string]$val))
        }
        return ($pairs -join '&')
    }

    try {
        if ($Method -eq 'GET') {
            $qs = Convert-ClouDNS-ParamsToQueryString -p $queryParams
            $fullUrl = if ($qs) { "$url`?$qs" } else { $url }
            $resp = Invoke-RestMethod -Uri $fullUrl -Method Get -ErrorAction Stop
        }
        else {
            $qs = Convert-ClouDNS-ParamsToQueryString -p $queryParams
            $resp = Invoke-RestMethod -Uri $url -Method Post -Body $qs -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
        }

        return $resp
    }
    catch {
        throw "API request failed: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Retrieve login/status information from ClouDNS.
.DESCRIPTION
    Calls the /dns/login.json endpoint and returns the parsed response.
.OUTPUTS
    Parsed JSON object from the API.
.EXAMPLE
    Get-ClouDNSLogin
#>
function Get-ClouDNSLogin {
    <#
    .SYNOPSIS
        Returns the login status using available credentials.
    .EXAMPLE
        Get-ClouDNS-Login
    #>
    [CmdletBinding()]
    param()

    # Returns a parsed JSON object from the /dns/login.json endpoint.
    return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/login.json'
}

<#
.SYNOPSIS
    Retrieve a paginated list of zones.
.PARAMETER Page
    Page number to request (default 1).
.PARAMETER RowsPerPage
    Number of rows per page (default 10).
.PARAMETER Search
    Optional search string to filter zones.
.PARAMETER GroupId
    Optional group ID to filter zones.
.EXAMPLE
    Get-ClouDNSZones -Page 1 -RowsPerPage 20
#>
function Get-ClouDNSZones {
    [CmdletBinding()]
    param(
        [int]$Page = 1,
        [int]$RowsPerPage = 10,
        [string]$Search = '',
        [string]$GroupId = ''
    )

    $params = @{
        'page'          = $Page
        'rows-per-page' = $RowsPerPage
    }
    if ($Search) { $params['search'] = $Search }
    if ($GroupId) { $params['group-id'] = $GroupId }

    # Returns a paginated list of zones.
    return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/list-zones.json' -Params $params
}

<#
.SYNOPSIS
    List DNS records for a domain.
.PARAMETER DomainName
    The domain to list records for (example: 'example.com').
.PARAMETER HostLabel
    Optional host label (subdomain) to filter by, e.g. 'www'.
.PARAMETER Type
    Optional DNS record type to filter by (e.g. 'A', 'CNAME').
.EXAMPLE
    Get-ClouDNSRecords -DomainName 'example.com'
#>
function Get-ClouDNSRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DomainName,
        [string]$HostLabel = '',
        [string]$Type = ''
    )

    $params = @{
        'domain-name' = $DomainName
    }
    if ($HostLabel -ne '') { $params['host'] = @{ 'value' = $HostLabel; 'optional' = $true } }
    if ($Type -ne '') { $params['type'] = @{ 'value' = $Type; 'optional' = $true } }

    # The ClouDNS API expects flat keys, convert nested values
    $flattened = @{}
    foreach ($k in $params.Keys) {
        $v = $params[$k]
        if ($v -is [hashtable]) { $flattened[$k] = $v['value'] }
        else { $flattened[$k] = $v }
    }

    return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/records.json' -Params $flattened
}

## Module exports are controlled by PSClouDNS.psd1 (FunctionsToExport = '*')

### Validation functions (ported from python validation.py)

<#
.SYNOPSIS
    Validate whether a string appears to be a domain name.
.PARAMETER Value
    The string value to validate.
.OUTPUTS
    Boolean
#>
function Test-ClouDNSIsDomainName {
    param([string]$Value)
    if (-not $Value) { return $false }
    $regex = '^(?=.{1,255}$)((?=[a-z0-9-]{1,63}\.)' + '(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$'
    return [bool]([regex]::IsMatch($Value, $regex))
}

<#
.SYNOPSIS
    Validate whether a string is an email-like value.
.PARAMETER Value
    The string value to validate.
.OUTPUTS
    Boolean
#>
function Test-ClouDNSIsEmail {
    param([string]$Value)
    if (-not $Value) { return $false }
    $regex = '(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
    return [bool]([regex]::IsMatch($Value, $regex))
}

<#
.SYNOPSIS
    Simple IPv4 address format validator.
.PARAMETER Value
    IPv4 string to validate.
.OUTPUTS
    Boolean
#>
function Test-ClouDNSIsIPv4 {
    param([string]$Value)
    if (-not $Value) { return $false }
    $octets = $Value -split '\.' | Where-Object { $_ -match '^[0-9]+$' -and [int]$_ -ge 0 -and [int]$_ -le 255 }
    return ($octets.Count -eq 4)
}

<#
.SYNOPSIS
    Simple IPv6 address presence validator.
.PARAMETER Value
    IPv6 string to validate.
.OUTPUTS
    Boolean
#>
function Test-ClouDNSIsIPv6 {
    param([string]$Value)
    if (-not $Value) { return $false }
    try {
        $parts = $Value -split ':'
        $count = ($parts | Where-Object { $_ -ne '' }).Count
        return ($count -ge 3)
    }
    catch { return $false }
}

<#
.SYNOPSIS
    Determine whether a value can be cast to integer.
.PARAMETER Value
    Value to test.
.OUTPUTS
    Boolean
#>
function Test-ClouDNSIsInt {
    param([Parameter(Mandatory = $true)]$Value)
    try { [int]$Value | Out-Null; return $true } catch { return $false }
}

<#
.SYNOPSIS
    Validate DNS record type against supported set.
.PARAMETER Value
    Record type string to validate (e.g. 'A', 'MX').
.OUTPUTS
    Boolean
#>
function Test-ClouDNSIsRecordType {
    param([string]$Value)
    if (-not $Value) { return $false }
    $valid = 'A', 'AAAA', 'MX', 'CNAME', 'TXT', 'SPF', 'NS', 'SRV', 'WR', 'RP', 'SSHFP', 'ALIAS', 'CAA', 'NAPTR', 'PTR'
    return ($valid -contains $Value.ToUpper())
}

<#
.SYNOPSIS
    Validate zone type string.
.PARAMETER Value
    Zone type to validate (e.g. 'master', 'slave').
.OUTPUTS
    Boolean
#>
function Test-ClouDNSIsZoneType {
    param([string]$Value)
    if (-not $Value) { return $false }
    $valid = 'master', 'slave', 'parked', 'geodns', 'domain', 'reverse'
    return ($valid -contains $Value.ToLower())
}

<#
.SYNOPSIS
    Validate TTL values or common TTL strings.
.PARAMETER Value
    TTL value (int or recognized string).
.OUTPUTS
    Boolean
#>
function Test-ClouDNSIsTTL {
    param([Parameter(Mandatory = $true)][Object]$Value)
    $ttls = @(60, 300, 900, 1800, 3600, 21600, 43200, 86400, 172800, 259200, 604800, 1209600, 2592000)
    if ($Value -is [string]) { $v = $Value.ToLower() } else { $v = $Value }
    return ($ttls -contains [int]$v) -or @('1 minute', '5 minutes', '15 minutes', '30 minutes', '1 hour', '6 hours', '12 hours', '1 day', '2 days', '3 days', '1 week', '2 weeks', '1 month') -contains $v
}

### Parameter generation utilities

<#
.SYNOPSIS
    Build a parameters hashtable for creating or updating DNS records.
.PARAMETER DomainName
    The zone domain name (example: 'example.com').
.PARAMETER RecordType
    DNS record type (A, CNAME, MX, etc.).
.PARAMETER HostLabel
    Host label for the record (use empty string for root).
.PARAMETER Record
    Record value (IP, target name, text, etc.).
.PARAMETER TTL
    Time-to-live in seconds.
.PARAMETER RecordId
    Optional record id when updating.
.PARAMETER ValidateAs
    Validation mode for the record value (default 'valid').
.PARAMETER Extra
    Additional key/value pairs to include in the request.
.OUTPUTS
    Hashtable ready to be flattened for API submission.
#>
function New-ClouDNSRecordParameters {
    param(
        [Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $true)][string]$RecordType,
        [string]$HostLabel = '',
        [string]$Record = '',
        [int]$TTL = 3600,
        [int]$RecordId = $null,
        [string]$ValidateAs = 'valid',
        [hashtable]$Extra
    )

    if (-not (Test-ClouDNSIsRecordType -Value $RecordType)) { throw "Invalid record type: $RecordType" }

    $params = @{
        'domain-name' = $DomainName
        'host'        = @{ 'value' = $HostLabel; 'optional' = $true }
        'ttl'         = $TTL
        'record'      = @{ 'value' = $Record; 'validate_as' = $ValidateAs }
    }
    if ($RecordType) { $params['record-type'] = $RecordType }
    if ($RecordId) { $params['record-id'] = $RecordId }
    if ($Extra) { foreach ($k in $Extra.Keys) { $params[$k] = $Extra[$k] } }

    return $params
}

<#
.SYNOPSIS
    Create a DNS record in a zone.
.PARAMETER DomainName
    Zone domain name.
.PARAMETER RecordType
    DNS record type.
.PARAMETER RecordValue
    Value for the record.
.PARAMETER HostLabel
    Host label (subdomain), use '' for root.
.PARAMETER TTL
    TTL in seconds.
.PARAMETER Extra
    Additional parameters as hashtable.
.EXAMPLE
    Invoke-ClouDNSCreateRecord -DomainName 'example.com' -RecordType 'A' -RecordValue '1.2.3.4' -HostLabel 'www'
#>
function Invoke-ClouDNSCreateRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $true)][string]$RecordType,
        [Parameter(Mandatory = $true)][string]$RecordValue,
        [string]$HostLabel = '',
        [int]$TTL = 3600,
        [hashtable]$Extra = @{}
    )

    $params = New-ClouDNSRecordParameters -DomainName $DomainName -RecordType $RecordType -HostLabel $HostLabel -Record $RecordValue -TTL $TTL -Extra $Extra
    # Flatten nested values for API
    $flat = @{ }
    foreach ($k in $params.Keys) {
        $v = $params[$k]
        if ($v -is [hashtable]) { $flat[$k] = $v['value'] } else { $flat[$k] = $v }
    }

    return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/add-record.json' -Params $flat
}

<#
.SYNOPSIS
    Retrieve a single DNS record by id from a zone.
.PARAMETER DomainName
    Zone domain name.
.PARAMETER RecordId
    Numeric record id.
.OUTPUTS
    Record object or throws when not found.
#>
function Get-ClouDNSRecord {
    param(
        [Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $true)][int]$RecordId
    )
    $resp = Get-ClouDNSRecords -DomainName $DomainName
    if ($null -eq $resp) { throw 'No response from API' }
    if ($resp -is [hashtable] -or $resp -is [System.Management.Automation.PSCustomObject]) {
        if ($resp.ContainsKey([string]$RecordId)) {
            return $resp[[string]$RecordId]
        }
        else { throw "Record $RecordId not found in zone $DomainName" }
    }
    return $resp
}

<#
.SYNOPSIS
    Update an existing DNS record (full replace or patch).
.PARAMETER DomainName
    Zone domain name.
.PARAMETER RecordId
    Numeric record id to update.
.PARAMETER RecordType
    Record type (used for validation).
.PARAMETER Patch
    Switch to indicate patching (merge provided params with existing).
.PARAMETER Params
    Hashtable of parameters to send.
.EXAMPLE
    Invoke-ClouDNSUpdateRecord -DomainName 'example.com' -RecordId 123 -RecordType 'A' -Patch -Params @{ 'record' = '1.2.3.5' }
#>
function Invoke-ClouDNSUpdateRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $true)][int]$RecordId,
        [Parameter(Mandatory = $true)][string]$RecordType,
        [switch]$Patch,
        [hashtable]$Params
    )

    if ($Patch) {
        $existing = Get-ClouDNSRecord -DomainName $DomainName -RecordId $RecordId
        if ($existing -is [hashtable] -or $existing -is [System.Management.Automation.PSCustomObject]) {
            foreach ($k in $existing.Keys) { if (-not $Params.ContainsKey($k)) { $Params[$k] = $existing[$k] } }
        }
    }

    # Ensure record-type isn't sent
    if ($Params.ContainsKey('record-type')) { $Params.Remove('record-type') }

    $Params['domain-name'] = $DomainName
    $Params['record-id'] = $RecordId

    return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/mod-record.json' -Params $Params
}
<#
.SYNOPSIS
    Activate a DNS record (set status = 1).
.PARAMETER DomainName
    Zone domain name.
.PARAMETER RecordId
    Numeric record id.
#>
function Invoke-ClouDNSActivateRecord { param([string]$DomainName, [int]$RecordId) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/change-record-status.json' -Params @{ 'domain-name' = $DomainName; 'record-id' = $RecordId; 'status' = 1 } }

<#
.SYNOPSIS
    Deactivate a DNS record (set status = 0).
.PARAMETER DomainName
    Zone domain name.
.PARAMETER RecordId
    Numeric record id.
#>
function Invoke-ClouDNSDeactivateRecord { param([string]$DomainName, [int]$RecordId) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/change-record-status.json' -Params @{ 'domain-name' = $DomainName; 'record-id' = $RecordId; 'status' = 0 } }

<#
.SYNOPSIS
    Toggle the status of a DNS record.
.PARAMETER DomainName
    Zone domain name.
.PARAMETER RecordId
    Numeric record id.
#>
function Invoke-ClouDNSToggleRecord { param([string]$DomainName, [int]$RecordId) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/change-record-status.json' -Params @{ 'domain-name' = $DomainName; 'record-id' = $RecordId } }

<#
.SYNOPSIS
    Delete a DNS record by id.
.PARAMETER DomainName
    Zone domain name.
.PARAMETER RecordId
    Numeric record id.
#>
function Invoke-ClouDNSDeleteRecord { param([string]$DomainName, [int]$RecordId) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/delete-record.json' -Params @{ 'domain-name' = $DomainName; 'record-id' = $RecordId } }

<#
.SYNOPSIS
    Export records for a domain (export format from API).
.PARAMETER DomainName
    Zone domain name.
#>
function Invoke-ClouDNSExportRecords { param([string]$DomainName) return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/records-export.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Get a dynamic URL for a dynamic DNS record.
.PARAMETER DomainName
    Zone domain name.
.PARAMETER RecordId
    Numeric record id.
#>
function Invoke-ClouDNSGetDynamicUrl { param([string]$DomainName, [int]$RecordId) return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/get-dynamic-url.json' -Params @{ 'domain-name' = $DomainName; 'record-id' = $RecordId } }

<#
.SYNOPSIS
    Trigger AXFR transfer/import from a server for a domain.
.PARAMETER DomainName
    Zone domain name.
.PARAMETER Server
    Remote server to request the AXFR from.
#>
function Invoke-ClouDNSTransfer { param([string]$DomainName, [string]$Server) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/axfr-import.json' -Params @{ 'domain-name' = $DomainName; 'server' = $Server } }

<#
.SYNOPSIS
    Copy records from another domain into the specified domain.
.PARAMETER DomainName
    Destination domain name.
.PARAMETER FromDomain
    Source domain to copy records from.
.PARAMETER DeleteCurrent
    When set, delete current records before copying.
#>
function Invoke-ClouDNSCopyRecords { param([string]$DomainName, [string]$FromDomain, [switch]$DeleteCurrent) return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/copy-records.json' -Params @{ 'domain-name' = $DomainName; 'from-domain' = $FromDomain; 'delete-current-records' = (if ($DeleteCurrent) { 1 } else { 0 }) } }

### Zone cmdlets

<#
.SYNOPSIS
    Convenience wrapper returning list of zones (alias to Get-ClouDNSZones with different naming).
.PARAMETER Page
    Page number.
.PARAMETER RowsPerPage
    Rows per page.
.PARAMETER Search
    Search term.
.PARAMETER GroupId
    Group identifier.
#>
function Get-ClouDNSZoneList {
    param([int]$Page = 1, [int]$RowsPerPage = 10, [string]$Search = '', [string]$GroupId = '')
    return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/list-zones.json' -Params @{ 'page' = $Page; 'rows-per-page' = $RowsPerPage; 'search' = $Search; 'group-id' = $GroupId }
}

<#
.SYNOPSIS
    Get the number of pages for zone listing given rows-per-page and optional search.
.PARAMETER RowsPerPage
    Rows per page.
.PARAMETER Search
    Search filter.
.PARAMETER GroupId
    Group identifier.
#>
function Get-ClouDNSZonePageCount { param([int]$RowsPerPage = 10, [string]$Search = '', [string]$GroupId = '') return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/get-pages-count.json' -Params @{ 'rows-per-page' = $RowsPerPage; 'search' = $Search; 'group-id' = $GroupId } }

<#
.SYNOPSIS
    Register a new zone with ClouDNS.
.PARAMETER DomainName
    Domain name to register.
.PARAMETER ZoneType
    Zone type (master, slave, etc.).
.PARAMETER NS
    Optional list of nameservers for master zones.
.PARAMETER MasterIP
    Master server IP for slave zones.
#>
function New-ClouDNSZone { param([string]$DomainName, [string]$ZoneType = 'master', [string[]]$NS = @(), [string]$MasterIP = $null) $p = @{ 'domain-name' = $DomainName; 'zone-type' = $ZoneType }; if ($ZoneType -and $ZoneType.ToLower() -eq 'slave') { $p['master-ip'] = @{ 'value' = $MasterIP; 'optional' = $false } } if ($ZoneType -and $ZoneType.ToLower() -eq 'master') { $p['ns'] = @{ 'value' = $NS; 'optional' = $true } } return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/register.json' -Params @{ 'domain-name' = $DomainName; 'zone-type' = $ZoneType; 'ns' = ($NS -join ',') } }

<#
.SYNOPSIS
    Retrieve zone information for a domain.
.PARAMETER DomainName
    Zone domain.
#>
function Get-ClouDNSZone { param([string]$DomainName) return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/get-zone-info.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Update a zone (placeholder; extend with parameters as needed).
.PARAMETER DomainName
    Zone domain to update.
#>
function Update-ClouDNSZone { param([string]$DomainName) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/update-zone.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Activate a zone.
.PARAMETER DomainName
    Zone to activate.
#>
function Invoke-ClouDNSActivateZone { param([string]$DomainName) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/change-status.json' -Params @{ 'domain-name' = $DomainName; 'status' = 1 } }

<#
.SYNOPSIS
    Deactivate a zone.
.PARAMETER DomainName
    Zone to deactivate.
#>
function Invoke-ClouDNSDeactivateZone { param([string]$DomainName) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/change-status.json' -Params @{ 'domain-name' = $DomainName; 'status' = 0 } }

<#
.SYNOPSIS
    Toggle a zone's status.
.PARAMETER DomainName
    Zone domain.
#>
function Invoke-ClouDNSToggleZone { param([string]$DomainName) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/change-status.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Remove (delete) a zone.
.PARAMETER DomainName
    Zone to remove.
#>
function Remove-ClouDNSZone { param([string]$DomainName) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/delete.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Get overall zone statistics.
#>
function Get-ClouDNSZoneStats { param() return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/get-zones-stats.json' -Params @{} }

<#
.SYNOPSIS
    Check whether DNSSEC is available for a domain.
.PARAMETER DomainName
    Zone domain.
#>
function Test-ClouDNSDnssecAvailable { param([string]$DomainName) return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/is-dnssec-available.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Activate DNSSEC for a domain.
.PARAMETER DomainName
    Zone domain.
#>
function Invoke-ClouDNSDnssecActivate { param([string]$DomainName) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/activate-dnssec.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Deactivate DNSSEC for a domain.
.PARAMETER DomainName
    Zone domain.
#>
function Invoke-ClouDNSDnssecDeactivate { param([string]$DomainName) return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/deactivate-dnssec.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Retrieve DNSSEC DS records for a domain.
.PARAMETER DomainName
    Zone domain.
#>
function Get-ClouDNSDnssecDsRecords { param([string]$DomainName) return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/get-dnssec-ds-records.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Test whether the zone is updated on ClouDNS name servers.
.PARAMETER DomainName
    Zone domain.
#>
function Test-ClouDNSIsUpdated { param([string]$DomainName) return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/is-updated.json' -Params @{ 'domain-name' = $DomainName } }

### SOA
<#
.SYNOPSIS
    Retrieve SOA details for a domain.
.PARAMETER DomainName
    Zone domain.
#>
function Get-ClouDNSSoa { param([string]$DomainName) return Invoke-ClouDNSApi -Method GET -Endpoint '/dns/soa-details.json' -Params @{ 'domain-name' = $DomainName } }

<#
.SYNOPSIS
    Update SOA parameters for a zone.
.PARAMETER DomainName
    Zone domain.
.PARAMETER PrimaryNs
    Primary nameserver.
.PARAMETER AdminMail
    Administrative email address.
.PARAMETER Refresh
    Refresh interval (seconds).
.PARAMETER Retry
    Retry interval (seconds).
.PARAMETER Expire
    Expire time (seconds).
.PARAMETER DefaultTtl
    Default TTL for records.
.PARAMETER Patch
    When set, patch behavior can be implemented.
#>
function Update-ClouDNSSoa {
    param([Parameter(Mandatory = $true)][string]$DomainName, [string]$PrimaryNs, [string]$AdminMail, [int]$Refresh, [int]$Retry, [int]$Expire, [int]$DefaultTtl, [switch]$Patch)

    $params = @{
        'domain-name' = $DomainName
        'primary-ns'  = $PrimaryNs
        'admin-mail'  = $AdminMail
        'refresh'     = $Refresh
        'retry'       = $Retry
        'expire'      = $Expire
        'default-ttl' = $DefaultTtl
    }

    return Invoke-ClouDNSApi -Method POST -Endpoint '/dns/modify-soa.json' -Params $params
}
