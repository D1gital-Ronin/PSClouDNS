# PSClouDNS

PowerShell client for the ClouDNS API — a focused, minimal wrapper.

Repository: https://github.com/D1gital-Ronin/cloudns-posh-api/

This repository contains a PowerShell module that provides convenience functions to interact with ClouDNS: list zones, manage records, SOA operations, DNSSEC checks and more. The module is intentionally lightweight and keeps credentials out of code files.

## Quickstart

1. Open PowerShell (PowerShell 5.1+ or PowerShell 7+ recommended).
2. Import the module (from the module folder):

Clone the repository locally and import the module from the cloned folder:

```powershell
# Clone the repository (if not already present)
git clone https://github.com/D1gital-Ronin/cloudns-posh-api.git

# Import the module from the repo (adjust path if you cloned elsewhere)
Import-Module .\cloudns-posh-api\PSClouDNS\PSClouDNS.psm1 -Force
```

3. Set credentials in-memory for the session (recommended):

```powershell
# Use your ClouDNS Auth ID and password. For local workspace testing the real
# test credentials are documented in `W:\readme.md` (do NOT commit those to
# source control). In this README we'll show a generic example with placeholders:
$pwd = ConvertTo-SecureString -String '<YOUR_CLOUDNS_PASSWORD>' -AsPlainText -Force
Set-ClouDNSCredentials -AuthId '<YOUR_CLOUDNS_AUTH_ID>' -Password $pwd
```

4. Test login:

```powershell
Get-ClouDNSLogin
```

## Exposed cmdlets (current)

The module uses a single-dash naming convention: VerbClouDNSNoun (e.g. Get-ClouDNSLogin).

- Convert-To-SecureString (helper)
- Get-ClouDNSAuthParams (internal)
- Set-ClouDNSCredentials
- Invoke-ClouDNSApi (low-level request wrapper)
- Get-ClouDNSLogin
- Get-ClouDNSZones
- Get-ClouDNSRecords
- Get-ClouDNSRecord
- Invoke-ClouDNSCreateRecord
- Invoke-ClouDNSUpdateRecord
- Invoke-ClouDNSDeleteRecord
- Invoke-ClouDNSActivateRecord
- Invoke-ClouDNSDeactivateRecord
- Invoke-ClouDNSToggleRecord
- Invoke-ClouDNSExportRecords
- Invoke-ClouDNSGetDynamicUrl
- Invoke-ClouDNSTransfer
- Invoke-ClouDNSCopyRecords
- Get-ClouDNSZoneList
- Get-ClouDNSZonePageCount
- New-ClouDNSZone
- Get-ClouDNSZone
- Update-ClouDNSZone
- Invoke-ClouDNSActivateZone
- Invoke-ClouDNSDeactivateZone
- Invoke-ClouDNSToggleZone
- Remove-ClouDNSZone
- Get-ClouDNSZoneStats
- Test-ClouDNSDnssecAvailable
- Invoke-ClouDNSDnssecActivate
- Invoke-ClouDNSDnssecDeactivate
- Get-ClouDNSDnssecDsRecords
- Test-ClouDNSIsUpdated
- Get-ClouDNSSoa
- Update-ClouDNSSoa

## Cmdlet reference

This section provides a short description and a minimal usage example for each exposed cmdlet. All examples assume you've already set credentials in-session with `Set-ClouDNSCredentials`.

- Convert-To-SecureString
	- Description: Helper that converts a plaintext password to a SecureString suitable for `Set-ClouDNSCredentials`.
	- Example:

		```powershell
		$pwd = Convert-To-SecureString -String '<YOUR_PLAIN_PASSWORD>'
		```

- Get-ClouDNSAuthParams (internal)
	- Description: Internal helper that builds the auth parameters (auth-id and password) required by ClouDNS API calls. Typically used by other cmdlets; not required directly by users.
	- Example: (internal) No public example; used by `Invoke-ClouDNSApi`.

- Set-ClouDNSCredentials
	- Description: Store your ClouDNS Auth ID and password (as SecureString) in-session for the current PowerShell run. Credentials are not persisted to disk by the module.
	- Example:

		```powershell
		$pwd = Convert-To-SecureString -String '<PASSWORD>' -AsPlainText -Force
		Set-ClouDNSCredentials -AuthId '<AUTH_ID>' -Password $pwd
		```

- Invoke-ClouDNSApi
	- Description: Low-level HTTP wrapper used by the module to call ClouDNS endpoints. Accepts method, endpoint and parameters. Returns parsed JSON results.
	- Example:

		```powershell
		Invoke-ClouDNSApi -Method 'POST' -Endpoint 'dns/add-record.json' -Params @{ 'domain-name' = 'example.com'; 'record-type' = 'A'; 'record' = '203.0.113.5' }
		```

- Get-ClouDNSLogin
	- Description: Validate the stored session credentials by calling the ClouDNS login endpoint. Returns information about the authenticated account.
	- Example:

		```powershell
		Get-ClouDNSLogin
		```

- Get-ClouDNSZones
	- Description: Retrieve a list of zones (domains) associated with the account. Supports pagination and filtering parameters.
	- Example:

		```powershell
		Get-ClouDNSZones -Page 1 -RowsPerPage 50
		```

- Get-ClouDNSRecords
	- Description: List DNS records for a given domain. Supports filtering by type and paging.
	- Example:

		```powershell
		Get-ClouDNSRecords -DomainName 'example.com' -RecordType 'A'
		```

- Get-ClouDNSRecord
	- Description: Retrieve a single record by its `RecordId` for the given domain.
	- Example:

		```powershell
		Get-ClouDNSRecord -DomainName 'example.com' -RecordId 12345
		```

- Invoke-ClouDNSCreateRecord
	- Description: Create a new DNS record for a domain. Use `HostLabel` for the host/hostname part.
	- Example:

		```powershell
		Invoke-ClouDNSCreateRecord -DomainName 'example.com' -RecordType 'A' -RecordValue '203.0.113.5' -HostLabel 'www' -TTL 3600
		```

- Invoke-ClouDNSUpdateRecord
	- Description: Update an existing record. Use `-Patch` with a hash table of fields to modify, or provide full fields for replacement.
	- Example:

		```powershell
		$params = @{ 'record' = '203.0.113.7'; 'ttl' = 3600 }
		Invoke-ClouDNSUpdateRecord -DomainName 'example.com' -RecordId 12345 -RecordType 'A' -Patch -Params $params
		```

- Invoke-ClouDNSDeleteRecord
	- Description: Remove a DNS record from a domain using its `RecordId`.
	- Example:

		```powershell
		Invoke-ClouDNSDeleteRecord -DomainName 'example.com' -RecordId 12345
		```

- Invoke-ClouDNSActivateRecord / Invoke-ClouDNSDeactivateRecord / Invoke-ClouDNSToggleRecord
	- Description: Convenience helpers to enable/disable or toggle the active state of a record.
	- Example:

		```powershell
		Invoke-ClouDNSDeactivateRecord -DomainName 'example.com' -RecordId 12345
		Invoke-ClouDNSActivateRecord -DomainName 'example.com' -RecordId 12345
		Invoke-ClouDNSToggleRecord -DomainName 'example.com' -RecordId 12345
		```

- Invoke-ClouDNSExportRecords
	- Description: Export all records for a domain in the provider's export format.
	- Example:

		```powershell
		Invoke-ClouDNSExportRecords -DomainName 'example.com'
		```

- Invoke-ClouDNSGetDynamicUrl
	- Description: Get a dynamic DNS update URL for a specific host under a domain. Useful for dynamic IP updates.
	- Example:

		```powershell
		Invoke-ClouDNSGetDynamicUrl -DomainName 'example.com' -HostLabel 'home'
		```

- Invoke-ClouDNSTransfer
	- Description: Initiate a domain transfer or related transfer operations supported by the API.
	- Example:

		```powershell
		Invoke-ClouDNSTransfer -DomainName 'example.com' -Params @{ 'target' = 'other-account' }
		```

- Invoke-ClouDNSCopyRecords
	- Description: Copy records from one domain to another within the account.
	- Example:

		```powershell
		Invoke-ClouDNSCopyRecords -Source 'old.example.com' -Destination 'example.com'
		```

- Get-ClouDNSZoneList
	- Description: Convenience wrapper to retrieve paginated lists of zones (similar to `Get-ClouDNSZones`).
	- Example:

		```powershell
		Get-ClouDNSZoneList -Page 1 -RowsPerPage 20
		```

- Get-ClouDNSZonePageCount
	- Description: Return the total number of pages available for zones given a rows-per-page value.
	- Example:

		```powershell
		Get-ClouDNSZonePageCount -RowsPerPage 50
		```

- New-ClouDNSZone
	- Description: Create a new DNS zone/domain under the account.
	- Example:

		```powershell
		New-ClouDNSZone -DomainName 'new-example.com' -ZoneType 'master'
		```

- Get-ClouDNSZone
	- Description: Retrieve detailed information about a specific zone.
	- Example:

		```powershell
		Get-ClouDNSZone -DomainName 'example.com'
		```

- Update-ClouDNSZone
	- Description: Modify properties of a zone (for example, reverse lookup settings or other metadata supported by the API).
	- Example:

		```powershell
		Update-ClouDNSZone -DomainName 'example.com' -Params @{ 'some-flag' = 'value' }
		```

- Invoke-ClouDNSActivateZone / Invoke-ClouDNSDeactivateZone / Invoke-ClouDNSToggleZone
	- Description: Activate, deactivate, or toggle an entire zone's active state.
	- Example:

		```powershell
		Invoke-ClouDNSDeactivateZone -DomainName 'example.com'
		Invoke-ClouDNSActivateZone -DomainName 'example.com'
		Invoke-ClouDNSToggleZone -DomainName 'example.com'
		```

- Remove-ClouDNSZone
	- Description: Delete a zone from the account. This is destructive and typically irreversible—use with caution.
	- Example:

		```powershell
		Remove-ClouDNSZone -DomainName 'old-example.com'
		```

- Get-ClouDNSZoneStats
	- Description: Retrieve usage or analytics-style statistics for a zone (where supported by the API).
	- Example:

		```powershell
		Get-ClouDNSZoneStats -DomainName 'example.com'
		```

- Test-ClouDNSDnssecAvailable
	- Description: Check whether DNSSEC is available for a domain on the provider side.
	- Example:

		```powershell
		Test-ClouDNSDnssecAvailable -DomainName 'example.com'
		```

- Invoke-ClouDNSDnssecActivate / Invoke-ClouDNSDnssecDeactivate
	- Description: Enable or disable DNSSEC for a domain.
	- Example:

		```powershell
		Invoke-ClouDNSDnssecActivate -DomainName 'example.com'
		Invoke-ClouDNSDnssecDeactivate -DomainName 'example.com'
		```

- Get-ClouDNSDnssecDsRecords
	- Description: Retrieve the DS records for a domain to publish to the parent registrar when DNSSEC is enabled.
	- Example:

		```powershell
		Get-ClouDNSDnssecDsRecords -DomainName 'example.com'
		```

- Test-ClouDNSIsUpdated
	- Description: Helper that checks whether a domain's records (or a specific record) have been updated recently. Useful in tests and automation.
	- Example:

		```powershell
		Test-ClouDNSIsUpdated -DomainName 'example.com' -RecordId 12345
		```

- Get-ClouDNSSoa
	- Description: Retrieve the SOA (Start of Authority) record for a domain.
	- Example:

		```powershell
		Get-ClouDNSSoa -DomainName 'example.com'
		```

- Update-ClouDNSSoa
	- Description: Update the SOA record for a domain (primary nameserver, admin contact, timers).
	- Example:

		```powershell
		Update-ClouDNSSoa -DomainName 'example.com' -PrimaryNs 'ns1.example.net' -AdminMail 'hostmaster@example.com' -Refresh 3600 -Retry 180 -Expire 1209600 -DefaultTtl 3600
		```

## Usage examples

All examples assume you have set credentials in the session with `Set-ClouDNSCredentials`.

List zones (paginated):

```powershell
Get-ClouDNSZoneList -Page 1 -RowsPerPage 20
```

List records for a domain:

```powershell
Get-ClouDNSRecords -DomainName 'example.com'
```

Create an A record (note: HostLabel parameter for the host part):

```powershell
Invoke-ClouDNSCreateRecord -DomainName 'example.com' -RecordType 'A' -RecordValue '203.0.113.5' -HostLabel 'www' -TTL 3600
```

Update a record (patch):

```powershell
$params = @{ 'record' = '203.0.113.7'; 'ttl' = 3600 }
Invoke-ClouDNSUpdateRecord -DomainName 'example.com' -RecordId 12345 -RecordType 'A' -Patch -Params $params
```

Delete a record:

```powershell
Invoke-ClouDNSDeleteRecord -DomainName 'example.com' -RecordId 12345
```

SOA operations:

```powershell
Get-ClouDNSSoa -DomainName 'example.com'
Update-ClouDNSSoa -DomainName 'example.com' -PrimaryNs 'ns1.example.net' -AdminMail 'hostmaster@example.com' -Refresh 3600 -Retry 180 -Expire 1209600 -DefaultTtl 3600
```

DNSSEC:

```powershell
Test-ClouDNSDnssecAvailable -DomainName 'example.com'
Get-ClouDNSDnssecDsRecords -DomainName 'example.com'
```

## Testing

This repository includes a small Pester test file `tests/PSClouDNS.Tests.ps1` with basic smoke tests. These tests talk to the live ClouDNS API and require valid credentials and network access.

Run the tests locally:

```powershell
# Ensure Pester is available
Install-Module Pester -Force -Scope CurrentUser

# From the repository root (after cloning), import the module manifest or module file:
Import-Module .\PSClouDNS\PSClouDNS.psd1 -Force

# Run the module tests (this will call the live API and requires valid credentials):
Invoke-Pester .\PSClouDNS\tests\PSClouDNS.Tests.ps1
```

## Implementation notes

- The module intentionally stores credentials in-session only via `Set-ClouDNSCredentials`.
- `Invoke-ClouDNSApi` formats requests as application/x-www-form-urlencoded and returns parsed JSON objects from `Invoke-RestMethod`.
- The parameter `HostLabel` is used instead of `Host` or `Hostname` to avoid collision with PowerShell automatic variables.

## Contribution

If you want to contribute:

- Open an issue describing the feature or bug.
- Send a pull request against the `main` branch. Keep changes small and include tests.

## Next improvements (planned)

- Add an ApiResponse-style wrapper to standardize return values and error handling.
- Expand Pester coverage to include create/update/delete flows and validation error cases.
- Add comment-based help for every exported function (currently only a subset have help headers).

---

If you'd like, I can now run the Pester tests and fix any issues introduced by the rename and documentation updates. Which would you prefer next: run tests, add ApiResponse wrapper, or expand tests? 
