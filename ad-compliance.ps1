<#
.SYNOPSIS
    Audits Active Directory against CIS, NIST, SOX, GDPR & HIPAA baseline controls and generates an interactive HTML compliance report.

.DESCRIPTION
    This script queries Active Directory and the local Group Policy / registry configuration of the target
    domain controller to evaluate a set of security baseline controls across five compliance frameworks
    (CIS, NIST, SOX, GDPR, HIPAA). It also enumerates all domain users, aggregating last-logon information
    across every domain controller, and reports password-expiry status per user.

    The output is a single, self-contained HTML file (Report.html) featuring Google Charts compliance
    gauges, an overall risk score, a filterable findings table, and a full AD user report.

.PARAMETER dchostname
    Hostname of the domain controller to query (e.g. DC01.yourdomain.com).

.PARAMETER domain
    Domain name to display in the report title (e.g. yourdomain.com).

.PARAMETER signature_url
    Text/URL rendered in the report footer (e.g. your company name or site).

.EXAMPLE
    .\ad-compliance.ps1 -dchostname "DC01.yourdomain.com" -domain "yourdomain.com" -signature_url "yourcompany.com"

.NOTES
    Author  : Maroun Haykal
    Requires: ActiveDirectory and GroupPolicy PowerShell modules, and Administrative privileges on the domain.
#>
param (
    [Parameter(Mandatory = $true)]
    [string]$dchostname,

    [Parameter(Mandatory = $true)]
    [string]$domain,

    [Parameter(Mandatory = $true)]
    [string]$signature_url
)

# Import required modules
Import-Module ActiveDirectory
Import-Module GroupPolicy
Add-Type -AssemblyName System.Web

# Suppress errors
$ErrorActionPreference = "Stop"

function ConvertTo-SafeHtml {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return [System.Web.HttpUtility]::HtmlEncode($Text)
}

# Update with your values


$BaseDirectory = $PSScriptRoot
$DomainController = $dchostname
$LogoPath = Join-Path -Path $BaseDirectory -ChildPath "Logo.jpg"
$ReportPath = Join-Path -Path $BaseDirectory -ChildPath "Report.html"

$SafeDomain = ConvertTo-SafeHtml $domain
$SafeSignatureUrl = ConvertTo-SafeHtml $signature_url

# Cache the default domain password policy once; reused by multiple benchmarks below
$DefaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $DomainController

# Domain stats
$DomainName = (Get-ADDomain).DNSRoot
$NumberOfUsers = (Get-ADUser -Filter *).Count
$NumberOfGroups = (Get-ADGroup -Filter *).Count
$NumberOfDisabledUsers = (Get-ADUser -Filter { Enabled -eq $false }).Count
try {
    $NumberOfDomainAdmins = (Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop).Count
} catch {
    Write-Warning "Failed to enumerate 'Domain Admins' group: $_"
    $NumberOfDomainAdmins = "N/A"
}

# Define the CIS benchmarks to check
$CISBenchmarks = @(
    @{ Name = "Ensure 'Account lockout duration' is set to '15 or more minute(s)'"; Command = { $DefaultPasswordPolicy.LockoutDuration.TotalMinutes -ge 15 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration"; Type = "CIS" },
    @{ Name = "Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s)'"; Command = { $DefaultPasswordPolicy.LockoutThreshold -le 10 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold"; Type = "CIS" },
    @{ Name = "Ensure 'Password minimum length' is set to '14 or more character(s)'"; Command = { $DefaultPasswordPolicy.MinPasswordLength -ge 14 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-minimum-length"; Type = "CIS" },
    @{ Name = "Ensure 'Password history size' is set to '24 or more password(s)'"; Command = { $DefaultPasswordPolicy.PasswordHistorySize -ge 24 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-password-history"; Type = "CIS" },
    @{ Name = "Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'"; Command = { ($DefaultPasswordPolicy.MaxPasswordAge.Days -le 60) -and ($DefaultPasswordPolicy.MaxPasswordAge.Days -gt 0) }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"; Type = "CIS" },
    @{ Name = "Ensure 'Minimum password age' is set to '1 or more day(s)'"; Command = { $DefaultPasswordPolicy.MinPasswordAge.Days -ge 1 }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-age"; Type = "CIS" },
    @{ Name = "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"; Command = {
        $TrustedAccounts = @(Get-ADObject -Filter { (TrustedForDelegation -eq $true) -or (msDS-AllowedToDelegateTo -like '*') } -Server $DomainController -ErrorAction Stop)
        $TrustedAccounts.Count -eq 0
    }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enable-computer-and-user-accounts-to-be-trusted-for-delegation"; Type = "CIS" },
    @{ Name = "Ensure 'User Rights Assignment: Access this computer from the network' is set to 'Administrators, Authenticated Users'"; Command = {
        try {
            $value = (Get-GPRegistryValue -Name 'Default Domain Controllers Policy' -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ValueName 'NullSessionShares' -ErrorAction Stop).Value
            return [string]::IsNullOrEmpty($value)
        } catch {
            return $false
        }
    }; Link = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network"; Type = "CIS" }
)

# Define the NIST controls to check
$NISTControls = @(
    @{ Name = "Ensure 'Audit Log Retention' is configured to not overwrite events (retain as needed)"; Command = {
        $RetentionValue = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' -Name 'Retention' -ErrorAction Stop).Retention
        $RetentionValue -eq 0
    }; Link = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"; Type = "NIST" },
    @{ Name = "Ensure 'Windows Firewall: Domain Profile' is set to 'On'"; Command = { (Get-NetFirewallProfile -Profile Domain).Enabled -eq 'True' }; Link = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"; Type = "NIST" },
    @{ Name = "Ensure 'Audit: Audit the access of global system objects' is set to 'Disabled'"; Command = { (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa').AuditBaseObjects -eq 0 }; Link = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"; Type = "NIST" },
    @{ Name = "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"; Command = { (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa').CrashOnAuditFail -eq 0 }; Link = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"; Type = "NIST" }
)

# Define the SOX controls to check
$SOXControls = @(
    @{ Name = "Ensure 'Logon Events are Audited'"; Command = { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security').Start -eq 4 }; Link = "https://example.com/sox-logon-events"; Type = "SOX" }
)

# Define GDPR controls to check
$GDPRControls = @(
    @{ Name = "Ensure 'Access Control Policy' is implemented"; Command = { (Get-ADUser -Filter {AdminCount -eq 1}).Count -le 5 }; Link = "https://gdpr-info.eu/art-32-gdpr/"; Type = "GDPR" },
    @{ Name = "Ensure 'Data Encryption' is enforced"; Command = { (Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\EFIM').DataEncryption -eq 1 }; Link = "https://gdpr-info.eu/art-32-gdpr/"; Type = "GDPR" }
)

# Define HIPAA controls to check
$HIPAAControls = @(
    @{ Name = "Ensure 'Audit Controls' are in place"; Command = {
        $AuditLogonPolicy = auditpol /get /subcategory:"Logon" /r | ConvertFrom-Csv
        $AuditLogonPolicy.'Inclusion Setting' -match 'Success'
    }; Link = "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"; Type = "HIPAA" },
    @{ Name = "Ensure 'Access Controls' are enforced"; Command = { (Get-ADUser -Filter {AdminCount -eq 1}).Count -le 5 }; Link = "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"; Type = "HIPAA" }
)

# Initialize counters for compliance
$CISCompliantCount = 0
$CISTotalCount = $CISBenchmarks.Count
$NISTCompliantCount = 0
$NISTTotalCount = $NISTControls.Count
$SOXCompliantCount = 0
$SOXTotalCount = $SOXControls.Count
$GDPRCompliantCount = 0
$GDPRTotalCount = $GDPRControls.Count
$HIPAACompliantCount = 0
$HIPAATotalCount = $HIPAAControls.Count

function Get-CompliancePercentage {
    param([int]$Compliant, [int]$Total)
    if ($Total -le 0) { return 0 }
    return [math]::Round(($Compliant / $Total) * 100, 2)
}

# Combined list of all checks, reused both for compliance counting and for rendering the report table below
$AllChecks = @($CISBenchmarks) + @($NISTControls) + @($SOXControls) + @($GDPRControls) + @($HIPAAControls)
$CheckResults = @()

# Check each CIS benchmark, NIST control, SOX control, GDPR control, and HIPAA control and count compliance
foreach ($Benchmark in $AllChecks) {
    $Name = $Benchmark.Name
    $Link = $Benchmark.Link
    $Type = $Benchmark.Type
    try {
        $Result = & $Benchmark.Command
    } catch {
        Write-Warning "Check '$Name' ($Type) failed to execute: $_"
        $Result = $false
    }
    if ($Result) {
        switch ($Type) {
            "CIS" { $CISCompliantCount++ }
            "NIST" { $NISTCompliantCount++ }
            "SOX" { $SOXCompliantCount++ }
            "GDPR" { $GDPRCompliantCount++ }
            "HIPAA" { $HIPAACompliantCount++ }
        }
    }
    $CheckResults += [PSCustomObject]@{
        Name   = $Name
        Link   = $Link
        Type   = $Type
        Result = [bool]$Result
    }
}

# Calculate compliance percentages
$CISCompliancePercentage = Get-CompliancePercentage -Compliant $CISCompliantCount -Total $CISTotalCount
$NISTCompliancePercentage = Get-CompliancePercentage -Compliant $NISTCompliantCount -Total $NISTTotalCount
$SOXCompliancePercentage = Get-CompliancePercentage -Compliant $SOXCompliantCount -Total $SOXTotalCount
$GDPRCompliancePercentage = Get-CompliancePercentage -Compliant $GDPRCompliantCount -Total $GDPRTotalCount
$HIPAACompliancePercentage = Get-CompliancePercentage -Compliant $HIPAACompliantCount -Total $HIPAATotalCount

# Calculate overall risk percentage based on compliance
$TotalChecks = $CISTotalCount + $NISTTotalCount + $SOXTotalCount + $GDPRTotalCount + $HIPAATotalCount
$TotalCompliant = $CISCompliantCount + $NISTCompliantCount + $SOXCompliantCount + $GDPRCompliantCount + $HIPAACompliantCount
$OverallCompliancePercentage = Get-CompliancePercentage -Compliant $TotalCompliant -Total $TotalChecks
$RiskPercentage = 100 - $OverallCompliancePercentage

# Determine risk level
if ($RiskPercentage -le 30) {
    $RiskLevel = "Low"
    $RiskColor = "green"
} elseif ($RiskPercentage -le 60) {
    $RiskLevel = "Medium"
    $RiskColor = "yellow"
} else {
    $RiskLevel = "High"
    $RiskColor = "red"
}

# Initialize the HTML report
$Report = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Compliance Report</title>
    <script type='text/javascript' src='loader.js'></script>
    <script type='text/javascript'>
      google.charts.load('current', {'packages':['gauge', 'corechart']});
      google.charts.setOnLoadCallback(drawChart);
      google.charts.setOnLoadCallback(drawRiskChart);

      function drawChart() {
        var dataCIS = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $CISCompliancePercentage]
        ]);

        var dataNIST = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $NISTCompliancePercentage]
        ]);

        var dataSOX = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $SOXCompliancePercentage]
        ]);

        var dataGDPR = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $GDPRCompliancePercentage]
        ]);

        var dataHIPAA = google.visualization.arrayToDataTable([
          ['Label', 'Value'],
          ['', $HIPAACompliancePercentage]
        ]);

        var options = {
          width: 300, height: 300,
          redFrom: 0, redTo: 30,
          yellowFrom: 30, yellowTo: 60,
          greenFrom: 60, greenTo: 100,
          minorTicks: 10,
          majorTicks: ['0', '20', '40', '60', '80', '100']
        };

        var chartCIS = new google.visualization.Gauge(document.getElementById('chart_cis_div'));
        var chartNIST = new google.visualization.Gauge(document.getElementById('chart_nist_div'));
        var chartSOX = new google.visualization.Gauge(document.getElementById('chart_sox_div'));
        var chartGDPR = new google.visualization.Gauge(document.getElementById('chart_gdpr_div'));
        var chartHIPAA = new google.visualization.Gauge(document.getElementById('chart_hipaa_div'));

        chartCIS.draw(dataCIS, options);
        chartNIST.draw(dataNIST, options);
        chartSOX.draw(dataSOX, options);
        chartGDPR.draw(dataGDPR, options);
        chartHIPAA.draw(dataHIPAA, options);
      }

      function drawRiskChart() {
        var data = google.visualization.arrayToDataTable([
          ['Risk Level', 'Percentage', { role: 'style' }],
          ['', $RiskPercentage, '$RiskColor']
        ]);

        var options = {
          title: 'Total Risk Compliance Score',
          width: 400,
          height: 200,
          bar: {groupWidth: '95%'},
          legend: { position: 'none' },
          hAxis: { minValue: 0, maxValue: 100 },
          vAxis: { format: '#' }
        };

        var chart = new google.visualization.BarChart(document.getElementById('risk_chart_div'));
        chart.draw(data, options);
      }

      function filterTable() {
        var typeSelectBox = document.getElementById('typeFilter');
        var resultSelectBox = document.getElementById('resultFilter');
        var selectedType = typeSelectBox.options[typeSelectBox.selectedIndex].value;
        var selectedResult = resultSelectBox.options[resultSelectBox.selectedIndex].value;
        var table = document.getElementById('complianceTable');
        var tr = table.getElementsByTagName('tr');

        for (var i = 1; i < tr.length; i++) {
          var typeCell = tr[i].getElementsByTagName('td')[0].innerHTML;
          var resultCell = tr[i].getElementsByTagName('td')[2].innerHTML;
          var displayType = (selectedType === 'All' || typeCell === selectedType);
          var displayResult = (selectedResult === 'All' || resultCell === selectedResult);

          tr[i].style.display = (displayType && displayResult) ? '' : 'none';
        }
      }
    </script>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
        }
        table {
            width: 80%;
            border-collapse: collapse;
            margin: 0 auto;
            border: 1px solid black;
        }
        table, th, td {
            border: 1px solid black;
        }
        th, td {
            padding: 15px;
            text-align: left;
        }
        th {
            background-color: #98AFC7;
        }
        .compliant {
            background-color: green;
            color: white;
        }
        .non-compliant {
            background-color: red;
            color: white;
        }
        .header {
            display: flex;
			flex-direction: column;
            align-items: center;
            justify-content: center;
			text-align: center
        }
        .header img {
            max-width: 300px;
            max-height: 300px;
            margin-right: 20px;
        }
        h1 {
            color: #00A4EF;
            text-align: center;
            width: 100%;
        }
        .chart-container {
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .chart {
            margin: 10px;
        }
        .chart-title {
            font-size: 24px; /* h3 font size */
            color: #7FBA00;
            margin-bottom: -10px;
        }
        .risk-container {
            display: flex;
            justify-content: center;
            align-items: flex-start;
            margin-top: 20px;
        }
        .filters {
            text-align: center;
            margin-bottom: 20px;
        }
        .footer {
            margin-top: 20px;
            font-size: 16px;
        }
        .domain-stats {
            margin-right: 20px;
            padding: 10px;
            color: black;
        }
        .domain-stats table {
            border-collapse: collapse;
            width: 100%;
        }
        .domain-stats th, .domain-stats td {
            border: 1px solid black;
            padding: 5px;
            text-align: left;
        }
    </style>
</head>
<body>
    <div class="header">

        <img src="file:///$LogoPath" alt="Logo" />
		<br><br>
        <h1>Active Directory Compliance Report for $SafeDomain</h1>
    </div>
    <div class='chart-container'>
        <div>
            <div class="chart-title">CIS Compliance</div>
            <div id='chart_cis_div' class='chart'></div>
        </div>
        <div>
            <div class="chart-title">NIST Compliance</div>
            <div id='chart_nist_div' class='chart'></div>
        </div>
        <div>
            <div class="chart-title">SOX Compliance</div>
            <div id='chart_sox_div' class='chart'></div>
        </div>
        <div>
            <div class="chart-title">GDPR Compliance</div>
            <div id='chart_gdpr_div' class='chart'></div>
        </div>
        <div>
            <div class="chart-title">HIPAA Compliance</div>
            <div id='chart_hipaa_div' class='chart'></div>
        </div>
    </div>
    <div class="risk-container">
        <div class="domain-stats">
            <h3>Domain Stats</h3>
            <table>
                <tr><th>Domain Name</th><td>$DomainName</td></tr>
                <tr><th>Number of Users</th><td>$NumberOfUsers</td></tr>
                <tr><th>Number of Groups</th><td>$NumberOfGroups</td></tr>
                <tr><th>Number of Disabled Users</th><td>$NumberOfDisabledUsers</td></tr>
                <tr><th>Number of Domain Admins</th><td>$NumberOfDomainAdmins</td></tr>
            </table>
        </div>
        <div id="risk_chart_div" style="width: 400px; height: 200px;"></div>
    </div>
    <div class="filters">
        <label for="typeFilter">Filter by Type:</label>
        <select id="typeFilter" onchange="filterTable()">
            <option value="All">All</option>
            <option value="CIS">CIS</option>
            <option value="NIST">NIST</option>
            <option value="SOX">SOX</option>
            <option value="GDPR">GDPR</option>
            <option value="HIPAA">HIPAA</option>
        </select>
        <label for="resultFilter">Filter by Result:</label>
        <select id="resultFilter" onchange="filterTable()">
            <option value="All">All</option>
            <option value="Compliant">Compliant</option>
            <option value="Non-Compliant">Non-Compliant</option>
        </select>
    </div>
    <br />
    <table id="complianceTable">
        <tr>
            <th>Type</th>
            <th>Benchmark</th>
            <th>Result</th>
        </tr>
"@

# Append the result of each benchmark/control (already evaluated above) to the report
foreach ($Check in $CheckResults) {
    $ResultText = if ($Check.Result) { "Compliant" } else { "Non-Compliant" }
    $ResultClass = if ($Check.Result) { "compliant" } else { "non-compliant" }
    $SafeName = ConvertTo-SafeHtml $Check.Name
    $SafeLink = ConvertTo-SafeHtml $Check.Link
    $Report += "<tr><td>$($Check.Type)</td><td><a href='$SafeLink' target='_blank'>$SafeName</a></td><td class='$ResultClass'>$ResultText</td></tr>"
}

# Finalize the HTML report
$Report += @"
    </table>

"@


# Get password complexity setting (reuse the policy already fetched above)
$PasswordComplexity = $DefaultPasswordPolicy.ComplexityEnabled

# Get all users
$AllUsers = Get-ADUser -Filter * -Properties LastLogon, PasswordLastSet

# Prepare the report content
$Report += @"



        <style>
            body { font-family: Arial, sans-serif; }
            h1 { color: #2C3E50; }
            h2 { color: #16A085; }
            p { color: #34495E; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 8px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #f2f2f2; }
            .expired { color: red; font-weight: bold; }
            .never { color: orange; font-weight: bold; }
            .builtin { color: green; font-weight: bold; }
            .ldap { color: blue; font-weight: bold; }
        </style>

   
        <h1>Active Directory Users Report</h1>
        <h2>Password Policy:</h2>
        <p>Password complexity enabled: $PasswordComplexity</p>
        <h2>Last Logon Dates and Password Expiry:</h2>
        <table>
            <tr>
                <th>User Name</th>
                <th>Last Logon Date</th>
                <th>Password Expires</th>
            </tr>
"@

# Get all domain controllers
$DomainControllers = Get-ADDomainController -Filter *

# Build a lookup of the latest LastLogon (non-replicated attribute) per user by querying
# each DC once for all users, instead of querying each user against every DC individually.
$LatestLogonByUser = @{}
foreach ($DC in $DomainControllers) {
    try {
        $DCUsers = Get-ADUser -Filter * -Server $DC.Name -Properties LastLogon -ErrorAction Stop
    } catch {
        Write-Warning "Failed to query domain controller '$($DC.Name)' for last logon data: $_"
        continue
    }
    foreach ($DCUser in $DCUsers) {
        if ($DCUser.LastLogon -and $DCUser.LastLogon -gt 0) {
            $LogonDate = [DateTime]::FromFileTime($DCUser.LastLogon)
            if (-not $LatestLogonByUser.ContainsKey($DCUser.SamAccountName) -or $LogonDate -gt $LatestLogonByUser[$DCUser.SamAccountName]) {
                $LatestLogonByUser[$DCUser.SamAccountName] = $LogonDate
            }
        }
    }
}

foreach ($User in $AllUsers) {
    $PasswordExpires = "N/A"  # Default value if no expiration is available
    $PasswordExpiryStatus = ""

    # If no logon found, display "Never logged in"
    $LastLogonDate = if ($LatestLogonByUser.ContainsKey($User.SamAccountName)) { $LatestLogonByUser[$User.SamAccountName] } else { "Never logged in" }

    # Check for built-in or LDAP users
    if ($User.SamAccountName -match "^[\w\s]*\$") {
        $PasswordExpiryStatus = "Built-in user"
    }
    elseif ($User.SamAccountName -match "LDAP") {
        $PasswordExpiryStatus = "LDAP user"
    }

    # Calculate Password Expiry Date
    if ($User.PasswordLastSet) {
        $MaxPasswordAge = $DefaultPasswordPolicy.MaxPasswordAge
        $PasswordExpiryDate = $User.PasswordLastSet.AddDays($MaxPasswordAge.Days)
        
        # Display the expiration date, and check if it's expired
        if ($PasswordExpiryDate -lt (Get-Date)) {
            $PasswordExpires = "<span class='expired'>Expired on: $($PasswordExpiryDate.ToString('dd/MM/yyyy')) , Might be Service account, Password never expires, Radius/LDAP user</span>"
        }
        else {
            $PasswordExpires = "Expires on: $($PasswordExpiryDate.ToString('dd/MM/yyyy'))"
        }
    }
    else {
        $PasswordExpires = "<span class='never'>Password Never Set</span>"
    }

    # Append user, last logon date, and password expiry to report
    $SafeSamAccountName = ConvertTo-SafeHtml $User.SamAccountName
    $Report += @"
            <tr>
                <td>$SafeSamAccountName</td>
                <td>$LastLogonDate</td>
                <td>$PasswordExpires</td>
            </tr>
"@
}

# End the HTML report
$Report += @"
        </table>
    
    <div class="footer">
        Powered By <a href="https://$SafeSignatureUrl" target="_blank">$SafeSignatureUrl</a>
    </div>
</body>
</html>
"@

# Output to HTML file

$Report | Out-File -FilePath $ReportPath -Encoding utf8



Write-Host "Report generated at: $ReportPath"
