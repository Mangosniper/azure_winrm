#################################################################################################################################
#  Name        : Configure-WinRM.ps1                                                                                            #
#                                                                                                                               #
#  Description : Configures the WinRM on a local machine                                                                        #
#                                                                                                                               #
#  Arguments   : HostName, specifies the FQDN of machine or domain                                                              #
#                                                                                                                               #
#  Version     : 1.1                                                                                                            #
#                                                                                                                               #
#################################################################################################################################

param
(
    [Parameter(Mandatory = $true)]
    [string] $HostName
)

#################################################################################################################################
#                                             Helper Functions                                                                  #
#################################################################################################################################

function Delete-WinRMListener
{
    try
    {
        $config = Winrm enumerate winrm/config/listener
        foreach($conf in $config)
        {
            if($conf.Contains("HTTPS"))
            {
                Write-Verbose "HTTPS is already configured. Deleting the exisiting configuration."
                Log-Write -LogPath $FullLogPath -LineValue "HTTPS is already configured. Deleting the exisiting configuration."
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
                break
            }
        }
    }
    catch
    {
        Write-Verbose -Verbose "Exception while deleting the listener: " + $_.Exception.Message
        Log-Write -LogPath $FullLogPath -LineValue "Exception while deleting the listener: " + $_.Exception.Message
    }
}

function Create-Certificate
{
    param(
        [string]$hostname
    )

    # makecert ocassionally produces negative serial numbers
	# which golang tls/crypto <1.6.1 cannot handle
	# https://github.com/golang/go/issues/8265
    $serial = Get-Random
    .\makecert -r -pe -n CN=$hostname -b 01/01/2012 -e 01/01/2022 -eku 1.3.6.1.5.5.7.3.1 -ss my -sr localmachine -sky exchange -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12 -# $serial 2>&1 | Out-Null

    $thumbprint=(Get-ChildItem cert:\Localmachine\my | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1).Thumbprint

    if(-not $thumbprint)
    {
        throw "Failed to create the test certificate."
        Log-Write -LogPath $FullLogPath -LineValue "Failed to create the test certificate"
    }

    return $thumbprint
}

function Configure-WinRMHttpsListener
{
    param([string] $HostName,
          [string] $port)

    # Delete the WinRM Https listener if it is already configured
    Delete-WinRMListener
    Log-Write -LogPath $FullLogPath -LineValue "Deleted the WinRM Https listener if it is already configured"

    # Create a test certificate
    $cert = (Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1)
    Log-Write -LogPath $FullLogPath -LineValue "Created a test certificate"
    $thumbprint = $cert.Thumbprint
    if(-not $thumbprint)
    {
	    $thumbprint = Create-Certificate -hostname $HostName
        Log-Write -LogPath $FullLogPath -LineValue "There was no thumbprint, created one"
    }
    elseif (-not $cert.PrivateKey)
    {
        # The private key is missing - could have been sysprepped
        # Delete the certificate
        Remove-Item Cert:\LocalMachine\My\$thumbprint -Force
        $thumbprint = Create-Certificate -hostname $HostName
        Log-Write -LogPath $FullLogPath -LineValue "There was no private key, created one"
    }

    $WinrmCreate= "winrm create --% winrm/config/Listener?Address=*+Transport=HTTPS @{Port=`"$port`";Hostname=`"$hostName`";CertificateThumbprint=`"$thumbPrint`"}"
    invoke-expression $WinrmCreate
    winrm set winrm/config/service/auth '@{Basic="true"}'
    Log-Write -LogPath $FullLogPath -LineValue "Set winrm authentication to basic"
}

function Add-FirewallException
{
    param([string] $port)

    # Delete an exisitng rule
    netsh advfirewall firewall delete rule name="Windows Remote Management (HTTPS-In)" dir=in protocol=TCP localport=$port
    Log-Write -LogPath $FullLogPath -LineValue "Deleted existing rule if there was any"

    # Add a new firewall rule
    netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=$port
    Log-Write -LogPath $FullLogPath -LineValue "Added new rule"
}


#################################################################################################################################
#                                              Configure WinRM                                                                  #
#################################################################################################################################

# Start Logging
. ".\Logging_Functions.ps1"
$FullLogPath = "C:\Windows\Temp\ConfigureWinRM.log"
Log-Start -LogPath "C:\Windows\Temp" -LogName "ConfigureWinRM.log" -ScriptVersion "1.1"

$winrmHttpsPort=443
Log-Write -LogPath $FullLogPath -LineValue "Value of winrmHttpsPort:"
Log-Write -LogPath $FullLogPath -LineValue $winrmHttpsPort

# The default MaxEnvelopeSizekb on Windows Server is 500 Kb which is very less. It needs to be at 8192 Kb. The small envelop size if not changed
# results in WS-Management service responding with error that the request size exceeded the configured MaxEnvelopeSize quota.
Log-Write -LogPath $FullLogPath -LineValue "Start seting winrm/config"
winrm set winrm/config '@{MaxEnvelopeSizekb = "8192"}'
Log-Write -LogPath $FullLogPath -LineValue "Setting winrm/config completed"

# Configure https listener
Log-Write -LogPath $FullLogPath -LineValue "Start configuring winrmhttpslistener"
Configure-WinRMHttpsListener $HostName $winrmHttpsPort
Log-Write -LogPath $FullLogPath -LineValue "Completed configuring winrmhttpslistener"

# Add firewall exception
Log-Write -LogPath $FullLogPath -LineValue "Start adding firewallexception"
Add-FirewallException -port $winrmHttpsPort
Log-Write -LogPath $FullLogPath -LineValue "Completed adding firewallexception"

Log-Finish -LogPath $FullLogPath -NoExit $True

#################################################################################################################################
#################################################################################################################################
