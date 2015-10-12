function Get-OAuthAuthorization {
    <#
    .SYNOPSIS
        Esta función es usada para realizar la configuración necesaria, en lo que a seguridad refiere,
        para utilizar la API de Twitter. Utiliza la versión 1.1 de la API. 
    .EXAMPLE 
        Get-OAuthAuthorization -DmMessage 'Hola!' -HttpEndPoint 'https://api.twitter.com/1.1/direct_messages/new.json' -Username adam 
     
        This example gets the authorization string needed in the HTTP POST method to send a direct 
        message with the text 'hello' to the user 'adam'. 
    .EXAMPLE 
        Get-OAuthAuthorization -TweetMessage 'hello' -HttpEndPoint 'https://api.twitter.com/1.1/statuses/update.json' 
     
        This example gets the authorization string needed in the HTTP POST method to send out a tweet. 
    .PARAMETER HttpEndPoint 
        This is the URI that you must use to issue calls to the API. 
    .PARAMETER TweetMessage 
        Use this parameter if you're sending a tweet.  This is the tweet's text. 
    .PARAMETER DmMessage 
        If you're sending a DM to someone, this is the DM's text. 
    .PARAMETER Username 
        If you're sending a DM to someone, this is the username you'll be sending to. 
    .PARAMETER ApiKey 
        The API key for the Twitter application you previously setup. 
    .PARAMETER ApiSecret 
        The API secret key for the Twitter application you previously setup. 
    .PARAMETER AccessToken 
        The access token that you generated within your Twitter application. 
    .PARAMETER 
        The access token secret that you generated within your Twitter application. 
    #> 
    [CmdletBinding(DefaultParameterSetName = 'None')] 
    [OutputType('System.Management.Automation.PSCustomObject')] 
    param ( 
        [Parameter(Mandatory)] 
        [string]$HttpEndPoint, 
        [Parameter(Mandatory, ParameterSetName = 'NewTweet')] 
        [string]$TweetMessage, 
        [Parameter(Mandatory, ParameterSetName = 'DM')] 
        [string]$DmMessage, 
        [Parameter(Mandatory, ParameterSetName = 'DM')] 
        [string]$Username, 
        [Parameter()] 
        [string]$ApiKey = 'j5Fvx1EnCaHM8zUS14HFRmZ7e', 
        [Parameter()] 
        [string]$ApiSecret = 'XUPYDP2qagFpLavREmDGLIqFauKZkY90SxuHNuC28pVyEdjIfM', 
        [Parameter()] 
        [string]$AccessToken = '703096147-Z3fSdcrwbW7n1FAoz7zO0AHxZVy9fbw6WbTH2jKz', 
        [Parameter()] 
        [string]$AccessTokenSecret = 'nu4kJmku3vVgoB2dEY6AiIPy3k5s7NZVcOOOyWCKHSUhD' 
    ) 
     
    begin { 
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop 
        Set-StrictMode -Version Latest 
        try { 
            [Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null 
            [Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null 
        } catch { 
            Write-Error $_.Exception.Message 
        }
    }
     
    process {
        try {
            $TimeTicks = ([System.DateTime]::Now.Ticks).ToString()
            $OauthNonce = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($TimeTicks.Substring(6,12)))
            Write-Verbose "Generated Oauth none string '$OauthNonce'"

            ## Find the total seconds since 1/1/1970 (Unix epoch time)
            $EpochTimeNow = [System.DateTime]::UtcNow - [System.DateTime]::ParseExact("01/01/1970", "dd/MM/yyyy", $null)
            Write-Verbose "Generated epoch time '$EpochTimeNow'"
            $OauthTimestamp = [System.Convert]::ToInt64($EpochTimeNow.TotalSeconds).ToString();
            Write-Verbose "Generated Oauth timestamp '$OauthTimestamp'"

            ## Build the signature
            $SignatureBase = "$([System.Uri]::EscapeDataString($HttpEndPoint))&"
            $SignatureParams = @{
                'oauth_consumer_key' = $ApiKey;
                'oauth_nonce' = $OauthNonce;
                'oauth_signature_method' = 'HMAC-SHA1';
                'oauth_timestamp' = $OauthTimestamp;
                'oauth_token' = $AccessToken;
                'oauth_version' = '1.0';
            }
            if ($TweetMessage) {
                $SignatureParams.status = $TweetMessage
            } elseif ($DmMessage) {
                $SignatureParams.screen_name = $Username
                $SignatureParams.text = $DmMessage
            }

            $SignatureParams.GetEnumerator() | sort name | foreach {
                Write-Verbose "Adding '$([System.Uri]::EscapeDataString(`"$($_.Key)=$($_.Value)&`"))' to signature string"
                $SignatureBase += [System.Uri]::EscapeDataString("$($_.Key)=$($_.Value)&".Replace(',','%2C').Replace('!','%21'))
            }
            $SignatureBase = $SignatureBase.TrimEnd('%26')
            $SignatureBase = 'POST&' + $SignatureBase
            Write-Verbose "Base signature generated '$SignatureBase'"

            $SignatureKey = [System.Uri]::EscapeDataString($ApiSecret) + "&" + [System.Uri]::EscapeDataString($AccessTokenSecret);

            $HMACSHA1 = New-Object System.Security.Cryptography.HMACSHA1;
            $HMACSHA1.Key = [System.Text.Encoding]::ASCII.GetBytes($SignatureKey);
            $OauthSignature = [System.Convert]::ToBase64String($HMACSHA1.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($SignatureBase)));
            Write-Verbose "Using signature '$OauthSignature'"

            $AuthorizationParams = $SignatureParams
            $AuthorizationParams.Add('oauth_signature', $OauthSignature)

            $AuthorizationParams.Remove('status')
            $AuthorizationParams.Remove('text')
            $AuthorizationParams.Remove('screen_name')

            $AuthorizationString = 'OAuth '
            $AuthorizationParams.GetEnumerator() | sort name | foreach { $AuthorizationString += $_.Key + '="' + [System.Uri]::EscapeDataString($_.Value) + '", ' }
            $AuthorizationString = $AuthorizationString.TrimEnd(', ')
            Write-Verbose "Using authorization string '$AuthorizationString'"

        } catch {
            Write-Error $_.Exception.Message
        }
    }
}
 
function Send-Tweet {
    <#
    .SYNOPSIS
        Este Cmdlet permite enviar un Tweet a un usuario (o varios).
    .EXAMPLE
        Send-Tweet -Message 'Hola! Este es un Tweet.'

        Con la línea anterior se envía un Tweet con el texto 'Hola! Este es un Tweet.'
    .PARAMETER Message
        Cuerpo del Tweet.
    #>
    [CmdletBinding()]
    [OutputType('System.Management.Automation.PSCustomObject')]
    param (
        [Parameter(Mandatory)][ValidateLength(1, 140)][string]$Message
    ) 
    process { 
        $HttpEndPoint = 'https://api.twitter.com/1.1/statuses/update.json'
        $AuthorizationString = Get-OAuthAuthorization -TweetMessage $Message -HttpEndPoint $HttpEndPoint
        $Body = "status=$Message"
        Write-Verbose "Using POST body '$Body'"
        Invoke-RestMethod -URI $HttpEndPoint -Method Post -Body $Body -Headers @{ 'Authorization' = $AuthorizationString } -ContentType "application/x-www-form-urlencoded"
    } 
} 
 
function Send-TwitterDm {
    <#
    .SYNOPSIS
        Este Cmdlet permite enviar un mensaje directo (DM) a un usuario (o varios) de Twitter.
        Están permitidos hasta un máximo de 250 mensajes en un período de 24 horas.
    .EXAMPLE
        Send-TwitterDm -Message 'Hola! Este es un mensaje directo.' -Username 'vmsilvamolina','user2'
     
        Con la línea anterior se enviará un DM con el texto "Hola! Este es un mensaje directo." a los usuarios "vmsilvamolina" y "user2".
    .PARAMETER Message
        Texto del mensaje
    .PARAMETER UserName
        El nombre/s de el/los usuario/s que recibirá/n el mensaje.
    #>
    [CmdletBinding()]
    [OutputType('System.Management.Automation.PSCustomObject')]
    param (
        [Parameter(Mandatory)][ValidateLength(1, 140)][string]$Message,
        [Parameter(Mandatory)][string[]]$UserName
    )
    process { 
        $HttpEndPoint = 'https://api.twitter.com/1.1/direct_messages/new.json'
        foreach ($User in $UserName) { 
            $AuthorizationString = Get-OAuthAuthorization -DmMessage $Message -HttpEndPoint $HttpEndPoint -Username $User
            $User = [System.Uri]::EscapeDataString($User) 
            $Body ="text=$Message&screen_name=$User" 
            Invoke-RestMethod -URI $HttpEndPoint -Method Post -Body $Body -Headers @{ 'Authorization' = $AuthorizationString } -ContentType "application/x-www-form-urlencoded"
        }
    }
}