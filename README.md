# hltvwatch
Automatic HLTV without AMX!

The HLTV has two methods (only method 1 is implemented right now)

Method 1: 
- The HLTV connect when the players on the server is superior from a static number and start to record
- The HLTV disconnect
  - When the players on the server is inferior from a static number
  - When the HLDS serv is down
  
 Method 2: Work in progress

In all cases:
- The HLTV stop and restart to record when there is a changelevel
- The .dem is compressed to a tar.gz and moved to a directory which can be connected to a website or a FTP

Installation:
- Copy hltv.cfg and hltv.lib in your hlds folder (not cstrike folder!)
- Create a folder named hltwatch and drop hldswatch.py and servers.conf
- chmod hltvwatch folder with the same user than HLDS folder
- Configure servers.cfg
