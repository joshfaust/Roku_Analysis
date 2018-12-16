<a href ="https://github.com/MNFaust/Roku_Analysis">
  <img src="https://q4j2g5j9.stackpathcdn.com/ddg-dream/3c99180cbf6b8e835dbe542241c8b94c42398093.jpg"
    title="Roku Analysis/Research" align="left" height=100 length=100 /></a> 


# Roku Log Analysis 

The inital purpose of this reasearch is to review PiHole Logs associated with a Roku's logging activity.Takes PiHole logs generated on a PiHole machine and parses 
out all Roku genereated traffic that's resident within the logs. The promary purpose is  to determine the amount of data a Roku is generating 
and how much of that data is non-streaming information being sent back to the Roku logging servers.  

# Usage: 
```
usage: analyze.py [-h] -d  -l  [-p]

optional arguments:
  -h, --help         show this help message and exit
  -d , --directory   Output directory
  -l , --logs        Location of PiHole Logs
  -p , --pcap        Path of PCAP file
 ```
 
At this time, the PCAP analysis is disabled. Feel free to fork this and edit the pcap analysis method at your leisure. I will update the script to enable a more
comprehensive PCAP analysis in time. Right now, I am gathering more logs.

#
<a href="https://twitter.com/JFaust0">
  <img src="https://cdn1.iconfinder.com/data/icons/iconza-circle-social/64/697029-twitter-512.png" height=75, width=75, align="left" />
  </a>
  
  **Twitter:** Jfaust0
