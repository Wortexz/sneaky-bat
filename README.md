# sneaky-bat - quick analysis

## Another targeted attack against GOV organizations in LT

It all started with a phishing email from a hacked email account or maybe hacked email server.    
Unfortunately we do not have an email sample - only the attachment.    

## Email attachment & Malware analysis
__We have *.img* file attachment and when we open the file, something happens:__    
* Virtual Disk is being mounted with read-only permissions (most AV solutions cannot clean the malware)    
* Inside Virtual Disk we have .bat file:

![Screenshot 2024-05-21 114854](https://github.com/Wortexz/sneaky-bat/assets/26935578/54227252-ad26-4a77-84d4-111cb92191fa)    

* When we execute the .bat file it launches a series of commands and visually you can see this:    

![Screenshot 2024-05-21 161505](https://github.com/Wortexz/sneaky-bat/assets/26935578/0a05d22d-d103-410e-a623-505b5a48b137)
![setup](https://github.com/Wortexz/sneaky-bat/assets/26935578/e8c904a2-136f-41cb-83a9-cf2624a3669b)

## Malware analysis     
* __Files names:__ *doc023561861500.bat / DOC02356.BAT / file.exe*    
* __SHA-256:__ 3dad11bcdd07ce0d3431ff24364eddac1e4dec7b72f806ed1c6cff7d876524a1    
* __File Type:__ Win32 EXE    
* __File entropy is quite unique:__ NSIS Installer (80.1%) & unique code (19.2%)
* __Malware family:__ GuLoader - fileless shellcode.
* __Obfuscation:__ XOR
* __Seen only on a few devices:__    

![Screenshot 2024-05-21 162656](https://github.com/Wortexz/sneaky-bat/assets/26935578/d32aeb15-2dd3-4a1e-9e9b-8a01b4b51a54)
## Malware Behavior    
* __Defense Evasion:__ detect-debug-environment / checks-bios / long-sleeps / checks-network-adapters & more anti-VM techniques    
* __MITRE ATT&CK & Technique:__
* [T1059] [T1059.001] [T1059] - Attempts to execute suspicious powershell command arguments    
* [T1106] Guard pages use detected - anti-debugging    
* __Command and Control__ [T1071] - Created a process from a suspicious location / Reads data out of its own binary image    
* __Collection:__ Archive Collected Data [T1560]    
* __Discovery:__ System Owner/User Discovery [T1033]    
* __Collects and encrypts information about the computer to send to C2 server__
* __ESET Detection:__ NSIS/Injector.ASH    

* __Process Tree:__

![Screenshot 2024-05-21 171645](https://github.com/Wortexz/sneaky-bat/assets/26935578/4e11f2d0-5cb9-49c1-86d0-0d4d487f1119)
![Screenshot 2024-05-21 172804](https://github.com/Wortexz/sneaky-bat/assets/26935578/f63aea51-1bb7-45d1-9f5f-4d5c174eead9)
![Screenshot 2024-05-21 172726](https://github.com/Wortexz/sneaky-bat/assets/26935578/4087adef-8fb0-4950-bb38-ba78ba1ecd72)




