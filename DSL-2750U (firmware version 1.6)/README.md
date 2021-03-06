# Analysis and PoC
## ***Update*** :
This bug was patched by D-link : 26/07/2021 
<br/>New firmware is released check the link : https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10230
### The following CVE numbers have been assigned:
- <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3707"> CVE-2021-3707 </a>
- <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-3708"> CVE-2021-3708 </a>
### Device Informations :
<i>
  Brand : D-link <br/>
  Model : DSL-2750U<br/>
  Hardware ID : GAN9.ET235B-B<br/>
  Version : ME_1.16<br/>
  firmware : GAN9.ET235B-B-DL-DSL2750U-R5B028-ME.EN_2T2R</i>
  
### firmware basic information gathering 
<i>I started looking into the firmware for backdoor accounts , the <b>/etc/shadow </b> file contains only 2 users root and sshuser , after bruteforcing the passwords , the root user has root as password , and sshuser : admin , but looks like web/telnet and ssh authentication is  configured somewhere else , in the file <b>/etc/config.xml </b> ,but looks like there is only one user for each service , so nothinng intresting .<br/> now for the web server , they are using a <b>mini_httpd</b> webserver and passing requests and actions through <b>/usr/www/cgi-bin/webproc</b>(Authentication , web pages ...) , now in the cgi-bin directory I found another file <b>webupg</b> its also a binary that handle certain type of requests . </i>
### reversing webupg
<i>file command says it s a stripped binary , importing file in ghidra , basic auto analysis , first it's checking for some headers in the request , and the request method : (all functions and symbols were reversed) </i>
```c
  iVar2 = getenv("REQUEST_METHOD");
  if ((iVar2 == 0) || (iVar2 = FUN_00401880(iVar2,"POST"), iVar2 != 0)) {
    iVar2 = 4;
    pcVar6 = "Unsupported Request Method";
LAB_0040343c:
    FUN_00401dfc(pcVar6);
  }
  else {
    iVar2 = getenv("CONTENT_TYPE");
    if (iVar2 == 0) {
LAB_004032bc:
      iVar2 = 5;
      pcVar6 = "Unsupported Content Type";
      goto LAB_0040343c;
    }
    iVar5 = FUN_00401100(iVar2,"application/x-www-form-urlencoded",0x21);
    if (iVar5 == 0) {
      iVar5 = 1;
    }
    else {
      iVar5 = 2;
      iVar2 = FUN_00401100(iVar2,"multipart/form-data",0x13);
      if (iVar2 != 0) goto LAB_004032bc;
    }
    bVar1 = false;
```

<i>Then its checking if we provided a valid session id </i>
```c
    iVar2 = getenv("HTTP_COOKIE");
    if (iVar2 != 0) {
      uVar9 = FUN_00401160(iVar2);
      iVar2 = FUN_00401250(uVar9,0x3d);
      if (iVar2 != 0) {
        iVar2 = FUN_00401130(uVar9,&DAT_00404ee4);
        while (iVar2 != 0) {
          iVar2 = FUN_004010d0(iVar2,"sessionid");
          if (iVar2 != 0) {
            iVar2 = FUN_00401250(iVar2,0x3d);
            if ((iVar2 != 0) && (iVar2 = FUN_004018a8(iVar2 + 1), iVar2 == 0)) {
              bVar1 = true;
```
<i> if we have ,it let us run some actions , depending on what we provided in a POST variable called name </i>
```c
            iVar5 = FUN_00401160(iVar2 + 5);
            iVar2 = func_0x004011c0(iVar5,"ShowSysEvtLogFile");
            uVar9 = 0;
            if (iVar2 == 0) {
LAB_004034f0:
              iVar2 = FUN_00402160(uVar9);
            }
            else {
              iVar2 = func_0x004011c0(iVar5,"ShowFirewallLogFile");
              if (iVar2 == 0) {
                iVar2 = FUN_00403148();
              }
              else {
                iVar2 = func_0x004011c0(iVar5,"downloadSysEvtLogFile");
                if (iVar2 == 0) {
                  uVar9 = 1;
                  goto LAB_004034f0;
                }
                iVar2 = func_0x004011c0(iVar5,"downloadConfig");
                if (iVar2 == 0) {
                  iVar2 = FUN_00401fc8();
                }
                else {
                  iVar2 = func_0x004011c0(iVar5,"mac");
                  if (iVar2 == 0) {
                    iVar2 = FUN_00402eec();
                  }
                  else {
                    iVar2 = func_0x004011c0(iVar5,"protest");
                    if (iVar2 == 0) {
                      iVar2 = FUN_00402cdc();
                    }
```
<i>So depending on what we provided in the name variable it will run the apropriate function , I started looking in every function for vulns ,now the function that gets executed when we ask for action : <b>mac</b> is interesting , the purpose of this function is to change the MAC address of the router , its doing that by overwritting the old mac address (our input) by the one in the file <b>" /proc/llconfig/macadd "</b> :</i>
<br/>
```c
    snprintf(auStack536,"echo %s>/proc/llconfig/macaddr",puVar3);
    system(auStack536,0);
```
<br/><i>
Hmm , so it snprintf our new mac address ( unsanitized input ) into that string and passing it to LIBC system , okey I found a way to do some command injection , I shall note that the mini_httpd server runs as root , so any command we pass will run as root .</i>

```
  583 root       1728 SW  /usr/sbin/mini_httpd -d /usr/www -c /cgi-bin/* -u roo
```
<i><br/>
so the only problem here is to get a valid session id ...</i><br/>
### Web Authentication <i>
Authentication on the web server : the client generate a random 4 byte number and send the username and the password to the CGI webproc , now if the username and password are valid the session id is set on both the server and client and I can invoke every previous action mentioned in the previous section , but no luck to get a session id without a valid username and password , I tried the root , sshuser but no luck ...</i><br/>
## misconfiguration of the tftp server (backdoor)<i>
nmap scans shows that tftp (trivial file transfer protocol) protocol is running on the router port 69 </i>
<br/>
```
ftp-data        20/tcp
ftp             21/tcp
telnet          23/tcp
tftp            69/udp
netbios-ssn     139/tcp
netbios-ns      137/udp

```
<br/>
<i>
tftp is very limited , and its generally used for simple tasks get , put some files via UDP , I looked in the configuration file of tftpd , I found that anonymous user is enabled , but the only files that let me download are <b>cfg.xml</b> and <b>image.img</b> , the cfg.xml turns out its the backup file for settings in router but its encrypted , I looked on the firmware how its encrypting the config file , but looks like a lot of work , and then I said well I will try to resend the same file with the command put , I doubt it will accept it ?? but it did and the router rebooted and did set those settings , So lets just overwrite the old configuration with a configuration I craft with my username and password .</i>

### Poc
<i>
okey now we have a way to overwrite the config file with my username and password (the router will do it for me , easy just login to my router saving the backup file with username:pwned , password:pwned , now I have a configuration file that I can send to any DSL-2750 router with the same firmware and the same bug ),and reach to the CGI <b>webproc</b> get authenticated , and get a valid session id , and use it to call the CGI <b>webupg</b> with appropriate headers , and param names to inject any command to run as root , and that's what I did , the file <b>exploit.sh</b> will send my crafted config file overwritting the config file through tftp ,call the file <b>exploit.py</b> get authenticated and send command to the router (since there is no netcat , filesystem is read-only , and I'm lazy to compile netcat for a MIPS LEXRA architecture) I sent only reboot command . </i>


### Pwned !
before exploit : <br/><br/>
<img src="img/before.jpg"/> <br/><br/>
After exploit :<br/><br/>
<img src="img/after.jpg"/> <br/><br/>
now we can access admin panel <br/><br/>
<img src="img/main.jpg"/>
## Security annoucement and relevant links :
- D-link Advisory : https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10230
- JAPAN / CC Disclosure : https://jvn.jp/en/vu/JVNVU92088210/
## end.
