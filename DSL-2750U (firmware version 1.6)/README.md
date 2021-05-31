# Analysis and PoC 

### Device Informations :
  Brand : Dlink <br/>
  Model : DSL-2750U<br/>
  Hardware ID : GAN9.ET235B-B<br/>
  Version : ME_1.16<br/>
  firmware : GAN9.ET235B-B-DL-DSL2750U-R5B028-ME.EN_2T2R<br/>
  
### firmware basic information gathering 
i started looking into the firmware for backdoor accounts , the <b>/etc/shadow </b> file contains only 2 users root and sshuser , after bruteforcing the passwords , the root user has root as password , and sshuser : admin , but looks like web/telnet and ssh authentication is  configured somewhere else , in the file <b>/etc/config.xml </b> ,but looks like there is only one user for each service , so nothinng intresting .<br/> now for the web server , they are using a <b>mini_httpd</b> webserver and passing requests and actions through <b>/usr/www/cgi-bin/webproc</b>(Authentication , web pages ...) , now in the cgi-bin directory i found another file <b>webupg</b> its also a binary that handle certain type of requests . 

### reversing webupg
file command says it s a stripped binary , importing file in ghidra , basic auto analysis , first its checking for some headers in the request , and the request method : (all functions and symbols were reversed) 
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
Then its checking if we provided a valid session id 
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
now if we have it let us run some actions , depending on what we provide in a POST variable called name  
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
now depending on what we provided in the name variable it will run the apropriate function , i started looking in every function for vulns ,now the function that gets executed when we ask for action : <b>mac</b> is interesting , the purpose of this function is to change the MAC address of the router , its doing that by overwritting 
