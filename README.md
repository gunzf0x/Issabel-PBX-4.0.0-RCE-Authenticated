# Issabel PBX 4.0.0 Remote Code Execution - Authenticated (CVE-2024-0986)

## Description

"A vulnerability was found in Issabel PBX 4.0.0. It has been rated as critical. 
This issue affects some unknown processing of the file `/index.php?menu=asterisk_cli` of the component Asterisk-Cli. 
The manipulation of the argument Command leads to os command injection. The attack may be initiated remotely. 
The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-252251. 
NOTE: The vendor was contacted early about this disclosure but did not respond in any way."


This PoC script is based on [this PoC Video](https://drive.google.com/file/d/10BYLQ7Rk4oag96afLZouSvDDPvsO7SoJ/view?usp=drive_link).


## Usage

```shell-session
$ python3 Issabel_PBX_Authenticated_RCE.py -u <user> -p <password> -t <ip-address> -c <UNIX command>
```

For example:
```shell-session
$ python3 Issabel_PBX_Authenticated_RCE.py -u 'pedrito' -p 'meelectrocutaste' -t 'https://10.10.10.10' -c 'id'
```

![PoC image](images/PoC.png)

## More info:
This script was tested on `Issabel PBX 4.0.0`.

More CVE-2024-0986 info:
- [https://nvd.nist.gov/vuln/detail/CVE-2024-0986](https://nvd.nist.gov/vuln/detail/CVE-2024-0986)
- [https://github.com/advisories/GHSA-v9pc-9fc9-4ff8](https://github.com/advisories/GHSA-v9pc-9fc9-4ff8)


## Disclaimer
The owner of this repository is not responsible for the usage of this software. It was made for educational purposes only.

## Licence
- MIT
