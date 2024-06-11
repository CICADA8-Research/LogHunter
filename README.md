# LogHunter
Opsec tool for finding user sessions by analyzing event log files through RPC (MS-EVEN). 

I was once doing a very complex project where there were over 1000 hosts in the infrastructure. I needed to detect the user session. Running Invoke-UserHunter would have been a huge mistake. That's when I came up with the idea that we could extract all the information we needed from Event Logs. That's how the LogHunter tool came into being. The tool is able to extract the following events via MS-EVEN protocol:
    4624: “An account was successfully logged on.”,
    4768: “A Kerberos authentication ticket (TGT) was requested.”,
    4672: “Special privileges assigned to new logon.”,
    4769: “A Kerberos service ticket (TGS) was requested.”.

These events will give us information about which computer the target user is on. Then hijack that computer and take control of the user.

# Requirements

You only have to install impacket. Other modules (e.g. logging, argparse, sys, struct, Queue, Thread, datetime) are standard Python libraries and are installed with Python.

```shell
pip install impacket
```

# Usage

See demo video at the end of the README.md :)

To use the tool, all you need to do is pass credentials as you would to a regular impacket tool:
```shell
python LogHunter.py OFFICE/Administrator:lolkekcheb123!@dc01.office.pwn
```
![изображение](https://github.com/CICADA8-Research/LogHunter/assets/92790655/e5d39d43-4cf2-4d65-9009-9bed3fc5ad98)


After that, the tool will start receiving events from the target computer (in this case, from dc01.office.pwn), writing them to the `events.log` file (can be overridden with the -outfile parameter). You can then search for the file using find.sh. You can search by user name, by EventID, or by computer name - whatever you prefer.

```shell
./find.sh -file events.log -searchkeyword Administrator
```
![изображение](https://github.com/CICADA8-Research/LogHunter/assets/92790655/5f6c09ec-c791-41ba-a57a-2d5c7d00151b)


# Demo

Check Here!

https://www.youtube.com/watch?v=0fjSTbyD9F0
