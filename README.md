# Virus Total IP&Domain Checker Python Script

This script check multiple and single IP&Domain via VT API key. It writes a csv file for results.

## Installation

```bash
pip install -r requirements.txt
```

## Usage for Single Entry

```bash
python3 vt-checker.py -s 10.10.10.10
python3 vt-checker.py -s github.com
```
## Usege for Multiple Entry
```bash
python3 vt-checker.py -i <PATH_TO_IP_LIST>
python3 vt-checker.py -u <PATH_TO_DOMAIN_LIST>
```
### Example for Multiple Entry

```bash
python3 vt-checker.py -i /home/user/iplist.txt
python3 vt-checker.py -u /home/user/domainlist.txt
```