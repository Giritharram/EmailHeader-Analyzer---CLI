# EmailHeader-Analyzer with OSINT

This tool is a CLI version of EH[Email Header]-Analyzer with the integration of OSINT features.

## How To Install
```
pip3 install -r requirements.txt
```


## How To Run

Place Your 'TXT' or 'EML' file inside the directory.

```
python3 main.py 'file' 'argument'
```
Give any one of the following arguments

```
 -h                -> Help                    
 -Eh               -> Email header analysis   
 -Ipinfo           -> IP Information                      
 -Domaininfo       -> Domain Information      
 -URLinfo          -> URL Information   
 ```
 
 After Trying all of the above arguments, try out the below ones
 
 ```
 -IPpassive        -> Passive DNS Information
 -PortScan         -> Scan for Openports
 -Whois            -> Whois Information
 ```
 
 Create a VirusTotal account and use your own API key, you can do it [here](https://www.virustotal.com/gui/home/search)
