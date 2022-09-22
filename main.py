import os,sys,shutil
from colorama import *
from EH_Parser import *
from OSINT_Functions import *


allowed_extension = ['EML','TXT']

lenofargv = len(sys.argv)

arguments=['-h','-Eh','-Ipinfo','-Domaininfo','-URLinfo','-IPpassive','-PortScan','-Whois']

def user_instruction():
   
    if lenofargv<=2 or sys.argv[2] == '-h':
        print("\n****************************************************")
        print("                 How To Run:                       *")
        print("****************************************************")
        print('                                                   |')
        print("  python3 main.py 'eml or txt file' -argument      |")
        print('                                                   |')
        print('_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _| ')
        print('\n')
        print("\n****************************************************")
        print("                  Arguments:                       *")
        print("****************************************************")
        print('                                                   | ')
        print("      -h                -> Help                    |")
        print("      -Eh               -> Email header analysis   |")
        print("      -IPinfo           -> IP Information          |")            
        print("      -Domaininfo       -> Domain Information      |")
        print("      -URLinfo          -> URL Information         |")
        print('                                                   | ')
        print('**************************************************** ')
        print(" Try The Following After : -Domaininfo & -IPinfo   *")    
        print('**************************************************** ')
        print('                                                   | ')
        print("      -IPpassive        -> Passive DNS Information |")
        print("      -PortScan         -> Scan for Openports      |")
        print("      -Whois            -> Whois Information       |") 
        print('_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _|\n') 

def allowed_file(arg):
    ext = arg.rsplit('.',1)[1]
    if ext.upper() in allowed_extension:
        return True
    else:
        return False 

def file_present(arg):
    isExist = os.path.exists(arg)
    if isExist is True:
        return True
    else:
        return False

def check_error():
    if file_present(sys.argv[1]) == False and sys.argv[1] not in arguments:
        print('_ _ _ _ _')
        print('          |')
        print(Fore.RED+' Warning!'+Style.RESET_ALL+' |')
        print('_ _ _ _ _ |')
        
        print(f"\nThe file named '{sys.argv[1]}'  could not be found !... \n")
        return True
    
    if allowed_file(sys.argv[1]) == False:
        print('_ _ _ _ _')
        print('          |')
        print(Fore.RED+' Warning!'+Style.RESET_ALL+' |')
        print('_ _ _ _ _ |')
        print("\nUpload a TXT or EML file ! , This extension is not allowed\n")
        return True
    
    
    if file_present(sys.argv[1]) == True and sys.argv[2] in arguments and allowed_file(sys.argv[1]) == True:
        return False
    

def save_file():
    if file_present(sys.argv[1]) and allowed_file(sys.argv[1]) == True:
        shutil.copy(sys.argv[1], 'Input/sample.txt')

def call_function_arguments():
    if sys.argv[2] == '-Eh':
        call_EH_functions()
    if sys.argv[2] == '-Ipinfo':
        ipaddress_information()
    if sys.argv[2] == '-Domaininfo':
        domainname_information()
    if sys.argv[2] == '-URLinfo':
        url_information()
if __name__ == '__main__':
    
    try:
        user_instruction() 
        if check_error()==False:
            save_file()
            call_function_arguments()
            print('\n')
            while True:
                print("\n****************************************************")
                print("                  Arguments:                       *")
                print("****************************************************")
                print('                                                   | ')
                print("      -Ipinfo           -> IP Information          |")            
                print("      -Domaininfo       -> Domain Information      |")
                print("      -URLinfo          -> URL Information         |")
                print('                                                   | ')
                print('**************************************************** ')
                print(" Try The Following After : -Domaininfo & -IPinfo   *")    
                print('**************************************************** ')
                print('                                                   | ')
                print("      -IPpassive        -> Passive DNS Information |")
                print("      -PortScan         -> Scan for Openports      |")
                print("      -Whois            -> Whois Information       |") 
                print('_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _|\n')
                
                a = input("Enter any of the above to know further Info or give exit: ")
                if a=='-Ipinfo':
                    ipaddress_information()

                if a=='-URLinfo':
                    url_information()

                if a=='-Domaininfo':
                    domainname_information()

                if a=='-PortScan':
                    portscan_information()

                if a=='-IPpassive':
                    passivedns_infomration()
                
                if a=='-Whois':
                    whois_information()

                if a=='exit':
                    break

    except:
        None
    