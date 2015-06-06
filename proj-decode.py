#!/usr/bin/env python

import sys
import optparse
import binascii
import base64
import string

# Tables for CRYPO encoder Base64 translations
tableB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
tableATOM128 = "/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC"
tableMEGAN35 = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5"
tableZONG22 = "ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2"
tableHAZZ15 = "HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5"
tableGILA7 = "7ZSTJK+W=cVtBCasyf0gzA8uvwDEq3XH/1RMNOILPQU4klm65YbdeFrx2hij9nopG"
tableESAB46 = "ABCDqrs456tuvNOPwxyz012KLM3789=+QRSTUVWXYZabcdefghijklmnopEFGHIJ/"
tableTRIPO5 = "ghijopE+G78lmnIJQRXY=abcS/UVWdefABCs456tDqruvNOPwx2KLyz01M3Hk9ZFT"
tableTIGO3FX = "FrsxyzA8VtuvwDEqWZ/1+4klm67=cBCa5Ybdef0g2hij9nopMNO3GHIRSTJKLPQUX"
tableFERON74 = "75XYTabcS/UVWdefADqr6RuvN8PBCsQtwx2KLyz+OM3Hk9ghi01ZFlmnjopE=GIJ4"

# Text output colors
class txtcolors:
    PURPLE = '\033[95m'
    HEADER = '\033[94m' # Blue
    KEYWORD = '\033[92m' # Green
    WARNING = '\033[93m'
    FAIL = '\033[91m' # Red
    ENDC = '\033[0m' # Ends color scheme
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Change color of output if a key word is matched
def checkKeyWords(result):
    if "admin" in result or "root" in result or \
       "administrator" in result or "key" in result or \
       "pass" in result or "flag" in result:
        return "key"
    elif "Invalid" in result or "Non-printable" in result:
        return "fail"
    else:
        return "norm"

# Signal whether or not the result contains non-printable characters
def checkNonPrintable(result):
    if all(c in string.printable for c in result):
        return False
    else:
        return True

# Output printing function
def printOutput(alg, result):
    # Print upper border with a standard length unless "none" is given
    if alg != "none":
        print txtcolors.BOLD + txtcolors.HEADER + "----- %s" %alg, "-" * \
              (63 - len(alg)) + txtcolors.ENDC
    # Print result
    if result != "":
        if checkKeyWords(result) == "key":
            print txtcolors.KEYWORD + result + txtcolors.ENDC
        elif checkKeyWords(result) == "fail":
            print txtcolors.FAIL + result + txtcolors.ENDC
        else:
            print result
    
# Prevent the code below from running if it's just being imported
if __name__ == "__main__":

    # Define options and args
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", action="store", type="string", 
                      dest="outputFileName",
                      help="Write output to a file")

    (options, args) = parser.parse_args()

    # Handle options and args
    if options.outputFileName:
        print "Caught the output arg! File is ", options.outputFileName

    # Make sure we get something to decode
    if len(args) != 1:
        print "Please specify the string to decrypt. Use -h for help."
        sys.exit(1)

    # Read in ciphertext
    ciphertext = args[0]
    printOutput("CIPHERTEXT", ciphertext)

    # Decode Bin to ASCII
    try:
        ciphertext_bin = ciphertext.replace(" ","")
        ciphertext_hx = int('0b'+ciphertext_bin, 2)
        result_btoa = binascii.unhexlify('%x' %ciphertext_hx)
        if checkNonPrintable(result_btoa):
            printOutput("Bin to ASCII", "Non-printable chars in result")
        else:
            printOutput("Bin to ASCII", result_btoa)
    except TypeError:
        printOutput("Bin to ASCII", "Invalid string for this operation.")    
    except ValueError:
        printOutput("Bin to ASCII", "Invalid string for this operation.")    

    # Decode Hex to ASCII
    # Valid formats: 7071, "70 71", \x70\x71, "0x70 0x71"
    ciphertext_hex = ciphertext.replace("0x","")
    ciphertext_hex = ciphertext_hex.replace("x","")
    ciphertext_hex = ciphertext_hex.replace(" ","")
    try:
        result_htoa = binascii.unhexlify(ciphertext_hex)
        if checkNonPrintable(result_htoa):
            printOutput("Hex to ASCII", "Non-printable chars in result")
        else:
            printOutput("Hex to ASCII", result_htoa)
    except TypeError:
        printOutput("Hex to ASCII", "Invalid string for this operation.")  

    # Decode Base64
    try:
        result_b64 = base64.b64decode(ciphertext)
        if checkNonPrintable(result_b64):
            printOutput("Base64", "Non-printable chars in result")
        else:
            printOutput("Base64", result_b64)
    except TypeError:
        printOutput("Base64", "Invalid string for this operation.")

    # Decode reverse-order
    result_reverse = ""
    for letternum in range(len(ciphertext) -1, -1, -1):
        result_reverse += ciphertext[letternum]
    printOutput("Reverse String", result_reverse)

    # Decode Caesar Shift, aka rotation ciphers
    # First check to see if there are even any letters here
    flg_alpha = False
    for letternum in range(0, len(ciphertext)):
        if ciphertext[letternum].isalpha():
            flg_alpha = True
            break
    if flg_alpha == True:
        # 25 possible shifts to go through the whole alphabet
        for shiftnum in range(1,26):
            result_caesarshift = ""
            for letternum in range(0, len(ciphertext)):
                if ciphertext[letternum].isalpha():
                    letterord = ord(ciphertext[letternum])
                    resultord = letterord - shiftnum
                    # Rotate back to the start, if reaching end points
                    if ciphertext[letternum].isupper():
                        if resultord < ord("A"):
                            resultord += 26
                    if ciphertext[letternum].islower():
                        if resultord < ord("a"):
                            resultord += 26
                    result_caesarshift += chr(resultord)
                # Don't shift symbols/spaces
                else:
                    result_caesarshift += ciphertext[letternum]
            if shiftnum == 1:
                outputTitle = "Caesar Shift/ROT(n)" 
                printOutput(outputTitle, "")
            if checkKeyWords(result_caesarshift) == "key":
                print txtcolors.KEYWORD + "%02d: "%shiftnum + result_caesarshift + \
                      txtcolors.ENDC
            else:
                print "%02d: "%shiftnum + result_caesarshift
    else:
        printOutput("Caesar Shift", "No letters to rotate")

    # Decode ATOM-128, MEGAN-35, ZONG-22, HAZZ-15 ciphers
    # These all follow the same principle for decoding:
    # Translate the string to b64 using the tables above, then decode the b64
    dictTables = {"ATOM-128":tableATOM128, "MEGAN-35":tableMEGAN35, \
                  "ZONG-22":tableZONG22, "HAZZ-15":tableHAZZ15, \
                  "GILA-7":tableGILA7, "ESAB-46":tableESAB46, \
                  "TRIPO-5":tableTRIPO5, "TIGO-3FX":tableTIGO3FX, \
                  "FERON-74":tableFERON74 }
    printOutput("CRYPO CIPHERS", "")
    for method in ["ATOM-128", "MEGAN-35", "ZONG-22", "HAZZ-15", \
                   "GILA-7", "ESAB-46", "TRIPO-5", "TIGO-3FX", "FERON-74"]:
        try:
            trans = string.maketrans(dictTables[method], tableB64)
            result_method = base64.b64decode(ciphertext.translate(trans))
            if checkNonPrintable(result_method):
                printOutput("none", method + ": " + "Non-printable chars in result")
            else:
                printOutput("none", method + ": " + result_method)
        except TypeError:
            print txtcolors.FAIL + method + ": Invalid string for this operation" + \
                  txtcolors.ENDC
