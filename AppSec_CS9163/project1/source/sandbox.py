"""
Nick Anderson, 09/17/2013
Application Security - Project 1, Turing Complete Sandbox

This is a python implementation of the turing complete sandbox for the Application
Security course at NYU-Poly.

This program takes as input the name of a program file which the sandbox will run.

This sand box takes from the command line one parameter, being the program which
the sandbox should run.  The structure of the program given to the sandbox should 
contain one to many of the following types of commands.  

* Variable Logic Operations        
    VAR ASGN X 10  # Assigns the value of X to be 10
    VAR ADD X 2    # Adds two to the value of X and stores the result in X
    VAR SUB Z 2    # Subtracts 2 from the value of Z and stores the result in Z
    VAR MUL Y 3    # Multiplies the value of Y by 3 and stores the result in Y
    VAR DIV X 4    # Divides the value of X by 4 and stores the result in X
    VAR EXP X 4    # Raises the value of X by 4 and stores the result in X

* Basic Arithmetic Operations
    ADD 1 2     # Adds the values 1 and 2
    SUB 1 2     # Subtracts the values 1 and 2
    MUL 1 2     # Multiplies the value 1, by the value 2
    DIV 1 2     # Divides 1 by the integer 2
    EXP 1 2     # Raises 1 to the 2nd power
    MOD 2 4     # Computes 2 modulo 4, similar to the % operator in Python
    
* Looping Constructs
    WHILE 'condition'  # While the condition is true
    'commands'         # Run these commands
    ENDWHILE           # Signals the completion of the while loop
    
* If statements
    IF 'condition'  # If the condition is true...
    'commands'      # Run these commands
    ELSE            # Otherwise...
    'commands'      # Run these commands
    ENDIF           # Signals the completion of the if statement.

* Verbosity Operations
    PRINT VAR X   # Prints the value currently stored in the variable X
    PRINT 1       # Will print the character '1'
    PRINT "HELLO"   # Will print the string 'Hello'


For additional information, please see the documentation accompanying this
program.
"""

from sys import argv, exit
from re  import search

# Error Messages
def parse_error(lnum):
    print("PARSE ERROR: Invalid Syntax - line %d" % lnum)
    exit()

def exec_error(cmd):
    print("EXECUTION ERROR: Unable to execute command:\n%s\nExiting." % cmd)
    exit()

def file_error(fname):
    print("FILE ERROR: Unable to open %s for reading" % fname)
    exit()

def logic_error(error):
    print("LOGICAL ERROR: %s" % error)
    exit()
#################################### END OF ERROR HANDLERS ####################################

# Parse logical statements
def parse_logic(tokens, lnum):
    logic = []
    cond  = ""
    if(len(tokens) == 3):
        lhs = 0
        rhs = 0
        try:
            lhs  = int(tokens[0])
            cond = str(tokens[1]).lower()
            rhs  = int(tokens[2])
        except: parse_error(lnum)
        if(cond != "lt" and cond != "gt"):
                logic_error("Invalid conditional - '%s', line %d" % (cond, lnum))
        logic.append(lhs)
        logic.append(cond)
        logic.append(rhs)
        return 1, logic
    elif(len(tokens) == 4):
        chk = ""
        lhs = ""
        rhs = 0
        try:
            chk  = str(tokens[0]).lower()
            lhs  = str(tokens[1])
            cond = str(tokens[2]).lower()
            rhs  = int(tokens[3])
        except: parse_error(lnum)
        if(cond != "lt" and cond != "gt"):
                logic_error("Invalid conditional - '%s', line %d" % (cond, lnum))
        if(chk == "var"):
            logic.append(chk)
            logic.append(lhs)
            logic.append(cond)
            logic.append(rhs)
            return 1, logic
    elif(len(tokens) == 5):
        chk1 = ""
        lhs  = ""
        chk2 = ""
        rhs  = ""
        try:
            chk1 = str(tokens[0]).lower()
            lhs  = str(tokens[1])
            cond = str(tokens[2]).lower()
            chk2 = str(tokens[3]).lower()
            rhs  = str(tokens[4])
        except: parse_error(lnum)
        if(cond != "lt" and cond != "gt"):
                logic_error("Invalid conditional - '%s', line %d" % (cond, lnum))
        if(chk1 == "var" and chk2 == "var"):
            logic.append(chk1)
            logic.append(lhs)
            logic.append(cond)
            logic.append(chk2)
            logic.append(rhs)
            return 1, logic
    else:
        return 0, []
    
# Parse the input
def parse(line, lnum):
    toks = line.split()
    cmd  = ""
    var1 = ""
    var2 = ""
    op   = ""
    cond = ""
    val1 = 0
    val2 = 0
    try:
        cmd = str(toks[0]).lower()
    except: parse_error(lnum)
    if(cmd == "print"):
        try:
            chk  = str(toks[1])
            var1 = str(toks[2])
            if(chk.lower() == "var"):
                return ["vprint",var1]
        except: pass
        try:
            val1 = int(toks[1])
            return ["iprint",val1]
        except: pass
        try:
            text  = ' '.join([str(x) for x in toks[1:]])
            regex = r'\".+?\"'
            val1 = search(regex, text).group()
            return ["sprint",val1]
        except: pass
        parse_error(lnum)
    elif(cmd == "var"):
        try: 
            op   = str(toks[1])
            var1 = str(toks[2])
        except: parse_error(lnum)
        try:
            val1 = int(toks[3])
            if(op.lower() == "asgn"):
                return ["viasgn", var1, val1]
            elif(op.lower() == "add"):
                return ["viadd", var1, val1]
            elif(op.lower() == "sub"):
                return ["visub", var1, val1]
            elif(op.lower() == "mul"):
                return ["vimul", var1, val1]
            elif(op.lower() == "div"):
                return ["vidiv", var1, val1]
            elif(op.lower() == "exp"):
                return ["viexp", var1, val1]
            elif(op.lower() == "mod"):
                return ["vimod", var1, val1]
        except: pass
        try:
            var2 = str(toks[3])
            if(op.lower() == "asgn"):
                return ["vvasgn", var1, var2]
            elif(op.lower() == "add"):
                return ["vvadd", var1, var2]
            elif(op.lower() == "sub"):
                return ["vvsub", var1, var2]
            elif(op.lower() == "mul"):
                return ["vvmul", var1, var2]
            elif(op.lower() == "div"):
                return ["vvdiv", var1, var2]
            elif(op.lower() == "exp"):
                return ["vvexp", var1, var2]
            elif(op.lower() == "mod"):
                return ["vvmod", var1, var2]
        except: pass
        parse_error(lnum)
    elif(cmd == "while"):
        (r,logic) = parse_logic([x for x in toks[1:]],lnum)
        if(r == 1):
            return ["while",logic]
        else:
            parse_error(lnum)
    elif(cmd == "endwhile"):
        return ["endwhile"]
    elif(cmd == "if"):
        (r,logic) = parse_logic([x for x in toks[1:]],lnum)
        if(r == 1):
            return ["if",logic]
        else:
            parse_error(lnum)
    elif(cmd == "else"):
        return ["else"]
    elif(cmd == "endif"):
        return ["endif"]
    elif(cmd == "add"):
        try:
            val1 = int(toks[1])
            val2 = int(toks[2])
        except: parse_error(lnum)
        return ["iiadd", val1, val2]
    elif(cmd == "sub"):
        try:
            val1 = int(toks[1])
            val2 = int(toks[2])
        except: parse_error(lnum)
        return ["sub", val1, val2]
    elif(cmd == "mul"):
        try:
            val1 = int(toks[1])
            val2 = int(toks[2])
        except: parse_error(lnum)
        return ["iimul", val1, val2]
    elif(cmd == "div"):
        try:
            val1 = int(toks[1])
            val2 = int(toks[2])
        except: parse_error(lnum)
        return ["iidiv", val1, val2]
    elif(cmd == "exp"):
        try:
            val1 = int(toks[1])
            val2 = int(toks[2])
        except: parse_error(lnum)
        return ["iiexp", val1, val2]
    elif(cmd == "mod"):
        try:
            val1 = int(toks[1])
            val2 = int(toks[2])
        except: parse_error(lnum)
        return ["iimod", val1, val2]
    else:
        return []

def parse_while(lines,c_inst):
    cmds  = []
    nexti = []
    endf  = False
    while(not endf and c_inst < len(lines)):
        nexti = parse(lines[c_inst], c_inst+1)
        if(nexti[0] == "endwhile"):
            endf = True
            break
        elif(nexti[0] == "if"):
            if_cmds, else_cmds, c_inst = parse_if(lines,c_inst+1)
            nexti.append(if_cmds)
            nexti.append(else_cmds)
            cmds.append(nexti)
        elif(nexti[0] == "while"):
            w_cmds, c_inst = parse_while(lines, c_inst+1)
            nexti.append(w_cmds)
            cmds.append(nexti)
        elif(nexti[0] == "else" or nexti[0] == "endif"):
            parse_error(c_inst+1)
        else:
            cmds.append(nexti)
        c_inst += 1
    if(endf):
        return cmds, c_inst
    else:
        parse_error(c_inst+1)

def parse_if(lines,c_inst):
    if_cmds   = []
    else_cmds = []
    nexti     = []
    endf      = False
    els       = False
    while(not endf and c_inst < len(lines)):
        nexti = parse(lines[c_inst], c_inst+1)
        if(nexti[0] == "endif"):
            endf = True
            break
        elif(nexti[0] == "while" and not els):
            w_cmds, c_inst = parse_while(lines, c_inst+1)
            nexti.append(w_cmds)
            if_cmds.append(nexti)
        elif(nexti[0] == "while" and els):
            w_cmds, c_inst = parse_while(lines, c_inst+1)
            nexti.append(w_cmds)
            else_cmds.append(nexti)
        elif(nexti[0] == "if" and not els):
            i_cmds, e_cmds, c_inst = parse_if(lines, c_inst+1)
            nexti.append(i_cmds)
            nexti.append(e_cmds)
            if_cmds.append(nexti)
        elif(nexti[0] == "if" and els):
            i_cmds, e_cmds, c_inst = parse_if(lines, c_inst+1)
            nexti.append(i_cmds)
            nexti.append(e_cmds)
            else_cmds.append(nexti)
        elif(nexti[0] == "else" and not els):
            els = True
        elif(not els):
            if_cmds.append(nexti)
        elif(els):
            else_cmds.append(nexti)
        else:
            parse_error(c_inst+1)
        c_inst += 1
    if(endf):
        return if_cmds, else_cmds, c_inst
    else:
        parse_error(c_inst+1)
#################################### END OF PARSE ####################################

def exec_c(cmd, vrbles):
    k     = set(vrbles.keys())
    blist = set(["add", "sub", "var", "mul", "exp", "div", "mod", "while", "if", "endwhile", "endif", "else", "asgn"])

    if((cmd[-1] == 0) and (("div" in cmd[0]) or ("mod" in cmd[0]))):
        logic_error("division by zero")
    if(cmd[0].startswith("v") and cmd[1] in blist):
        exec_error("Illegal variable name - '%s'" % cmd[1])
    if(cmd[0] == "iiadd"):
        print("RSLT: %d + %d = %d" % (cmd[1], cmd[2], int(cmd[1]+cmd[2])))
    elif(cmd[0] == "iisub"):
        print("RSLT: %d - %d = %d" % (cmd[1], cmd[2], int(cmd[1]-cmd[2])))
    elif(cmd[0] == "iimul"):
        print("RSLT: %d * %d = %d" % (cmd[1], cmd[2], int(cmd[1]*cmd[2])))
    elif(cmd[0] == "iidiv" and cmd[2] != 0):
        print("RSLT: %d * %d = %d" % (cmd[1], cmd[2], int(cmd[1]/cmd[2])))
    elif(cmd[0] == "iiexp"):
        print("RSLT: %d * %d = %d" % (cmd[1], cmd[2], int(cmd[1]**cmd[2])))
    elif(cmd[0] == "iimod"):
        print("RSLT: %d * %d = %d" % (cmd[1], cmd[2], int(cmd[1]%cmd[2])))
    elif(cmd[0] == "sprint"):
        print("PRINT STRING: %s" % cmd[1])
    elif(cmd[0] == "iprint"):
        print("PRINT INT: %d" % cmd[1])
    elif(cmd[0] == "vprint" and cmd[1] in set(vrbles.keys())):
        print("PRINT VAR %s: %s" % (cmd[1],vrbles[cmd[1]]))
    elif(cmd[0] == "viasgn"):
        vrbles[cmd[1]] = cmd[2]
    elif(cmd[0] == "viadd"):
        vrbles[cmd[1]] = vrbles[cmd[1]]+cmd[2] if cmd[1] in k else cmd[2]
    elif(cmd[0] == "visub"):
        vrbles[cmd[1]] = vrbles[cmd[1]]-cmd[2] if cmd[1] in k else cmd[2]
    elif(cmd[0] == "vimul"):
        vrbles[cmd[1]] = vrbles[cmd[1]]*cmd[2] if cmd[1] in k else cmd[2]
    elif(cmd[0] == "vidiv"):
        vrbles[cmd[1]] = vrbles[cmd[1]]/cmd[2] if cmd[1] in k else cmd[2]
    elif(cmd[0] == "viexp"):
        vrbles[cmd[1]] = vrbles[cmd[1]]**cmd[2] if cmd[1] in k else cmd[2]
    elif(cmd[0] == "vimod"):
        vrbles[cmd[1]] = vrbles[cmd[1]]%cmd[2] if cmd[1] in k else cmd[2]
    elif(cmd[0] == "vvasgn"):
        if(cmd[1] in k and cmd[2] in k):
            vrbles[cmd[1]] = vrbles[cmd[2]]
        elif(cmd[1] in k):
            vrbles[cmd[2]] = 0
        elif(cmd[2] in k):
            vrbles[cmd[1]] = 0
        else:
            vrbles[cmd[1]] = 0
            vrbles[cmd[2]] = 0
    elif(cmd[0] == "vvadd"):
        if(cmd[1] in k and cmd[2] in k):
            vrbles[cmd[1]] = vrbles[cmd[1]]+vrbles[cmd[2]]
        elif(cmd[2] in k and cmd[1] not in k):
            vrbles[cmd[1]] = vrbles[cmd[2]]
        elif(cmd[1] in k and cmd[2] not in k):
            vrbles[cmd[2]] = 0
        else:
            vrbles[cmd[1]] = 0
            vrbles[cmd[2]] = 0
    elif(cmd[0] == "vvsub"):
        if(cmd[1] in k and cmd[2] in k):
            vrbles[cmd[1]] = vrbles[cmd[1]]-vrbles[cmd[2]]
        elif(cmd[2] in k and cmd[1] not in k):
            vrbles[cmd[1]] = -vrbles[cmd[2]]
        elif(cmd[1] in k and cmd[2] not in k):
            vrbles[cmd[2]] = 0
        else:
            vrbles[cmd[1]] = 0
            vrbles[cmd[2]] = 0
    elif(cmd[0] == "vvmul"):
        if(cmd[1] in k and cmd[2] in k):
            vrbles[cmd[1]] = vrbles[cmd[1]]*vrbles[cmd[2]]
        elif(cmd[2] in k and cmd[1] not in k):
            vrbles[cmd[1]] = 0
        else:
            vrbles[cmd[1]] = 0
            vrbles[cmd[2]] = 0
    elif(cmd[0] == "vvdiv"):
        if(cmd[1] in k and cmd[2] in k):
            vrbles[cmd[1]] = vrbles[cmd[1]]/vrbles[cmd[2]]
        elif(cmd[2] in k and cmd[1] not in k):
            vrbles[cmd[1]] = 0
        else:
            logic_error("division by zero")
    elif(cmd[0] == "vvexp"):
        if(cmd[1] in k and cmd[2] in k):
            vrbles[cmd[1]] = vrbles[cmd[1]]**vrbles[cmd[2]]
        elif(cmd[2] in k and cmd[1] not in k):
            vrbles[cmd[1]] = 0
        else:
            vrbles[cmd[1]] = 1
            vrbles[cmd[2]] = 0
    elif(cmd[0] == "vvmod"):
        if(cmd[1] in k and cmd[2] in k):
            vrbles[cmd[1]] = vrbles[cmd[1]]%vrbles[cmd[2]]
        elif(cmd[2] in k and cmd[1] not in k):
            vrbles[cmd[1]] = 0
        else:
            logic_error("division by zero")
    else:
        exec_error(' '.join([str(x) for x in cmd]))

def exec_while(cmds, vrbles):
    logic  = cmds[1]
    w_cmds = cmds[2]
    lhs    = 0
    rhs    = 0
    if(len(logic) == 3):
        if(logic[1] == "lt"):
            while(logic[0] < logic[2]):
                for t in w_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
        else:
            while(logic[0] > logic[2]):
                for t in w_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)

    elif(len(logic) == 4 and logic[1] in set(vrbles.keys())):
        if(logic[2] == "lt"):
            while(vrbles[logic[1]] < logic[3]):
                for t in w_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
        else:
            while(vrbles[logic[1]] > logic[3]):
                for t in w_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
    elif(len(logic) == 5 and (logic[1] in set(vrbles.keys()) and logic[4] in set(vrbles.keys()))):
        if(logic[2] == "lt"):
            while(vrbles[logic[1]] < vrbles[logic[4]]):
                for t in w_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
        else:
            while(vrbles[logic[1]] > vrbles[logic[4]]):
                for t in w_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
    else:
        logic_error("Invalid control logic")

def exec_if(cmds, vrbles):
    logic  = cmds[1]
    i_cmds = cmds[2]
    e_cmds = cmds[3]
    lhs    = 0
    rhs    = 0
    if(len(logic) == 3):
        if(logic[1] == "lt"):
            if(logic[0] < logic[2]):
                for t in i_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
            else:
                for t in e_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
        else:
            if(logic[0] > logic[2]):
                for t in i_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
            else:
                for t in e_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
    elif(len(logic) == 4 and logic[1] in set(vrbles.keys())):
        if(logic[2] == "lt"):
            if(vrbles[logic[1]] < logic[3]):
                for t in i_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
            else:
                for t in e_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
        else:
            if(vrbles[logic[1]] > logic[3]):
                for t in i_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
            else:
                for t in e_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
    elif(len(logic) == 5 and (logic[1] in set(vrbles.keys()) and logic[4] in set(vrbles.keys()))):
        if(logic[2] == "lt"):
            if(vrbles[logic[1]] < vrbles[logic[4]]):
                for t in i_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
            else:
                for t in e_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
        else:
            if(vrbles[logic[1]] > vrbles[logic[4]]):
                for t in i_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
            else:
                for t in e_cmds:
                    if(t[0] == "while"):
                        exec_while(t, vrbles)
                    elif(t[0] == "if"):
                        exec_if(t, vrbles)
                    else:
                        exec_c(t, vrbles)
    else:
        logic_error("Invalid control logic")
#################################### END OF EXEC ####################################

# Handler
def handler(fname):
    try:
        fin  = open(fname,"r")
    except: file_error(fname)
    lines = [x.strip() for x in fin.readlines() if x.strip() != '']
    cmds  = []
    # Parse
    i = 0
    while i < len(lines):
        r = parse(lines[i],i+1)
        if(len(r) != 0):
            if(r[0] == "while"):
                while_coms, nnum = parse_while(lines, i+1)
                r.append(while_coms)
                cmds.append(r)
                i = nnum
            elif(r[0] == "if"):
                if_coms, els_coms, nnum = parse_if(lines, i+1)
                r.append(if_coms)
                r.append(els_coms)
                cmds.append(r)
                i = nnum
            elif(r[0] == "endwhile" or r[0] == "else" or r[0] == "endif"):
                parse_error(i+1)
            else:
                cmds.append(r)
            i += 1
        else:
            parse_error(i+1)
    # Execute
    vrbles = {}
    for c in cmds:
        if(c[0] == "while"):
            exec_while(c, vrbles)
        elif(c[0] == "if"):
            exec_if(c, vrbles)
        else:
            exec_c(c, vrbles)
        
# Entry Point
if __name__ == '__main__':
    if(len(argv) != 2):
        print("Usage: python %s <ProgramFile.in>" % argv[0])
        print("For detailed list of commands, please see documentation.pdf")
        exit()
    else:
        handler(argv[1])