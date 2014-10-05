#!/usr/bin/python
import sys, subprocess, re, os, time

def run_timings(prefix, num):
    os.chdir("./")
    subprocess.Popen(['make','clean'])
    time.sleep(1)
    subprocess.Popen(['make'])
    time.sleep(1)
    cmd = './keygen >key.hex'
    p = subprocess.Popen(cmd, shell = True)
    
    files = []
    current_dir = os.listdir('./')
    for c in current_dir:
        if c.startswith(prefix):
            files.append(c)
    
    for f in files:
        enc_t = 0.0
        dec_t = 0.0
        for i in xrange(num):
            
            #            p = subprocess.Popen(['./encrypt','key.hex',f,'>','ciphertext.hex','-t'], stdout=subprocess.PIPE)
            cmd = './encrypt key.hex ' + f+ '> ciphertext.hex -t'
            p = subprocess.Popen(cmd, shell = True, stderr=subprocess.PIPE)

            out,err = p.communicate()
            enc_t += float(re.findall(r"\d+.\d+",err)[0])
            time.sleep(1)
            

#           p = subprocess.Popen(['./decrypt','key.hex', 'ciphertext.hex', '>','decrypted.hex','-t'], stdout=subprocess.PIPE)

            cmd = './decrypt key.hex ciphertext.hex > decrypted.hex -t'
            p = subprocess.Popen(cmd, shell = True, stderr=subprocess.PIPE)
            
            out,err = p.communicate()
            dec_t += float(re.findall(r"\d+.\d+",err)[0])
            time.sleep(1)
        print "Average encryption time for %s - %f seconds" % (f, enc_t/float(num))
        print "Average decryption time for %s - %f seconds" % (f, dec_t/float(num))





if __name__ == "__main__":
    if(len(sys.argv) != 3):
        print "Usage: %s <Sample Text Prefix> <Number of Timing Runs>"
        sys.exit()
    else:
        run_timings(sys.argv[1], int(sys.argv[2]))
