#!/usr/bin/python
import sys, subprocess, re, os, time

def run_timings(prefix, num):
    fout = open("./timing_report.csv",'w')
    os.chdir("./")
    subprocess.Popen(['make','clean'])
    time.sleep(2)
    subprocess.Popen(['make'])
    time.sleep(2)
    p = subprocess.Popen(['./hybridkeygen'])
    time.sleep(2)

    files = []
    current_dir = os.listdir('./')
    for c in current_dir:
        if c.startswith(prefix):
            files.append(c)

    fout.write("File Name, Total Enc Time, Symmetric Encryption Time, Asymmetric Encryption Time, Enc HMAC Comp, Total Dec Time, Symmetric Decryption Time, Asymmetric Decryption Time, Dec HMAC Comp\n")

    for f in files:
	etot_t = 0.0        
	symenc_t  = 0.0
        asymenc_t = 0.0
	encHMAC_t = 0.0
        dtot_t = 0.0
        symdec_t  = 0.0
        asymdec_t = 0.0
        decHMAC_t = 0.0
        
        for i in xrange(num):
            p = subprocess.Popen(['./hybridencrypt','publickey.txt',f,'-t'], stdout=subprocess.PIPE)
            out,err = p.communicate()
            times   = re.findall(r"\d+.\d+",out)
            etot_t  += float(times[0])
            symenc_t += float(times[1])
            asymenc_t += float(times[2])
            encHMAC_t += float(times[3])		
            time.sleep(2)

            p = subprocess.Popen(['./hybriddecrypt','publickey.txt', 'secretkey.txt', 'ciphertext.txt','-t'], stdout=subprocess.PIPE)
            out,err = p.communicate()
            times   = re.findall(r"\d+.\d+",out)
            dtot_t  += float(times[0])
            symdec_t += float(times[1])
            asymdec_t += float(times[2])
            decHMAC_t += float(times[3])
            time.sleep(2)

        fout.write(f+',%f,%f,%f,%f,%f,%f,%f,%f\n' % (etot_t/float(num),symenc_t/float(num),asymenc_t/float(num), encHMAC_t/float(num), \
                                dtot_t/float(num),symdec_t/float(num),asymdec_t/float(num),decHMAC_t/float(num)))
        print "################################################################"
        print "Average encryption time for %s - %f seconds" % (f, etot_t/float(num))
        print "Average symmetric encryption time for %s - %f seconds" % (f, symenc_t/float(num))
        print "Average asymmetric encryption time for %s - %f seconds" % (f, asymenc_t/float(num))        
	print "Average encryption HMAC computation time for %s - %f seconds" % (f, encHMAC_t/float(num))
	print "----------------------------------------------------------------"
        print "Average decryption time for %s - %f seconds" % (f, dtot_t/float(num))
        print "Average symmetric decryption time for %s - %f seconds" % (f, symdec_t/float(num))
        print "Average asymmetric decryption time for %s - %f seconds" % (f, asymdec_t/float(num))
        print "Average decryption HMAC computation time for %s - %f seconds" % (f, decHMAC_t/float(num))
            




if __name__ == "__main__":
    if(len(sys.argv) != 3):
        print "Usage: %s <Sample Text Prefix> <Number of Timing Runs>"
        sys.exit()
    else:
        run_timings(sys.argv[1], int(sys.argv[2]))
