#!/usr/bin/python
import sys, subprocess, re, os, time

def run_timings(prefix, num):
    fout = open("./timing_report.csv",'w')
    os.chdir("./")
    subprocess.Popen(['make','clean'])
    time.sleep(1)
    subprocess.Popen(['make'])
    time.sleep(1)
    p = subprocess.Popen(['./keygen'])

    files = []
    current_dir = os.listdir('./')
    for c in current_dir:
        if c.startswith(prefix):
            files.append(c)

    fout.write("File Name,Enc Time,Enc Tag Comp,Total Enc Time,Dec Time Dec,Tag Verify,Dec Tag Comp,Total Dec Time\n")

    for f in files:
        enc_t  = 0.0
        etag_t = 0.0
        etot_t = 0.0
        dec_t  = 0.0
        tver_t = 0.0
        dtag_t = 0.0
        dtot_t = 0.0
        for i in xrange(num):
            p = subprocess.Popen(['./encrypt','key.txt',f,'-t'], stdout=subprocess.PIPE)
            out,err = p.communicate()
            times   = re.findall(r"\d+.\d+",out)
            enc_t  += float(times[0])
            etag_t += float(times[1])
            etot_t += float(times[2])
            time.sleep(1)

            p = subprocess.Popen(['./decrypt','key.txt', 'ciphertext.txt','-t'], stdout=subprocess.PIPE)
            out,err = p.communicate()
            times   = re.findall(r"\d+.\d+",out)
            dec_t  += float(times[0])
            tver_t += float(times[1])
            dtag_t += float(times[2])
            dtot_t += float(times[3])
            time.sleep(1)

        fout.write(f+',%f,%f,%f,%f,%f,%f,%f\n' % (enc_t/float(num),etag_t/float(num),etot_t/float(num), \
                                dec_t/float(num),tver_t/float(num),dtag_t/float(num),dtot_t/float(num)))
        print "################################################################"
        print "Average encryption time for %s - %f seconds" % (f, enc_t/float(num))
        print "Average tag comp time for %s - %f seconds" % (f, etag_t/float(num))
        print "Average total time for %s - %f seconds" % (f, etot_t/float(num))
        print "----------------------------------------------------------------"
        print "Average decryption time for %s - %f seconds" % (f, dec_t/float(num))
        print "Average tag verify time for %s - %f seconds" % (f, tver_t/float(num))
        print "Average tag comp time for %s - %f seconds" % (f, dtag_t/float(num))
        print "Average total time for %s - %f seconds" % (f, dtot_t/float(num))
            




if __name__ == "__main__":
    if(len(sys.argv) != 3):
        print "Usage: %s <Sample Text Prefix> <Number of Timing Runs>"
        sys.exit()
    else:
        run_timings(sys.argv[1], int(sys.argv[2]))
