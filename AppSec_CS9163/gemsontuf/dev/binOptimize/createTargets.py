import threading
import os
import hashlib

class genTargets(threading.Thread):
	def __init__(self, threadName, name, start, end):
		threading.Thread.__init__(self)
		self.start = start
		self.end = end
		self.threadName = threadName
		self.repo = "./repository/targets/" 

	def run(self):
		i = 1000000
		for k in range(self.start, self.end):
			name = i + k
			
			t = hashlib.sha256()
			t.update(self.repo + str(name))
			y = t.hexdigest()
			num = int(y[0:3], 16)
            
			folder = ''
			if num < 1024:
				folder = self.repo + str(1024) + "/" + str(name)
			elif num >= 1024 and num < 2048:
				folder = self.repo + str(2048) + "/" + str(name)
			elif num >= 2048 and num < 3072:
				folder = self.repo + str(3072) + "/" + str(name)
			else:
				folder = self.repo + str(4096) + "/" + str(name)
				
			f = open(folder, "w")
			f.close()
		print self.threadName + " complete"

os.makedirs("./repository/targets/1024")
os.makedirs("./repository/targets/2048")
os.makedirs("./repository/targets/3072")
os.makedirs("./repository/targets/4096")

for i in range(0, 15):
	name = hex(i)
	name = name[2:]

	a = genTargets(name, name, i * 10000, (i * 10000) + 10000)

	a.run()

print "Exit"
