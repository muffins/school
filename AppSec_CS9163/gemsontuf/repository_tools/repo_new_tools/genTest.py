i = 0
for j in range(9000):
	mystr = str(i)
	filename = "tests/" + mystr + ".txt" 
	with open(filename, 'w') as f:
		f.write(mystr)
		f.close()
	i += 1
