#!/usr/bin/python2.7

import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

# Header size in a log file
HEADER_SIZE = 3

# Relative path to log directory
LOG_DIR = './logs'

def parse_logs():

	data = []
	date = None
	peer = ''
	sample_size = 0

	# Cycle through all files in directory
	for file in os.listdir(LOG_DIR):
		# Grab log files
		if file.endswith('cycle.log'):
			with open(os.path.join(LOG_DIR, file), 'r') as fd:

				# Split by newline
				log = fd.read().split('\n')

				# Get header info
				# (data, function, cipher, warmup, complexity, stat)
				date = log[0]
				peer = log[1]
				sample_size = log[2]

				# For each msg size, and for each chunk length,
				# retrieve the measured clock cycles
				for i in range(0, int(sample_size)):
					data.append(log[HEADER_SIZE + i])

				print 'Median cycles: {}'.format(peer)
				print np.median(map(float ,data))

if __name__ == '__main__':

	parse_logs()
