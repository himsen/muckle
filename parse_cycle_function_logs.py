#!/usr/bin/python2.7

import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

# Header size in a log file
HEADER_SIZE = 3

# Relative path to log directory
LOG_DIR = './'

medians_initiator_functions = []
medians_responder_functions = []

def switch_list(peer):

	if peer == 'initiator':
		return medians_initiator_functions
	elif peer == 'responder':
		return medians_responder_functions

	print 'Not found'
	return None

def parse_logs():

	data = []
	median_list = None
	date = None
	peer = ''
	sample_size = 0

	# Cycle through all files in directory
	for file in os.listdir(LOG_DIR):
		# Grab log files
		if file.endswith('cycle_functions_az.log'):
			with open(os.path.join(LOG_DIR, file), 'r') as fd:

				# Split by newline
				log = fd.read().split('\n')

				# Get header info
				# (data, function, cipher, warmup, complexity, stat)
				date = log[0]
				peer = log[1]
				sample_size = log[2]

				median_list = switch_list(peer)

				if median_list != None:
					for i in range(7):
						for j in range(int(sample_size)):
							data.append(log[HEADER_SIZE + i + j * 7])

						print data
						median_list.append(np.median(map(float, data)))
						data = []
					print median_list

	median_initiator = medians_initiator_functions[6]
	median_responder = medians_responder_functions[6]

	print 'Initiator median cycle count: {}'.format(median_initiator)
	print 'Responder median cycle count: {}'.format(median_responder)

	# Compute Other category
	for val in medians_initiator_functions[:6]:
		medians_initiator_functions[6] -= val
	for val in medians_responder_functions[:6]:
		medians_responder_functions[6] -= val

	return median_initiator, median_responder

def draw_grid_graphs(median_initiator, median_responder):

	labels = 'ECDH gen', 'SIDH gen', 'ECDH compute', 'SIDH compute', 'Read QKD keys', 'Derive keys', 'Other'
	labels_initiator = ['%s %1.3f %%' % (l, 100 * (float(s) / median_initiator)) for l, s in zip(labels, medians_initiator_functions)]
	labels_responder = ['%s %1.3f %%' % (l, 100 * (float(s) / median_responder)) for l, s in zip(labels, medians_responder_functions)]

	fig = plt.figure(figsize=(20,4))

	fig.suptitle('Clock cycles', fontsize=22)

	gs = gridspec.GridSpec(1, 2)
	ax1 = plt.subplot(gs[0])
	ax2 = plt.subplot(gs[1])

	ax1.pie(medians_initiator_functions, startangle=0)
	ax1.axis('equal')
	ax1.legend(labels_initiator, title='Function type', loc='right',  bbox_to_anchor=(1, 0, 0.3, 1))
	ax1.set_title('Initiator')

	pie2 = ax2.pie(medians_responder_functions, startangle=0)
	ax2.axis('equal')
	ax2.legend(labels_responder, title="Function type", loc="right",  bbox_to_anchor=(1, 0, 0.3, 1))
	ax2.set_title('Responder')

	plt.tight_layout(rect=[0, 0, 1, 0.9])
	plt.subplots_adjust(left=0.0, bottom=0.1, right=0.87, top=0.93)
	plt.show()

if __name__ == '__main__':

	median_initiator, median_responder = parse_logs()
	draw_grid_graphs(median_initiator, median_responder)
