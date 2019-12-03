#!/usr/bin/python2.7

import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

COUNT = 8

# Header size in a log file
HEADER_SIZE = 3

# Relative path to log directory
LOG_DIR = './'

LOG_FILE ='walltime_functions_az.log'
#LOG_FILE = 'walltime_functions_region.log'

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
		if file.endswith(LOG_FILE):
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
					for i in range(COUNT):
						for j in range(int(sample_size)):
							data.append(log[HEADER_SIZE + i + j * COUNT])

						print data
						median_list.append(np.median(map(float, data)))
						data = []
					print median_list

	median_initiator = medians_initiator_functions[COUNT - 1]
	median_responder = medians_responder_functions[COUNT - 1]

	print 'Initiator median wall-time: {}'.format(median_initiator)
	print 'Responder median wall-time: {}'.format(median_responder)

	# Compute Other category
	for val in medians_initiator_functions[:COUNT - 1]:
		medians_initiator_functions[COUNT - 1] -= val
	for val in medians_responder_functions[:COUNT - 1]:
		medians_responder_functions[COUNT - 1] -= val

	return median_initiator, median_responder

def draw_grid_graphs(median_initiator, median_responder):

	labels = 'ECDH gen', 'ECDH compute', 'SIDH gen', 'SIDH compute', 'Read QKD keys', 'Derive keys', 'Network', 'Other'

	ll = []
	lll = []

	ll.append(medians_initiator_functions[0])
	ll.append(medians_initiator_functions[3])
	ll.append(medians_initiator_functions[1])
	ll.append(medians_initiator_functions[4])
	ll.append(medians_initiator_functions[5])
	ll.append(medians_initiator_functions[6])
	ll.append(medians_initiator_functions[2])
	ll.append(medians_initiator_functions[7])

	lll.append(medians_responder_functions[1])
	lll.append(medians_responder_functions[3])
	lll.append(medians_responder_functions[2])
	lll.append(medians_responder_functions[4])
	lll.append(medians_responder_functions[5])
	lll.append(medians_responder_functions[6])
	lll.append(medians_responder_functions[0])
	lll.append(medians_responder_functions[7])

	labels_initiator = ['%s %1.3f %%' % (l, 100 * (float(s) / median_initiator)) for l, s in zip(labels, ll)]
	labels_responder = ['%s %1.3f %%' % (l, 100 * (float(s) / median_responder)) for l, s in zip(labels, lll)]

	colors = ['orangered', 'black', 'fuchsia', 'yellow', 'cyan', 'grey', 'blue', 'lime']

	fig = plt.figure(figsize=(20,7))

	fig.suptitle('Wall-time', fontsize=36)

	gs = gridspec.GridSpec(1, 2)
	ax1 = plt.subplot(gs[0])
	ax2 = plt.subplot(gs[1])
	print medians_initiator_functions
	print ll
	ax1.pie(ll, startangle=0, colors=colors)
	ax1.axis('equal')
	legend = ax1.legend(labels_initiator, title='Function type', loc='right',  bbox_to_anchor=(1, 0, 0.47, 1), prop={'size': 18})
	plt.setp(legend.get_title(), fontsize='x-large')
	ax1.set_title('Initiator', fontsize=26)

	ax2.pie(lll, startangle=0, colors=colors)
	ax2.axis('equal')
	legend = ax2.legend(labels_responder, title="Function type", loc="right",  bbox_to_anchor=(1, 0, 0.47, 1), prop={'size': 18})
	plt.setp(legend.get_title(), fontsize='x-large')
	ax2.set_title('Responder', fontsize=26)

	#plt.tight_layout(rect=[0, 0, 1, 0.85])
	plt.subplots_adjust(left=0.0, bottom=0.1, right=0.80, top=0.80, wspace=0.38)
	plt.show()

if __name__ == '__main__':

	median_initiator, median_responder = parse_logs()
	draw_grid_graphs(median_initiator, median_responder)
