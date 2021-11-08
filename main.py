from scapy.all import *
from threading import Thread
import pandas
import time
import os
import cv2
import numpy as np
# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
signlArray=[]

def callback(packet):
	global signlArray
	blank_image = np.zeros((1500,2000,3), np.uint8)
	if packet.haslayer(Dot11Beacon):
		# extract the MAC address of the network
		bssid = packet[Dot11].addr2
		# print(bssid)
		# get the name of it
		ssid = packet[Dot11Elt].info.decode()
		try:
			dbm_signal = packet.dBm_AntSignal
		except:
			dbm_signal = 0


		print(bssid,"|",dbm_signal) 
		signlArray.append(dbm_signal)  
		# extract network stats
		stats = packet[Dot11Beacon].network_stats()
		# get the channel of the AP
		channel = stats.get("channel")
		# get the crypto
		crypto = stats.get("crypto")
		networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
		if(len(signlArray)>100):

			signlArray=signlArray[1:]
		pts=[]
		for i in range(len(signlArray)):
			if(i==0):
				continue
			pts.append([i*20, 500-(signlArray[i]+70)*60])
		pts2 = np.array(pts,np.int32)
		  
		pts2 = pts2.reshape((-1, 1, 2))


		blank_image = cv2.polylines(blank_image, [pts2], False, (0, 0, 255), 2)
		blank_image = cv2.line(blank_image, (0,500), (2000,500), (255, 255, 255), 1)

		cv2.imshow('Frame',blank_image)
		cv2.waitKey(1)
		# if cv2.waitKey(25) & 0xFF == ord('q'):

	print(signlArray)



def print_all():
	while True:
		os.system("clear")
		#print(networks["BSSID"])
		time.sleep(0.1)


def change_channel():
	ch = 10
	while True:
		os.system(f"iwconfig {interface} channel {ch}")
		# switch channel from 1 to 14 each 0.5s
	   # ch = ch % 14 + 1
		time.sleep(0.5)


if __name__ == "__main__":
	# interface name, check using iwconfig
	interface = "wlan0mon"
	# start the thread that prints all the networks
	printer = Thread(target=print_all)
	printer.daemon = True
	printer.start()
	# start the channel changer
	channel_changer = Thread(target=change_channel)
	channel_changer.daemon = True
	channel_changer.start()
	# start sniffing
	sniff(prn=callback, iface=interface)