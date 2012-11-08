import sys
import time
import os
import optparse
# update the system path to look for Tool80211 one directory up
sys.path.append('../')
import Tool80211


if __name__ == "__main__":
    print "Py80211 Sample Application"
    parser = optparse.OptionParser("%prog options [-i]")
    parser.add_option("-i", "--interface", dest="card", nargs=1,
        help="Interface to sniff and inject from")
    
    #check for correct number of arguments provided
    if len(sys.argv) < 2:
        parser.print_help()
        print "Calling Example"
        print "python pyview.py -i wlan0"
        sys.exit(0)
    else:
        (options, args) = parser.parse_args()
    try:
        """
        create an instance and create vap and monitor
        mode interface
        """
        x = Tool80211.Toolkit80211(options.card)
        """
        create an instance of Airview
        will only work with one interface for the time being
        """
        y = x.Airview(x.moniface)
        # start airview parsing and channel hopping
        y.start()
        ppmac = x.RandomBits.pformatMac
        while True:
            """
            run loop every 2 seconds to give us a chance to get new data
            this is a long time but not terrible
            """
            time.sleep(2)
            # clear the screen on every loop
            os.system("clear")
            """
            grab a local copy from airview thread
            This allows us to work with snapshots and not
            have to deal with thread lock issues
            """
            lbss = y.bss
            # print the current sniffing channel to the screen
            print "Channel %i" %(y.channel)
            # print out the access points and their essids
            print "Access point"
            for bssid in lbss.keys():
                apbssid = ppmac(bssid)
                print "%s %s" %(apbssid, lbss[bssid])
            """
            Print out the clients and anything they are assoicated to
            as well as probes to the screen
            """
            print "\nClients"
            # get local copies from airview thread
            # local clients
            lclient = y.clients
            # local clientsExtra
            eclient = y.clientsExtra
            # for each client show its data
            for client in lclient.keys():
                pclient = ppmac(client)
                # remove any wired devices we say via wired broadcasts
                if client in eclient.keys():
                    if eclient[client]['wired'] == True:
                        continue
                plclient = lclient[client]
                if plclient != "Not Associated":
                    plclient = ppmac(plclient)
                probes = y.getProbes(client)
                # print out a probe list, otherwise just print the client and its assoication
                if probes != None:
                    pass
                    print pclient, plclient, ','.join(probes)
                else:
                    pass
                    print pclient, plclient
    except KeyboardInterrupt:
        print "\nbye"
        x.exit()
        sys.exit(0)


