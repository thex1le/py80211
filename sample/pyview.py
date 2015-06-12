#!/usr/bin/python
import sys
import time
import re
import optparse
import curses
import locale
# update the system path to look for Tool80211 one directory up
try:
    import Tool80211
except ImportError:
    # Tool80211 not installed
    # assuming were running out of source directory
    sys.path.append('../')
    try:
        import Tool80211
    except ImportError, e:
        print e
        sys.exit(-1)


class FilterEngine:
    """
    Filter ESSID's
    """
    def __init__(self, **kwargs):
        """
        Show Networks based on essid's found in filter
        fiename: Str of file to open
        exact: bool if should be exact match vs case insensative greedy match
        """
        self.filename = kwargs.get("filter")
        self.exact = kwargs.get("exact")
        self.essids = list()
        self.load_essids()

    def load_essids(self):
        """
        Load the essid's from user file
        """
        with open(self.filename, 'r') as f:
            self.essids.extend(f.readlines())

    def filter_parse(self, check_essid):
        """
        Show Networks based on essid's found in filter
        :return bool if match
        """
        if check_essid is None:
            return False
        for ssid in self.essids:
            check = re.compile("{}".format(ssid.strip()), re.IGNORECASE)
            if check.match(check_essid) is not None:
                return True
        return False


if __name__ == "__main__":
    print "Pyview Wifi View"
    parser = optparse.OptionParser("%prog options [-i]")
    parser.add_option("-i", "--interface", dest="card", nargs=1,
        help="Interface to sniff and inject from")
    parser.add_option("-c", "--channel", dest="channel", nargs=1, default=False,
        help="Interface to sniff and inject from")
    parser.add_option("-f", "--filter", dest="filter", nargs=1, default=None,
        help="File of SSID's to filter on, one per line")
    parser.add_option("-e", "--exact", dest="exact", action="store_true", default=False,
        help="Trigger Exact matching on the essid filter")
    #check for correct number of arguments provided
    if len(sys.argv) < 3:
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
        if options.filter is not None:
            fe = FilterEngine(**{"filter": options.filter, "exact": options.exact})
        airmonitor = Tool80211.Airview(options.card)
        airmonitor.start()
        ppmac = airmonitor.pformatMac
        locale.setlocale(locale.LC_ALL, "")
        curses_screen = curses.initscr()
        curses_screen.border(0)
        while True:
            """
            run loop every 2 seconds to give us a chance to get new data
            this is a long time but not terrible
            """
            time.sleep(.5)
            """
            grab a local copy from airview thread
            This allows us to work with snapshots and not
            have to deal with thread lock issues
            """
            bss = airmonitor.apObjects 
            # print the current sniffing channel to the screen
            if options.channel is not False:
                airmonitor.hopper.pause()
                airmonitor.hopper.setchannel(int(options.channel))
            curses_screen.move(0,0)
            curses_screen.erase()
            #curses_screen.refresh()
            curses_screen.addstr(1, 1, "Channel %i" %(airmonitor.channel))
            # print out the access points and their essids
            curses_screen.addstr(2, 1, "Access Points")
            curses_screen.addstr(3, 1, "BSSID")
            curses_screen.addstr(3, 20, "RSSI")
            curses_screen.addstr(3, 26, "CH")
            curses_screen.addstr(3, 31, "ESSID")
            curses_screen.addstr(3, 58, "ENC")
            curses_screen.addstr(3, 66, "CIPHER")
            curses_screen.addstr(3, 79, "AUTH")
            curses_screen.addstr(3, 86, "BAND")
            curses_screen.addstr(3, 95, "OUI")
            curses_screen.addstr(3, 130, "HOSTNAME")
            curses_screen.addstr(3, 151, "REPORTED")
            curses_screen.addstr(3, 162, "SNIFFED")
            counter_bssid = 5
            bss_static = bss.copy()
            for bssid in bss_static.keys():
                ap = bss_static[bssid]
                # filter out SSID's not in list
                if options.filter is not None:
                    exists = fe.filter_parse(ap.essid)
                    if exists is False:
                        continue
                curses_screen.addstr(counter_bssid, 1, "{}".format(ppmac(bssid)))
                curses_screen.addstr(counter_bssid, 20, "{}".format(ap.rssi))
                curses_screen.addstr(counter_bssid, 26, "{}".format(ap.channel))
                curses_screen.addstr(counter_bssid, 31, "{}".format(ap.essid))
                curses_screen.addstr(counter_bssid, 58, "{}".format(ap.encryption))
                curses_screen.addstr(counter_bssid, 66, "{}".format(ap.cipher))
                curses_screen.addstr(counter_bssid, 79, "{}".format(ap.auth))
                curses_screen.addstr(counter_bssid, 86, "{}".format(ap.getband()))
                curses_screen.addstr(counter_bssid, 95, "{}".format(ap.oui))
                curses_screen.addstr(counter_bssid, 130, "{}".format(ap.hostname))
                curses_screen.addstr(counter_bssid, 154, "{}".format(ap.numClients()[1]))
                curses_screen.addstr(counter_bssid, 166, "{}".format(ap.numClients()[0]))
                counter_bssid += 1
            ###
            """
            Print out the clients and anything they are assoicated to+
            as well as probes to the screen
            """
            ###
            curses_screen.addstr(counter_bssid + 2, 1, "Clients")
            curses_screen.addstr(counter_bssid + 3, 1, "Client Mac")
            curses_screen.addstr(counter_bssid + 3, 20, "Assoicated AP")
            curses_screen.addstr(counter_bssid + 3, 40, "ESSID")
            curses_screen.addstr(counter_bssid + 3, 65, "OUI")
            curses_screen.addstr(counter_bssid + 3, 110, "RSSI")
            curses_screen.addstr(counter_bssid + 3, 116, "PROBES")
            # get local copies from airview thread
            # local clients
            clients = airmonitor.clientObjects
            # for each client show its data
            counter_client = counter_bssid + 5
            for mac in clients.keys():
                # remove any wired devices we see via wired broadcasts
                if clients[mac].wired is True:
                    continue
                curses_screen.addstr(counter_client, 1, "{}".format(ppmac(mac)))
                if clients[mac].assoicated is True:
                    curses_screen.addstr(counter_client, 20, "{}".format(ppmac(clients[mac].bssid)))
                else:
                    curses_screen.addstr(counter_client, 20, "{}".format(clients[mac].bssid))
                curses_screen.addstr(counter_client, 40, "{}".format(clients[mac].getEssid()))
                curses_screen.addstr(counter_client, 65, "{}".format(clients[mac].oui))
                curses_screen.addstr(counter_client, 110, "{}".format(clients[mac].rssi))
                probes = clients[mac].probes
                if probes is not []:
                    curses_screen.addstr(counter_client, 116, "{}".format(','.join(probes)))
                counter_client += 1
            # write out to screen
            curses_screen.refresh()

    except KeyboardInterrupt:
        curses_screen.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.endwin()
        print "\nbye\n"
        airmonitor.kill()
        sys.exit(0)


