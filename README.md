Splunk for Sourcefire App (v2.0)                               #
                                                                 #
  Description:                                                   #
     Connect to an eStreamer server (e.g. Defense Center) and    #
     pull intrusion event records and packet records (pcap data) #
     into Splunk. A user can search through eStreamer records    #
     based on IP addresses, ports, event ID, and etc.            #
                                                                 #
  Splunk Version: 4.1 and Higher                                 #
  Supported Platform: Linux                                      #
  Last Modified: Mar-2012                                        #
  For support: This is an usupported app                         #
  Please post to answers.splunk.com                              #
                                                                 #



Disclaimer

You need to set up your eStreamer client before Splunk for Sourcefire App can
function correctly.

Please refer to docs/How_to_add_an_eStreamer_client.pdf for more information.


Welcome to the Splunk for Sourcefire 

The Splunk for Sourcefire App includes an eStreamer client that will connect to
your eStreamer server (e.g. Defense Center) and pull intrusion event records and
packet records (pcap data) into Splunk. Then you can search through eStreamer
records based on source or destination IP addresses, ports, event ID, and etc.

By default, the app will not try to pull the packet records (pcap data) from the
eStreamer server. You can enable the pcap input by editing inputs.conf:
    $ vi $SPLUNK_HOME/etc/apps/Sourcefire/default/inputs.conf

Change the line that says "disabled = true" to "disabled = false" like the following:

    [script://$SPLUNK_HOME/etc/apps/Sourcefire/bin/estreamer_pcap.py]
    disabled = false
    interval = 60
    source = estreamer_pcap.py
    sourcetype = estreamer_pcap

Then restart the Splunk server.


NOTE: It may take up to 5 minutes for new data to show up. The app relies on "sourcetype = estreamer" and "sourcetype = estreamer_pcap" data, please do not change the sourcetype in inputs.conf.
