.. _nsca_daemon_module:

============
NSCA module
============


The NSCA daemon module is used to receive NSCA packets and submit them to the Shinken command pipe. The NSCA module can be loaded by the Receiver (best solution) or Arbiter process. It will listen on port TCP/5667 for NSCA packets.

.. tip::  Passive checks can be submitted :ref:`natively to the Shinken command pipe <thebasics/passivechecks>` or from remote hosts to modules, such as NSCA, AMQP or collectd, loaded in the Shinken Arbiter or Receiver process. AMQP is implemented for integration with the Canopsis Hypervisor, but could be re-used for generic messaging.

.. note::  The Shinken NSCA module implementation is currently limited to the "xor" obfuscation/encryption.


To append the NSCA module to the Shinken receiver daemon, simply add (or uncomment) in the receiver configuration:


::

  define receiver {
      receiver_name   receiver-master
      address         localhost
      port            7773
      spare           0

      ## Optional parameters
      timeout             3   ; Ping timeout
      data_timeout        120 ; Data send timeout
      max_check_attempts  3   ; If ping fails N or more, then the node is dead
      check_interval      60  ; Ping node every N seconds

      ## Modules for Receiver
      # - named-pipe             = Open the named pipe nagios.cmd
      # - nsca                    = NSCA server
      # - TSCA                    = TSCA server
      # - ws-arbiter              = WebService for pushing results to the arbiter
      # - Collectd                = Receive collectd perfdata
      modules	nsca

      # Enable https or not
      use_ssl	          0
      # enable certificate/hostname check, will avoid man in the middle attacks
      hard_ssl_name_check  0
      
      ## Advanced Feature
      direct_routing      0   ; If enabled, it will directly send commands to the
                              ; schedulers if it know about the hostname in the
                              ; command.
      realm   All
  }
  
This daemon is totally optional. Its main goal is to get all passive "things" (checks but why not other commands) in distant realms. 
It will act as a "passive receive buffer" and will then dispatch the data or commands directly to the appropriate Scheduler or Arbiter process.

Data can be received from any Realm, thus the Realm option is nonsensical.

It is launched like all other daemons:
  
::

  /etc/init.d/shinken-receiver start
  
  
.. tip::  Alternatively, for small installations you can configure an NSCA module inside your Arbiter instead of the Receiver. It will listen the TCP/5667 port for NSCA packets. 


To configure the NSCA module in your Arbiter instead of Receiver, add the NSCA module to the arbiter configuration.

::

  define arbiter {
      ... 

      modules    	 ..., nsca

  }

  


The NSCA module configuration is defined in the module configuration file: nsca.cfg.

Default configuration is convenient for 'recent' NSCA client implementing NSCA version 3. This configuration 
has been tested with Linux send_nsca 2.9.1 and with Windows NSClient versions 0.4.1 and 0.4.2.

.. note::  Received NSCA packets which are not containing version 3 information are dropped by the module!


::

  ## Module:      nsca
  ## Loaded by:   Arbiter, Receiver
  # Receive check results sent with NSCA protocol.
  define module {
    module_name			nsca
    module_type			nsca_server
    
    # Default is listening on all address, TCP port 5667
    host				      *
    port				      5667
    
    # Encryption method:
    # 0 for no encryption (default)
    # 1 for simple Xor
    # No other encryption method available!
    encryption_method   0
    password			      helloworld
    
    # Maximum packet age defines the maximum delay
    # (in seconds) for a packet to be considered as staled
    max_packet_age		  60
    
    # If check_future_packet attribute is defined, packets
    # more recent than current timestamp are dropped
    check_future_packet 
    
    # Payload length is length of effective data sent :
    # . -1 to accept any payload length
    # . 512 or 4096 depending upon NSCA client configuration
    # If packet payload is not the right size, packet is dropped
    payload_length		-1
    
    # Buffer length is maximum length of received data :
    # should be greater than payload length
    # Default is 8192
    buffer_length		  8192
  }
