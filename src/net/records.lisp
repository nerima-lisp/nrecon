(in-package #:nrecon.net)

(defstruct (network-host
            (:constructor %make-network-host
                (&key ip-addresses mac-addresses names protocols)))
  ip-addresses
  mac-addresses
  names
  protocols)
