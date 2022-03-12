# no_partscan

Kernel module to allow (temporarily) blocking the partition scan when a new disk is added.
It can block once|always and can be set on a per device-path basis.

# biosnoop

Kernel module to track any block io submitted to the block susbsystem.
It reports which end_io function is used, and reports any IO errors.
A flag is available to report *all* IO completions.
