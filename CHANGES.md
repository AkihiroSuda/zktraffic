ChangeLog
=========

0.1.5 (2015-06-22)
--------------------

Bug Handling
************
- per-path aggregation for watches wasn't working
- silence scapy logging
- add missing help strings and their defaults

Features
********
- zk-dump: add support for profiling latencies by path/type

Breaking changes
****************
- zk-dump: rename --sort-by to --group-by

0.1.4 (2015-06-17)
--------------------

Bug Handling
************
- handle IOError for fix zk-dump, fle-dump, zab-dump

Features
********
-  add --count-requests and --sort-by