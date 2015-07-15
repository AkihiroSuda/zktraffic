# # ==================================================================================================
# # Copyright 2015 Twitter, Inc.
# # --------------------------------------------------------------------------------------------------
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this work except in compliance with the License.
# # You may obtain a copy of the License in the LICENSE file, or at:
# #
# #  http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.
# # ==================================================================================================
#
# import unittest
# from zktraffic.base.util import QuorumConfig
# from zktraffic.cli.printer import Printer as Printer, DefaultPrinter as ZKDefaultPrinter
# from zktraffic.network.sniffer import Sniffer
# import zktraffic.fle.message as FLE
# import zktraffic.zab.quorum_packet as ZAB
# from zktraffic.base.sniffer import Sniffer as ZKSniffer, SnifferConfig as ZKSnifferConfig
# from zktraffic import __version__
# from zktraffic.omni.omni_sniffer import OmniSniffer
# from .common import get_full_path
# from somewhere import scapy
#
# class OmniTestCase(unittest.TestCase):
#   def get_sniffer(self):
#     def fle_sniffer_factory(port):
#      return Sniffer('dummy', port, FLE.Message, None, dump_bad_packet=False, start=False)
#
#     def zab_sniffer_factory(port):
#      return Sniffer('dummy', port, ZAB.QuorumPacket, None, dump_bad_packet=False, start=False)
#
#     def zk_sniffer_factory(port):
#       config = ZKSnifferConfig('dummy')
#       config.track_replies = True
#       config.zookeeper_port = port
#       config.client_port = 0
#       return ZKSniffer(config, None, None, None, error_to_stderr=True)
#
#     sniffer = OmniSniffer(
#       fle_sniffer_factory,
#       zab_sniffer_factory,
#       zk_sniffer_factory,
#       dump_bad_packet=False,
#       start=False)
#
#     return sniffer
#
#
#
#   def test_omni(self):
#     sniffer = self.get_sniffer()
#     packets = rdpcap(get_full_path('omni'))
#     for packet in packets:
#       print 'TEST OMNI PACKET: %s' % packet.summary()
#       message = sniffer.message_from_packet(packet)
#       print 'TEST OMNI MESSAGE: %s' % message
#
#
