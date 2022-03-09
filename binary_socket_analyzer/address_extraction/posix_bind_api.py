import logging
from typing import List

import networkx as nx
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import Subject
from angr.engines.light import SpOffset
from angr.knowledge_plugins import Function
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.undefined import Undefined

import utils
from address_extraction import SocketAddressExtractor, StringConstructionHandler
from generic_function_handler import GenericFunctionHandler

log = logging.getLogger(__name__)

class PosixSocketAddressExtractor(SocketAddressExtractor):

    def _is_unix_family(self, livedefs, sockaddr_sp_offset):
        sock_family_defs = livedefs.stack_definitions.get_objects_by_offset(sockaddr_sp_offset.offset)
        for sock_family_def in sock_family_defs:
            for d in sock_family_def.data:
                if (isinstance(d, int) and d == 1) or isinstance(d, Undefined):
                    return True

        # they are all defined values that are not 1
        return False

    def get_bind_functions(self):
        return [fn for fn in self.functions.values() if fn.name == "bind"]

    def find_addresses_from_livedefs_at_callsite(self, bind_fn, rda, livedefs):
        any_unix_binds_exist = False
        addresses = set()

        sockaddr_defs = utils.get_arg_defs(self.p.arch, livedefs, 1)
        for sockaddr_def in sockaddr_defs:
            for sp_offset in sockaddr_def.data:
                addrs = set()
                if not isinstance(sp_offset, SpOffset):
                    log.error("sockaddr_def.data is not SpOffset: %s" % sockaddr_def)
                    continue

                if not self._is_unix_family(livedefs, sp_offset):
                    log.info("Call is not a unix domain socket bind")
                    continue

                any_unix_binds_exist = True
                sunpath_sp_offset = sp_offset + 2
                if isinstance(rda._function_handler, GenericFunctionHandler):
                    addrs = rda._function_handler.load_data(livedefs, {sunpath_sp_offset}, {108})

                for addr in addrs:
                    namespace = "UNKOWN"
                    if addr.startswith(b'\0'):
                        namespace = "ABSTRACT"
                    elif b'/' in addr:
                        namespace = "FILESYSTEM"

                    addresses.add((namespace, addr))

        analyze_caller = any_unix_binds_exist and not addresses
        return analyze_caller, addresses
