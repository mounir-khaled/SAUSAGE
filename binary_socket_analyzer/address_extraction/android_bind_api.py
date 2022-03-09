
import logging
from collections import deque
from itertools import product
from typing import Tuple, Set

import networkx as nx
from angr.analyses import ReachingDefinitionsAnalysis
from angr.knowledge_plugins import Function
from angr.knowledge_plugins.key_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.undefined import Undefined

import utils
from address_extraction import SocketAddressExtractor, NAMESPACE_ID_MAP, StringConstructionHandler
from generic_function_handler import GenericFunctionHandler

log = logging.getLogger(__name__)

ANDROID_ENV_SOCKET_PREFIX = "ANDROID_SOCKET_"

ANDROID_BIND_FUNCTIONS = {  "FrameworkListener::{base ctor}(char const*": {
                                "namespace": "RESERVED",
                                "addr_param_ix": 1,
                                "exact_name": False
                            },
                            "SocketListener::{base ctor}(char const*": {
                                "namespace": "RESERVED",
                                "addr_param_ix": 1,
                                "exact_name": False
                            },
                            "android_get_control_socket": {
                                "namespace": "RESERVED",
                                "addr_param_ix": 0,
                                "exact_name": True
                            },
                            "socket_local_server": {
                                "namespace_param_ix": 1,
                                "addr_param_ix": 0,
                                "exact_name": True
                            },
                            "socket_local_server_bind": {
                                "namespace_param_ix": 2,
                                "addr_param_ix": 1,
                                "exact_name": True
                            },
                            "getenv": {
                                "addr_param_ix": 0,
                                "namespace": "RESERVED",
                                "exact_name": True
                            }
                        }

class AndroidSocketAddressExtractor(SocketAddressExtractor):

    def get_bind_functions(self):
        self._bind_fns_params = {}
        for fn_name, fn_params in ANDROID_BIND_FUNCTIONS.items():
            matches = utils.search_functions(self.functions, fn_name, exact_match=fn_params["exact_name"])
            if not matches:
                log.info("%s not found in binary", fn_name)

            for fn in matches:
                self._bind_fns_params[fn] = fn_params

        return list(self._bind_fns_params.keys())

    def find_addresses_from_livedefs_at_callsite(self,
                                                 bind_fn: Function,
                                                 rda: ReachingDefinitionsAnalysis,
                                                 livedefs: LiveDefinitions) -> Tuple[bool, Set[Tuple[str, str]]]:

        fn_params = self._bind_fns_params[bind_fn]

        namespaces = set()
        if "namespace" in fn_params:
            namespaces.add(fn_params["namespace"])
        else:
            namespace_param_ix = fn_params["namespace_param_ix"]
            namespace_defs = utils.get_arg_defs(self.p.arch, livedefs, namespace_param_ix)
            for namespace_def in namespace_defs:
                for ns_id in namespace_def.data:
                    if isinstance(ns_id, int):
                        namespace = NAMESPACE_ID_MAP[ns_id]
                    else:
                        log.warning("Non-constant namespace")
                        namespace = "UNKNOWN"

                    namespaces.add(namespace)

        addr_param_ix = fn_params["addr_param_ix"]
        addresses = set()
        addr_defs = utils.get_arg_defs(self.p.arch, livedefs, addr_param_ix)
        for addr_def in addr_defs:
            if isinstance(rda._function_handler, GenericFunctionHandler):
                addresses.update(rda._function_handler.load_string(livedefs, addr_def.data, {108}))
            else:
                for memory_addr in addr_def.data:
                    if isinstance(memory_addr, int):
                        addresses.add(utils.load_string_from_memory(self.p, memory_addr, 108))
                    elif isinstance(memory_addr, Undefined):
                        log.warning("Undefined memory address")
                    else:
                        log.warning("Unhandled memory address type %s", type(memory_addr))

        if not namespaces:
            namespaces.add("UNKNOWN")

        analyze_caller = len(addresses) == 0

        if bind_fn.name == "getenv":
            addresses = set(addr[len(ANDROID_ENV_SOCKET_PREFIX):] for addr in addresses
                            if addr and addr.startswith(ANDROID_ENV_SOCKET_PREFIX))

            # getenv is called a lot, but usually with a fixed string so lets just skip going too deep into it
            analyze_caller = False

        return analyze_caller, set(product(namespaces, addresses))


