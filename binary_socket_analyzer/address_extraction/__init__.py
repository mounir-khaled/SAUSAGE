
import logging
from abc import ABC, abstractmethod
from collections import deque
from itertools import product
from typing import List, Set, Tuple

import angr
import networkx as nx
from angr.analyses import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import Subject
from angr.calling_conventions import SimRegArg, SimStackArg
from angr.knowledge_plugins import Function
from angr.knowledge_plugins.key_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.dataset import DataSet

import utils

from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER

from address_extraction.string_construction_handler import StringConstructionHandler


log = logging.getLogger("address_extraction")
log.setLevel(logging.DEBUG)

NAMESPACE_ID_MAP = {0: "ABSTRACT", 1: "RESERVED", 2: "FILESYSTEM"}


class SocketAddressExtractor(ABC):
    def __init__(self, p: angr.Project, max_callstack_depth=4):
        self.p = p
        self.cfg = p.kb.cfgs["CFGFast"]
        self.functions = p.kb.functions
        self.default_cc_cls = angr.DEFAULT_CC[p.arch.name]
        self.max_call_stack_depth = max_callstack_depth
        self.entry_node = self.cfg.get_node(self.p.entry)

        self.socket_addresses = {}
        self._analyze()

    def _get_function_entry_node(self, function):
        if function.is_plt:
            fn_node = self.cfg.get_node(function.addr)
        else:
            fn_node = next(iter(self.cfg.get_node(function.addr).predecessors))

        return fn_node

    def _analyze(self):
        bind_functions = self.get_bind_functions()
        for bind_fn in bind_functions:
            fn_node = self._get_function_entry_node(bind_fn)
            calling_nodes = [cn for cn, jk in fn_node.predecessors_and_jumpkinds() if jk == "Ijk_Call" and cn.block]
            obs_points = [("insn", max(cn.block.instruction_addrs), OP_BEFORE) for cn in calling_nodes]
            to_analyze = deque(calling_nodes)
            n_initial_nodes = len(calling_nodes)
            i = 0
            while to_analyze:
                i += 1

                calling_node = to_analyze.pop()
                is_reachable = nx.has_path(self.cfg.graph, self.entry_node, calling_node)
                calling_fn = self.functions.get_by_addr(calling_node.function_address)
                if not calling_node.block:
                    log.error("No block at %#x", calling_node.addr)
                    continue

                if i <= n_initial_nodes:
                    analyze_fn_caller, addrs = self._analyze_shallow(bind_fn, calling_fn, obs_points)
                    if analyze_fn_caller:
                        analyze_fn_caller, addrs = self._analyze_deep(bind_fn, calling_fn, obs_points)

                else:
                    analyze_fn_caller, addrs = self._analyze_deep(bind_fn, calling_fn, obs_points)

                if addrs:
                    callsite_details = {"bind_api": bind_fn.demangled_name,
                                        "reachable": str(is_reachable),
                                        "addresses": []}

                    self.socket_addresses[calling_node.addr] = self.socket_addresses.get(calling_node.addr, callsite_details)
                    addresses = [{"namespace": addr[0], "address": addr[1]} for addr in addrs]

                    self.socket_addresses[calling_node.addr]["addresses"].extend(addresses)

                if analyze_fn_caller:
                    fn_node = self.cfg.get_node(calling_fn.addr)
                    to_analyze.extendleft(fn_node.predecessors)

    def _analyze_shallow(self, bind_fn, calling_fn, obs_points):
        rda = self.p.analyses.ReachingDefinitions(calling_fn, observation_points=obs_points)

        addrs = set()
        analyze_fn_caller = False
        for obs_point, livedefs in rda.observed_results.items():
            analyze_caller, current_addrs = self.find_addresses_from_livedefs_at_callsite(bind_fn, rda, livedefs)
            addrs.update(current_addrs)
            analyze_fn_caller |= analyze_caller

        return analyze_fn_caller, addrs

    def _analyze_deep(self, bind_fn, calling_fn, obs_points):
        string_construction_handler = StringConstructionHandler()
        rda = self.p.analyses.ReachingDefinitions(calling_fn, observation_points=obs_points,
                                                  call_stack=[],
                                                  maximum_local_call_depth=self.max_call_stack_depth,
                                                  function_handler=string_construction_handler)

        addrs = set()
        analyze_fn_caller = False
        for obs_point, livedefs in rda.observed_results.items():
            analyze_caller, current_addrs = self.find_addresses_from_livedefs_at_callsite(bind_fn, rda, livedefs)
            addrs.update(current_addrs)
            analyze_fn_caller |= analyze_caller

        return analyze_fn_caller, addrs

    @abstractmethod
    def get_bind_functions(self) -> List[Function]:
        pass

    @abstractmethod
    def find_addresses_from_livedefs_at_callsite(self,
                                                 bind_fn: Function,
                                                 rda: ReachingDefinitionsAnalysis,
                                                 livedefs: LiveDefinitions) -> Tuple[bool, Set[Tuple[str, str]]]:
        pass





