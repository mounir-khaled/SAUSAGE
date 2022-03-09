import logging
from functools import reduce
from typing import Optional, Set, List

from angr.analyses import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.calling_conventions import SimRegArg, SimStackArg
from angr.code_location import CodeLocation
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.knowledge_plugins.key_definitions.dataset import DataSet
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from networkx import NetworkXError

import utils

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class TaintedVariableTag(LocalVariableTag):
    pass


class TaintedData(Undefined):
    def __init__(self, taint_name, offset):
        self.taint_name = taint_name
        self.offset = offset
        self.name = "<%s+%x>" % (taint_name, offset)

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, TaintedData):
            return self.taint_name == other.taint_name and self.offset == other.offset
        else:
            return False

    def __ne__(self, other):
        return not (self == other)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class TaintingFunctionHandler(FunctionHandler):

    def __init__(self, f_addr, taint_arg_ix=None, taint_arg_size=None, taint_return=False, taint_name="tainted_var",
                 follow_untainted_parameters=True):

        self.f_addr = f_addr
        self.taint_arg_ix = taint_arg_ix
        self.taint_return = taint_return
        self.taint_arg_size = taint_arg_size
        self.taint_name = taint_name
        self.follow_untainted_parameters = follow_untainted_parameters

        self.rda: ReachingDefinitionsAnalysis = None
        self.project = None
        self.reverse_plt = None

    def hook(self, analysis: ReachingDefinitionsAnalysis):
        self.rda = analysis
        self.project = analysis.project
        self.reverse_plt = self.project.loader.main_object.reverse_plt

        if not self.taint_arg_size:
            self.taint_arg_size = self.project.arch.bytes

        return self

    def handle_local_function(self, state: 'ReachingDefinitionsState', function_address: int, call_stack: List,
                              maximum_local_call_depth: int, visited_blocks: Set[int], dep_graph: 'DepGraph',
                              src_ins_addr: Optional[int] = None,
                              codeloc: Optional['CodeLocation'] = None):

        visited_blocks.add(function_address)
        if function_address == self.f_addr:
            return self._handle_source(state, function_address, codeloc, visited_blocks, call_stack, dep_graph)
        elif function_address in self.reverse_plt:
            # Taint propagation through cpy functions
            return self._handle_external_function(state, function_address, codeloc, visited_blocks, call_stack,
                                                  dep_graph)
        else:
            f = self.project.kb.functions.get_by_addr(function_address)
            if self._is_args_tainted(function_address, state) \
                    or utils.find_call_in_callgraph(self.project, f, addr=self.f_addr):

                return self._handle_internal_function(state, function_address, codeloc, visited_blocks, call_stack,
                                                      dep_graph)
            else:
                return False, None, None, None

    def _is_args_tainted(self, function_address, state):
        functions = self.project.kb.functions
        cfg = self.project.kb.cfgs["CFGFast"]

        f = functions.get_by_addr(function_address)
        livedefs = state.live_definitions

        cc = f.calling_convention
        if not cc:
            cc_result = self.project.analyses.CallingConvention(f, cfg, analyze_callsites=True)
            cc = cc_result.cc

        if not cc:
            return True

        for arg in cc.args:
            if isinstance(arg, SimRegArg):
                reg_offset, reg_size = self.project.arch.registers[arg.reg_name]
                arg_defs = livedefs.register_definitions.get_objects_by_offset(reg_offset)

            elif isinstance(arg, SimStackArg):
                arg_defs = livedefs.stack_definitions.get_objects_by_offset(arg.stack_offset)

            else:
                continue

            is_arg_tainted = any(self.is_tainted(self.rda.dep_graph, arg_def) for arg_def in arg_defs)
            if is_arg_tainted:
                return True

        return False

    @staticmethod
    def is_tainted(dep_graph, def_):
        arg_data = def_.data
        is_tainted = False
        if any(isinstance(d, TaintedData) for d in def_.data):
            is_tainted = True

        elif any(not isinstance(d, int) for d in def_.data):
            try:
                deps = dep_graph.transitive_closure(def_)
            except NetworkXError:
                log.error("%s is not in dep_graph" % def_)
                is_tainted = False
                deps = []

            for dep in deps:
                dep: Definition
                if any(isinstance(t, TaintedVariableTag) for t in dep.tags):
                    is_tainted = True

        return is_tainted

    def _get_argument_definition(self, state: 'ReachingDefinitionsState', codeloc, arg_ix):
        # implemented just argument registers for now
        # we're mostly dealing with ARM anyways
        reg_offset = utils.get_arg_reg_offset(self.project, arg_ix)
        reg_defs = state.register_definitions.get_variables_by_offset(reg_offset)
        if len(reg_defs) > 1:
            log.warning("Found more than one definition for argument index %d at block %#x",
                        arg_ix, codeloc.block_addr)

        return next(iter(reg_defs))

    def _handle_source(self, state, function_address, codeloc, visited_blocks, call_stack, dep_graph):
        tainted_arg_def = self._get_argument_definition(state, codeloc, self.taint_arg_ix)
        if not tainted_arg_def:
            log.error("Could not find argument definition")
            return False, state, visited_blocks, dep_graph

        tainted_mem_addr = tainted_arg_def.data.get_first_element()
        if not (isinstance(tainted_mem_addr, SpOffset) or isinstance(tainted_mem_addr, int)):
            log.error("Could not taint data at address defined by %s" % tainted_mem_addr)
            return False, state, visited_blocks, dep_graph

        # FIXME: I'll just hardcode this for now...
        optname_def = self._get_argument_definition(state, codeloc, 2)
        # 0x11 is SO_PEERCRED, 0X12 is SO_PEERSEC
        optname_val = optname_def.data.get_first_element()
        if optname_val == 0x11:
            pass
        elif optname_val == 0x12:
            pass
        else:
            return False, state, visited_blocks, dep_graph

        # each variable should have a size of p.arch.bytes
        n = 0
        for offset in range(0, self.taint_arg_size, self.project.arch.bytes):
            tainted_mem_loc = MemoryLocation(tainted_mem_addr + offset, self.project.arch.bytes)
            data = DataSet({TaintedData(self.taint_name, offset)}, self.project.arch.bits)
            state.kill_and_add_definition(tainted_mem_loc, codeloc, data,
                                          tags={TaintedVariableTag(self.f_addr, "%s_%d" % (self.taint_name, n))})
            n += 1

        return False, state, visited_blocks, dep_graph

    def _handle_internal_function(self, state, function_address, codeloc, visited_blocks, call_stack, dep_graph):
        # init_state is copied inside rda

        func = self.project.kb.functions.get_by_addr(function_address)

        ret_points = [("node", rs.addr, OP_AFTER) for rs in func.ret_sites]
        child_rda = self.project.analyses.ReachingDefinitions(func, observation_points=self.rda._observation_points + ret_points, dep_graph=dep_graph,
                                                              init_state=state, function_handler=self,
                                                              visited_blocks=visited_blocks,
                                                              call_stack=call_stack)

        livedefs_at_rets = []
        for op in ret_points:
            if op in child_rda.observed_results:
                livedefs_at_ret = child_rda.observed_results[op]
                livedefs_at_rets.append(livedefs_at_ret)
            else:
                log.warning("Could not get livedef at return (addr=%#x)" % op[1])

        if livedefs_at_rets:
            state.live_definitions = reduce(LiveDefinitions.merge, livedefs_at_rets)
            
        self.rda.observed_results.update(child_rda.observed_results)
        return True, state, visited_blocks, dep_graph

    def _handle_external_function(self, state, function_address, codeloc, visited_blocks, call_stack, dep_graph):
        return False, state, visited_blocks, dep_graph
