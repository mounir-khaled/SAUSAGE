import logging
from abc import abstractmethod
from collections import deque
from functools import reduce
from itertools import product

import angr
from angr.analyses import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.engines.light import SpOffset, RegisterOffset
from angr.knowledge_plugins.key_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.knowledge_plugins.key_definitions.dataset import DataSet
from angr.knowledge_plugins.key_definitions.definition import Definition
from typing import Set, Optional

from angr.knowledge_plugins.key_definitions.tag import ParameterTag
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.procedures.stubs.format_parser import FormatParser

import utils
from simprocedure_call import FormatParserCall

log = logging.getLogger(__name__)


def _data_to_bytes(data, endness="Iend_LE"):
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    elif isinstance(data, bytes):
        data_bytes = data
    elif isinstance(data, int):
        # Sometimes they are saved as constant data
        if data == 0:
            data_bytes = b'\x00'
        else:
            endness = "little" if endness == 'Iend_LE' else 'big'
            data_bytes = data.to_bytes((data.bit_length() + 7) // 8, endness)
    else:
        raise TypeError("Unhandled data type %s" % type(data))

    return data_bytes

def _load_data_from_sp_offset(state, sp_offset, size, endness="Iend_LE"):
    loaded_size = -1
    loaded_data = set()

    defs_in_range = set()
    for i in range(size):
        defs_in_range.update(state.stack_definitions.get_variables_by_offset(sp_offset.offset + i))

    # https://www.geeksforgeeks.org/merging-intervals/

    def_data_intervals = []
    for _def in defs_in_range:
        data_intervals = set()
        assert isinstance(_def.atom, MemoryLocation)
        for data in _def.data:
            if isinstance(data, Undefined):
                continue

            try:
                data = _data_to_bytes(data)
            except TypeError as e:
                log.error(e)
                continue

            start = _def.atom.addr.offset - sp_offset.offset
            end = start + len(data)
            data_intervals.add((start, end, data))

        if data_intervals:
            def_data_intervals.append(data_intervals)

    for data_intervals in product(*def_data_intervals):
        # What if we have intervals with the same starts or ends or both
        data_intervals = sorted(data_intervals, key=lambda x: x[0])
        merge_stack = deque(data_intervals[:1])
        for di in data_intervals:
            top = merge_stack[-1]
            is_overlapping = top[0] <= di[0] <= top[1] or top[0] <= di[1] <= top[1]
            if not is_overlapping:
                merge_stack.append(di)
            elif di[1] > top[1]:
                top = merge_stack.pop()

                top_data = top[2]
                di_data = di[2]
                start = min(top[0], di[0])
                if top[0] < di[0]:
                    # t**********11111111111
                    # d*************22222222222
                    # m**********11111111111222
                    # m**********11122222222222
                    m1 = top_data + di_data[top[1]:]
                    m2 = top_data[:di[0]] + di_data
                else:
                    # t********11111111111
                    # d******22222222222222
                    m1 = di_data[:top[0]] + top_data + di_data[top[1]:]
                    m2 = di_data

                merge_stack.append((start, di[1], m1))
                merge_stack.append((start, di[1], m2))

        loaded_data.update(d for _, _, d in merge_stack)

    return loaded_data

class GenericFunctionHandler(FunctionHandler):
    def __init__(self, default_n_args=0, tag_parameters=False, stop_after_obs_points=False):
        self.default_n_args = default_n_args
        self.tag_parameters = tag_parameters
        self.stop_after_obs_points = stop_after_obs_points

        self.rda: Optional['ReachingDefinitionsAnalysis'] = None
        self.p = None
        self.cfg = None
        self.functions = None

    def hook(self, analysis: ReachingDefinitionsAnalysis):
        self.rda = analysis
        self.p = analysis.project
        self.functions = self.p.kb.functions
        self.cfg = self.p.kb.cfgs["CFGFast"]
        self._initialize_handlers()
        return self

    def handle_local_function(self, state, function_address, call_stack,
                              maximum_local_call_depth, visited_blocks, dep_graph,
                              src_ins_addr=None,
                              codeloc=None):

        reached_obs_points = all(op in self.rda.observed_results for op in self.rda._observation_points)
        if self.stop_after_obs_points and reached_obs_points:
            log.info("Reached all observation points, not analysing function call at %#x to %#x",
                     codeloc.block_addr,
                     function_address)
            return False, state, visited_blocks, dep_graph

        try:
            func = self.functions.get_by_addr(function_address)
        except KeyError:
            log.error("Function at %#x not found", function_address)
            return False, state, visited_blocks, dep_graph

        if not func.name.startswith("sub_") and not func.is_plt:
            if hasattr(self, "handle_%s" % func.name):
                return_value = getattr(self, "handle_%s" % func.name)(state, codeloc)
                return return_value[0], return_value[1], visited_blocks, dep_graph

        # if func.is_plt:
        #     ret_points = [("node", function_address, OP_AFTER)]
        # else:
        ret_points = [("node", rs.addr, OP_AFTER) for rs in func.ret_sites]
        if not ret_points:
            ret_points = [("node", function_address, OP_AFTER)]

        if len(call_stack) >= self.rda._maximum_local_call_depth:
            for cs in func.get_call_sites():
                ct = func.get_call_target(cs)
                callee = self.functions.get_by_addr(ct)
                cca = self.p.analyses.CallingConvention(callee, self.cfg, analyze_callsites=True)
                if cca.cc and cca.cc.args:
                    callee.calling_convention = cca.cc
                else:
                    arch_cc_cls = angr.DEFAULT_CC[self.p.arch.name]
                    callee.calling_convention = arch_cc_cls.from_arg_kinds(self.p.arch, [False] * self.default_n_args)

        child_rda: ReachingDefinitionsAnalysis = self.p.analyses.ReachingDefinitions(func,
                                                        observation_points=self.rda._observation_points + ret_points,
                                                        dep_graph=dep_graph,
                                                        init_state=state, function_handler=self,
                                                        visited_blocks=visited_blocks,
                                                        call_stack=call_stack,
                                                        maximum_local_call_depth=self.rda._maximum_local_call_depth)


        livedefs_at_rets = []
        for op in ret_points:
            if op in child_rda.observed_results:
                livedefs_at_ret = child_rda.observed_results[op]
                livedefs_at_rets.append(livedefs_at_ret)
            else:
                log.warning("Could not get livedef at return (addr=%#x)", op[1])

        merged_livedefs = reduce(LiveDefinitions.merge, livedefs_at_rets)

        is_parameter = True
        arg_ix = 0
        while self.tag_parameters and is_parameter:
            is_parameter = False
            arg_defs = utils.get_arg_defs(self.p.arch, state, arg_ix)
            for arg_def in arg_defs:
                is_parameter = any(True for d in child_rda.all_uses.get_uses(arg_def))
                if is_parameter:
                    for arg_def_after in utils.get_arg_defs(self.p.arch, merged_livedefs, arg_ix):
                        arg_def_after.tags.add(ParameterTag(
                            function=function_address,
                            metadata={'tagged_by': 'GenericFunctionHandler'}
                        ))


            arg_ix += 1

        state.live_definitions = merged_livedefs
        state.all_definitions |= child_rda.all_definitions

        for op, livedefs in child_rda.observed_results.items():
            if op in self.rda._observation_points:
                self.rda.observed_results[op] = livedefs

        return True, state, visited_blocks, dep_graph

    def handle_external_function_fallback(self, state, codeloc):

        calling_node = self.cfg.get_node(codeloc.block_addr)
        callee_node = calling_node.successors[0]
        simproc = self.p.hooked_by(callee_node.addr)
        if not simproc and callee_node.successors:
            next_node = callee_node.successors[0]
            executed_rda, new_state, *rest = self.handle_local_function(state,
                                                                        next_node.function_address,
                                                                        self.rda._call_stack,
                                                                        self.rda._maximum_local_call_depth,
                                                                        self.rda.visited_blocks,
                                                                        self.rda.dep_graph,
                                                                        codeloc.ins_addr,
                                                                        codeloc)
            state.live_definitions = state.live_definitions.merge(new_state.live_definitions)
            return executed_rda, state

        if isinstance(simproc, FormatParser):
            simproc_fn = self.functions.get_by_addr(callee_node.addr)

            simproc_call = FormatParserCall(self.p, state, simproc)
            arch_default_cc = angr.DEFAULT_CC[self.p.arch.name]
            simproc_fn.calling_convention = arch_default_cc.from_arg_kinds(self.p.arch, [False] * simproc_call.num_args)
            log.info("Replacing format parser calling convention")

        return False, state

    def handle_unknown_call(self, state, src_codeloc):
        # this is a calling node so we can get the next function address from the cfg
        no = self.cfg.get_node(src_codeloc.block_addr)
        if not no:
            log.error("Could not find node in CFG %#x" % src_codeloc.block_addr)
            return False, state

        if not no.successors:
            log.error("Could not find node successors in CFG %#x" % src_codeloc.block_addr)
            return False, state

        callee_node = no.successors[0]
        callee_addr = callee_node.addr
        if not callee_addr in self.functions:
            log.error("Callee address is not in kb.functions %#x")
            return False, state

        next_node = None
        if callee_node.successors:
            next_node = callee_node.successors[0]

        callee_fn = self.functions.get_by_addr(callee_addr)
        handler_name = "handle_%s" % callee_fn.name
        if hasattr(self, handler_name):
            return getattr(self, handler_name)(state, src_codeloc)
        elif next_node and not next_node.is_simprocedure:
            executed_rda, new_state, *rest = self.handle_local_function(state,
                                                                    next_node.function_address,
                                                                    self.rda._call_stack,
                                                                    self.rda._maximum_local_call_depth,
                                                                    self.rda.visited_blocks,
                                                                    self.rda.dep_graph,
                                                                    src_codeloc.ins_addr,
                                                                    src_codeloc)
            state.live_definitions = state.live_definitions.merge(new_state.live_definitions)
            return executed_rda, state

        return False, state
            # self.handle_local_function(state, callee_addr, self.rda._call_stack, self.rda._maximum_local_call_deptj

    def _create_handler(self, data_handler, arg_order, **kwargs):

        def _handler(state, codeloc):
            data_args = []
            for arg_ix in arg_order:
                arg_defs = utils.get_arg_defs(self.p.arch, state, arg_ix)
                if not arg_defs:
                    data_args.append(None)
                    log.error("No argument definitions found")

                arg_dataset = DataSet(set(), max(arg_def.data.bits for arg_def in arg_defs))
                for arg_def in arg_defs:
                    arg_dataset.update(arg_def.data)

                data_args.append(arg_dataset)

            return data_handler(state, codeloc, *data_args)

        return _handler

    def load_string(self, state, addr_dataset, sz_dataset=None):
        loaded_data = self.load_data(state, addr_dataset, sz_dataset)
        str_data = set()
        for str_bytes in loaded_data:
            if 0 in str_bytes:
                str_bytes = str_bytes[:str_bytes.find(0)]

            str_data.add(str_bytes.decode("utf-8", errors="backslashreplace"))

        return str_data

    def load_data(self, state, addr_dataset, sz_dataset=None):
        MAX_STR_SIZE = 1024

        if sz_dataset is None:
            sz_dataset = DataSet({MAX_STR_SIZE}, self.p.arch.bits)
        elif len(sz_dataset) == 0:
            log.warning("Empty size dataset, using %d", MAX_STR_SIZE)
            sz_dataset = DataSet({MAX_STR_SIZE}, self.p.arch.bits)

        sizes = set()
        for sz in sz_dataset:
            if not isinstance(sz, int):
                log.warning("Non-constant size, ignoring...")
                continue

            sizes.add(sz)

        if not sizes:
            log.warning("Assuming size is %d", MAX_STR_SIZE)

        src_and_size_combinations = product(addr_dataset, sizes)

        loaded_data = set()
        for src_arg_data, sz in src_and_size_combinations:
            if isinstance(src_arg_data, int):
                try:
                    src_bytes = self.p.loader.memory.load(src_arg_data, sz)
                except KeyError:
                    log.error("Invalid memory address %#x" % src_arg_data)
                    continue

                loaded_data.add(src_bytes)

            elif isinstance(src_arg_data, SpOffset):
                loaded_data.update(_load_data_from_sp_offset(state, src_arg_data, sz))

            else:
                log.warning("Unhandled src type: %s", src_arg_data)

        return loaded_data

    def _store_dataset(self, state, codeloc, addr_dataset, dataset: DataSet):
        string_dataset_bytes = dataset.bits // 8

        for dst_arg_data in addr_dataset:
            if not isinstance(dst_arg_data, RegisterOffset):
                log.warning("Unhandled dst type: %s", dst_arg_data)
                continue

            if not isinstance(dst_arg_data, SpOffset) and dst_arg_data.reg == 'sp':
                sp_offset =  SpOffset(dst_arg_data.bits, dst_arg_data.offset)
                atom = MemoryLocation(sp_offset, string_dataset_bytes)
            else:
                atom = MemoryLocation(dst_arg_data, string_dataset_bytes)

            state.live_definitions.kill_and_add_definition(atom, codeloc, dataset)

    @abstractmethod
    def _initialize_handlers(self):
        pass
