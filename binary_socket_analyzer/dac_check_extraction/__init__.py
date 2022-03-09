
import logging
from collections import deque

import pyvex.stmt
from angr.analyses import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins import Function
from angr.knowledge_plugins.key_definitions.atoms import GuardUse
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag, ParameterTag

from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.definition import Definition

import utils
from dac_check_extraction.getsockopt_handler import GetsockoptHandler, CredData

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def _find_cmp_ops_and_constants(block, ins_addr):
    ops_and_constants = []

    curr_ins_addr = -1
    accumulated_constants = []
    for stmt in block.vex.statements:
        if isinstance(stmt, pyvex.stmt.IMark):
            curr_ins_addr = stmt.addr + stmt.delta
        elif isinstance(stmt, pyvex.stmt.WrTmp) and curr_ins_addr == ins_addr:
            expr = stmt.data
            accumulated_constants.extend(c.con.value
                                            for c in expr.child_expressions if isinstance(c, pyvex.expr.Const))

            if isinstance(expr, pyvex.expr.Binop) and "cmp" in expr.op.lower():
                ops_and_constants.extend((block.addr, expr.op, c.con.value)
                                            for c in expr.child_expressions if isinstance(c, pyvex.expr.Const))

                if not ops_and_constants:
                    ops_and_constants.extend((block.addr, expr.op, c) for c in accumulated_constants)
                    accumulated_constants = []

                if not ops_and_constants:
                    ops_and_constants.append((block.addr, expr.op, "UNDEFINED"))

    return ops_and_constants

def _is_function_argument(_def):
    return any(isinstance(t, ParameterTag) for t in _def.tags)

def _is_return_value(_def):
    return any(isinstance(t, ReturnValueTag) for t in _def.tags)

def _find_dependent_arg_defs(dep_graph, _def, same_data=True):
    dependent_args = set()
    data = _def.data.get_first_element()
    for arg in dep_graph.nodes():
        if _is_function_argument(arg):
            is_same_data = (not same_data) or (same_data and data in arg.data)
            if is_same_data:
                tc = dep_graph.transitive_closure(arg)
                if tc.has_node(_def):
                    dependent_args.add(arg)

    return dependent_args

class CredCheckAnalysis:
    def __init__(self, p):
        self.p = p
        self.cfg = p.kb.cfgs["CFGFast"]
        self.functions = p.kb.functions
        self.security_options = []
        self._sec_getsockopt_calls = []
        # self.security_checks = {"uid": {"is_used": False, "uses": set()},
        #                         "gid": {"is_used": False, "uses": set()},
        #                         "pid": {"is_used": False, "uses": set()},
        #                         "cred": {"is_used": False, "uses": set()}}
        self.security_checks = {}

        self._analyze()

    def _find_dependent_guard_defs(self, dep_graph, _def, same_data=True):
        dependent_guards = set()
        data = _def.data.get_first_element()
        for g in dep_graph.nodes():
            if isinstance(g.atom, GuardUse) or g.data.bits == 1:
                pred_def = g
                if same_data:
                    g_preds = list(dep_graph.predecessors(pred_def))
                    is_dependent = any(data in pred.data for pred in g_preds)
                else:
                    tc = dep_graph.transitive_closure(g)
                    is_dependent = tc.has_node(_def)

                if is_dependent:
                    dependent_guards.add(g)

        return dependent_guards

    def _analyze(self):
        self._sec_getsockopt_calls = self._find_getsockopt_calls_and_optnames()
        self.security_options += [opt for cs, opt in self._find_setsockopt_calls_and_optnames()]
        self.security_options += [opt for cs, opt in self._sec_getsockopt_calls]

        callsites = [cs_node for cs_node, optname in self._sec_getsockopt_calls if optname == 17]

        getsockopt_callers = callsites

        while getsockopt_callers:
            callsite_node = getsockopt_callers.pop()

            security_checks = {}

            caller_fn:Function = self.functions.get_by_addr(callsite_node.function_address)
            observation_points = [("node", callsite_node.addr, OP_AFTER)]

            getsockopt_handler = GetsockoptHandler()
            rda = self.p.analyses.ReachingDefinitions(caller_fn, observation_points=observation_points,
                                               function_handler=getsockopt_handler, call_stack=[],
                                               maximum_local_call_depth=4, dep_graph=DepGraph())

            rd_after_getsockopt = rda.one_result
            cred_defs = utils.get_arg_defs(self.p.arch, rd_after_getsockopt, 3)

            for cred_def in cred_defs:
                for cred_sp_offset in cred_def.data:
                    pid_defs = rd_after_getsockopt.stack_definitions.get_objects_by_offset(cred_sp_offset.offset)
                    uid_defs = rd_after_getsockopt.stack_definitions.get_objects_by_offset(cred_sp_offset.offset + 4)
                    gid_defs = rd_after_getsockopt.stack_definitions.get_objects_by_offset(cred_sp_offset.offset + 8)

                    for uid_def in uid_defs:
                        if not any(isinstance(d, CredData) for d in uid_def.data):
                            continue

                        if rda.all_uses.get_uses(uid_def):
                            security_checks["uid"] = security_checks.get("uid", set())
                            security_checks["uid"].update(("cmp", *chk)
                                                               for chk in self._find_checks(rda.dep_graph, uid_def))
                            security_checks["uid"].update(("arg", *arg)
                                                               for arg in self._find_call_uses(rda.dep_graph, uid_def))

                    for gid_def in gid_defs:
                        if not any(isinstance(d, CredData) for d in gid_def.data):
                            continue

                        if rda.all_uses.get_uses(gid_def):
                            security_checks["gid"] = security_checks.get("gid", set())
                            security_checks["gid"].update(("cmp", *chk)
                                                               for chk in self._find_checks(rda.dep_graph, gid_def))
                            security_checks["gid"].update(("arg", *arg)
                                                               for arg in self._find_call_uses(rda.dep_graph, gid_def))

                    for pid_def in pid_defs:
                        if not any(isinstance(d, CredData) for d in pid_def.data):
                            continue

                        if rda.all_uses.get_uses(pid_def):
                            security_checks["pid"] = security_checks.get("pid", set())
                            security_checks["pid"].update(("cmp", *chk)
                                                               for chk in self._find_checks(rda.dep_graph, pid_def))
                            security_checks["pid"].update(("arg", *arg)
                                                               for arg in self._find_call_uses(rda.dep_graph, pid_def))

                    for cred_def in cred_defs:
                        security_checks["cred"] = security_checks.get("cred", set())
                        security_checks["cred"].update(("arg", *arg)
                                                                    for arg in self._find_call_uses(rda.dep_graph, cred_def))

            self.security_checks[callsite_node.addr] = security_checks

        # cred_checks = self.security_checks["cred"]["uses"].copy()
        # for chk in cred_checks:
        #     if chk[0] == 'arg' and chk[1].name == "getsockopt":
        #         self.security_checks["cred"]["uses"].remove(chk)

    def _find_call_uses(self, dep_graph, _def):
        call_uses = set()
        dependent_args = _find_dependent_arg_defs(dep_graph, _def)
        for arg in dependent_args:
            p_tags = [t for t in arg.tags if isinstance(t, ParameterTag)]
            for p_tag in p_tags:
                if not p_tag.function:
                    log.error("Unresolved function address in call use", p_tag.function)
                    continue

                fn = self.functions.get_by_addr(p_tag.function)
                call_uses.add((fn, frozenset(arg.data.data)))

        return call_uses

    def _find_checks(self, dep_graph, _def):
        checks = set()

        dependent_guards = self._find_dependent_guard_defs(dep_graph, _def)
        for g in dependent_guards:
            b = self.cfg.get_node(g.codeloc.block_addr).block
            ops_and_constants = _find_cmp_ops_and_constants(b, g.codeloc.ins_addr)
            resolved = set()
            for b_addr, op, const in ops_and_constants:
                if const == "UNDEFINED":
                    operand_defs = dep_graph.predecessors(g)
                    for op_def in operand_defs:
                        if any(isinstance(d, CredData) for d in op_def.data):
                            continue

                        resolved.add((b_addr, op, op_def.data))

                else:
                    resolved.add((b_addr, op, const))

            checks.update(ops_and_constants)

        return checks

    def _find_getsockopt_calls_and_optnames(self):
        try:
            getsockopt_addr = self.functions["getsockopt"].addr
        except KeyError:
            return []

        calls = []
        optname_arg_reg_offset = utils.get_arg_reg_offset(self.p, 2)

        getsockopt_callsite_nodes = self.cfg.get_node(getsockopt_addr).predecessors
        for cs_node in getsockopt_callsite_nodes:
            cs_block = cs_node.block
            call_insn_addr = max(cs_block.instruction_addrs)
            observation_point = ("insn", call_insn_addr, OP_BEFORE)
            rda = self.p.analyses.ReachingDefinitions(cs_node.block, observation_points=[observation_point])
            livedefs = rda.one_result
            arg_defs = livedefs.register_definitions.get_variables_by_offset(optname_arg_reg_offset)
            for arg_def in arg_defs:
                for data_element in arg_def.data.data:
                    if not isinstance(data_element, int):
                        log.error("getsockopt optname is not an int %#x", cs_block.addr)
                        continue

                    # https://cs.android.com/android/platform/superproject/+/master:bionic/libc/kernel/uapi/asm-generic/socket.h?q=SO_PEERCRED&ss=android%2Fplatform%2Fsuperproject:bionic%2Flibc%2F
                    # SO_PEERCRED, SO_PEERSEC
                    if data_element in {17, 31}:
                        calls.append((cs_node, data_element))

        return calls


    def _find_setsockopt_calls_and_optnames(self):
        try:
            getsockopt_addr = self.functions["setsockopt"].addr
        except KeyError:
            return []

        calls = []
        optname_arg_reg_offset = utils.get_arg_reg_offset(self.p, 2)

        getsockopt_callsite_nodes = self.cfg.get_node(getsockopt_addr).predecessors
        for cs_node in getsockopt_callsite_nodes:
            cs_block = cs_node.block
            call_insn_addr = max(cs_block.instruction_addrs)
            observation_point = ("insn", call_insn_addr, OP_BEFORE)
            rda = self.p.analyses.ReachingDefinitions(cs_node.block, observation_points=[observation_point])
            livedefs = rda.one_result
            arg_defs = livedefs.register_definitions.get_variables_by_offset(optname_arg_reg_offset)
            for arg_def in arg_defs:
                for data_element in arg_def.data.data:
                    if not isinstance(data_element, int):
                        log.error("setsockopt optname is not an int %#x", cs_block.addr)
                        continue

                    # https://cs.android.com/android/platform/superproject/+/master:bionic/libc/kernel/uapi/asm-generic/socket.h?q=SO_PEERCRED&ss=android%2Fplatform%2Fsuperproject:bionic%2Flibc%2F
                    # SO_PASSCRED, SO_PASSSEC
                    if data_element in {16, 34}:
                        calls.append((cs_node, data_element))

        return calls