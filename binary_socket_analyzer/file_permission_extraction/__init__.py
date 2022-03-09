from typing import Iterable, Dict

import angr
import logging

import networkx as nx
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE

import utils

log = logging.getLogger(__name__)

class FilePermissionExtractor:

    def __init__(self, p: angr.Project, file_creation_sites: Dict[int, Iterable[str]]):
        self.p = p
        self.cfg = p.kb.cfgs["CFGFast"]
        self.functions = p.kb.functions
        self.file_creation_sites = file_creation_sites

        self.file_permissions = {}

        self._analyze()

    def _find_all_callsites_and_arguments(self, fns, arg_ixs):
        callsite_nodes = []
        for fn in fns:
            fn_node = self.cfg.get_node(fn.addr)
            caller_nodes = [no for no, jk in fn_node.predecessors_and_jumpkinds() if jk == "Ijk_Call"]
            callsite_nodes.extend(caller_nodes)

        callsites_and_arguments = {}
        for cs_node in callsite_nodes:
            callsites_and_arguments[cs_node] = None
            if not cs_node.block:
                log.error("Block at node %#x was not lifted", cs_node.addr)
                continue

            call_insn_addr = max(cs_node.block.instruction_addrs)
            obs_point = ("insn", call_insn_addr, OP_BEFORE)
            rda = self.p.analyses.ReachingDefinitions(cs_node.block, observation_points=[obs_point])
            livedefs = rda.one_result

            callsites_and_arguments[cs_node] = {}
            for arg_ix in arg_ixs:
                arg_defs = utils.get_arg_defs(self.p.arch, livedefs, arg_ix)
                if not arg_defs:
                    log.error("Argument was not defined in block at %#x", cs_node.addr)
                    continue

                if len(arg_defs) > 1:
                    log.warning("Multiple argument definitions found, using one of them...")

                arg_def = next(iter(arg_defs))
                callsites_and_arguments[cs_node][arg_ix] = arg_def.data.get_first_element()

        return callsites_and_arguments

    def _find_umask_callsites_and_arguments(self):
        umask_fns = utils.search_functions(self.functions, "umask")
        umask_fns = [fn for fn in umask_fns if fn.name == "umask" or fn.name == "__umask_chk"]

        return self._find_all_callsites_and_arguments(umask_fns, [0])


    def _find_fn_callsites_and_arguments(self, fn_name, arg_ixs):
        fns = utils.search_functions(self.functions, fn_name, exact_match=True)
        return self._find_all_callsites_and_arguments(fns, arg_ixs)

    def _find_closest_callsite_before_node(self, callsite_nodes, target_node):
        for cs_node in callsite_nodes:
            if not nx.has_path(self.cfg.graph, cs_node, target_node):
                continue

            is_closest_callsite = True
            shortest_path = nx.shortest_path(self.cfg.graph, cs_node, target_node)
            for no in shortest_path[1:]:
                if no in callsite_nodes:
                    log.info(""
                             "Another callsite was found in path " + \
                             "between callsite at %#x and file creation at %#x",
                             cs_node.addr, target_node.addr)

                    is_closest_callsite = False
                    break

            if is_closest_callsite:
                return cs_node

        return None

    def _find_closest_callsite_after_node(self, source_node, callsite_nodes):
        for target_node in callsite_nodes:
            if not nx.has_path(self.cfg.graph, source_node, target_node):
                continue

            is_closest_callsite = True
            shortest_path = nx.shortest_path(self.cfg.graph, source_node, target_node)
            for no in shortest_path[:-1]:
                if no in callsite_nodes:
                    log.info(""
                             "Another callsite was found in path " + \
                             "between callsite at %#x and file creation at %#x",
                             source_node.addr, target_node.addr)

                    is_closest_callsite = False
                    break

            if is_closest_callsite:
                return target_node

        return None


    def _analyze(self):
        umask_cs_and_args = self._find_umask_callsites_and_arguments()
        seteuid_cs_and_args = self._find_fn_callsites_and_arguments("seteuid", [0])
        setegid_cs_and_args = self._find_fn_callsites_and_arguments("setegid", [0])

        chmod_cs_and_args = self._find_fn_callsites_and_arguments("chmod", [0, 1])
        fchmod_cs_and_args = self._find_fn_callsites_and_arguments("fchmod", [1])

        chown_cs_and_args = self._find_fn_callsites_and_arguments("chown", [0, 1, 2])
        fchown_cs_and_args = self._find_fn_callsites_and_arguments("fchown", [1, 2])

        for addr, files in self.file_creation_sites.items():
            self.file_permissions[addr] = {}
            file_creation_node = self.cfg.get_node(addr)

            # umask
            closest_umask_node = self._find_closest_callsite_before_node(umask_cs_and_args.keys(), file_creation_node)
            if closest_umask_node:
                self.file_permissions[addr]["umask"] = umask_cs_and_args[closest_umask_node][0]

            # seteuid
            closest_seteuid_node = self._find_closest_callsite_before_node(seteuid_cs_and_args.keys(),
                                                                           file_creation_node)
            if closest_seteuid_node:
                self.file_permissions[addr]["uid"] = umask_cs_and_args[closest_seteuid_node][0]

            # setegid
            closest_setegid_node = self._find_closest_callsite_before_node(setegid_cs_and_args.keys(),
                                                                           file_creation_node)
            if closest_setegid_node:
                self.file_permissions[addr]["gid"] = setegid_cs_and_args[closest_setegid_node][0]

            # fchmod
            closest_chmod_node = self._find_closest_callsite_after_node(file_creation_node,
                                                                         list(fchmod_cs_and_args.keys()) + \
                                                                         list(chmod_cs_and_args.keys()))
            if closest_chmod_node in fchmod_cs_and_args:
                self.file_permissions[addr]["mode"] = fchmod_cs_and_args[closest_chmod_node][1]
            elif closest_chmod_node in chmod_cs_and_args:
                args = chmod_cs_and_args[closest_chmod_node]
                if isinstance(args[0], int):
                    path = utils.load_string_from_memory(self.p, args[0], 256)
                    if path.encode('utf-8') in files:
                        self.file_permissions[addr]["mode"] = args[1]
                else:
                    self.file_permissions[addr]["mode"] = args[1]

            # chown
            closest_chown_node = self._find_closest_callsite_after_node(file_creation_node,
                                                                         list(fchown_cs_and_args.keys()) + \
                                                                         list(chown_cs_and_args.keys()))
            if closest_chown_node in fchown_cs_and_args:
                args = fchown_cs_and_args[closest_chown_node]
                self.file_permissions[addr]["uid"] = args[1]
                self.file_permissions[addr]["gid"] = args[2]
            elif closest_chown_node in chown_cs_and_args:
                args = chown_cs_and_args[closest_chown_node]
                if isinstance(args[0], int):
                    path = utils.load_string_from_memory(self.p, args[0], 256)
                    if path.encode('utf-8') in files:
                        self.file_permissions[addr]["uid"] = args[1]
                        self.file_permissions[addr]["gid"] = args[2]
                else:
                    self.file_permissions[addr]["uid"] = args[1]
                    self.file_permissions[addr]["gid"] = args[2]




