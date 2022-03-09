import angr

from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.calling_conventions import SimStackArg, SimRegArg
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions import LiveDefinitions


def get_arg_defs(arch, livedefs, arg_ix):
    cc = angr.DEFAULT_CC[arch.name](arch)
    arg_loc = cc.arg_locs(is_fp=[False] * (arg_ix + 1))[arg_ix]

    if isinstance(arg_loc, SimRegArg):
        reg_offset = arch.registers[arg_loc.reg_name][0]
        arg_defs = livedefs.register_definitions.get_objects_by_offset(reg_offset)
    elif isinstance(arg_loc, SimStackArg):
        arg_defs = livedefs.stack_definitions.get_objects_by_offset(livedefs.get_sp().offset + arg_loc.stack_offset)
    else:
        raise ValueError("")

    return arg_defs

def search_functions(functions, q, match_case=True, exact_match=False):
    matches = []
    q_lower = q
    if not match_case:
        q_lower = q.lower()

    for func in functions.values():
        is_match = func.name == q_lower or func.demangled_name == q_lower
        if not exact_match and not is_match:
            is_match = (q in func.name or q in func.demangled_name) or \
                       not match_case and (q_lower in func.name.lower() or q_lower in func.demangled_name.lower())

        if is_match:
            matches.append(func)

    return matches


def rda_with_dep_graph(p, *args, **kwargs):
    return p.analyses.ReachingDefinitions(*args, dep_graph=DepGraph(), **kwargs)


def get_arg_reg_offset(p, arg_ix):
    cc = angr.DEFAULT_CC[p.arch.name]
    r = cc.ARG_REGS[arg_ix]
    return p.arch.registers[r][0]


def get_ordered_arg_reg_offsets(p):
    cc = angr.DEFAULT_CC[p.arch.name]
    return [p.arch.registers[r][0] for r in cc.ARG_REGS]


def get_function_call_sites_and_targets(p, f):
    functions = p.kb.functions

    call_sites = {}
    for cs in f.get_call_sites():
        ct_addr = f.get_call_target(cs)
        call_sites[cs] = functions.get_by_addr(ct_addr)

    return call_sites


def load_string_from_memory(p, addr, load_size=128):
    try:
        string_bytes = p.loader.memory.load(addr, load_size)
    except KeyError as e:
        return None

    if 0 in string_bytes:
        zix = string_bytes.find(0)
        if zix < 2:
            string_bytes = string_bytes[:string_bytes.find(0, zix)]
        else:
            string_bytes = string_bytes[:zix]

    return string_bytes.decode('utf-8', errors='backslashreplace')


def find_call_in_callgraph(p, f, addr=None, name=None, max_depth=3):
    callsites = {}
    _find_call_in_callgraph(p, f, addr, name, max_depth, callsites)
    return callsites


def _find_call_in_callgraph(p, f, addr, name, max_depth, callsites):
    if max_depth <= 0:
        return

    current_callsites = get_function_call_sites_and_targets(p, f)
    for cs, ct in current_callsites.items():
        if (addr and ct.addr == addr) or (name and ct.demangled_name == name) or (addr is None and name is None):
            callsites[cs] = ct
        else:
            _find_call_in_callgraph(p, ct, addr, name, max_depth-1, callsites)

# def dominates()

