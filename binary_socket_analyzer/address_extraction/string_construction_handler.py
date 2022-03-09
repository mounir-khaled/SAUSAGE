import logging
from functools import reduce
from itertools import product

from angr.analyses import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.engines.light import SpOffset, RegisterOffset
from angr.knowledge_plugins.key_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.atoms import Atom, MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.knowledge_plugins.key_definitions.dataset import DataSet
from angr.knowledge_plugins.key_definitions.definition import Definition
from typing import Set

from angr.knowledge_plugins.key_definitions.undefined import Undefined

import utils
from generic_function_handler import GenericFunctionHandler

log = logging.getLogger(__name__)

class UndefinedStringAddress(Undefined):
    def __init__(self, idx, offset=0):
        self.idx = idx
        self.offset = offset

    def __add__(self, other):
        if not isinstance(other, int):
            raise NotImplemented
        return UndefinedStringAddress(self.idx, self.offset + other)

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        return UndefinedStringAddress(self.idx, self.offset - other)

    def __eq__(self, other):
        return isinstance(other, UndefinedStringAddress) and other.idx == self.idx and other.offset == self.offset

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(hash('UndefinedStringAddress') ^ hash(self.idx) ^ hash(self.offset))

    def __str__(self):
        return '<UndefinedStringAddress[%d] + %#x>' % (self.idx, self.offset)

    def __repr__(self):
        return str(self)

class StringConstructionHandler(GenericFunctionHandler):
    def __init__(self):
        super(StringConstructionHandler, self).__init__(stop_after_obs_points=True)

    def hook(self, analysis: ReachingDefinitionsAnalysis):
        super(StringConstructionHandler, self).hook(analysis)
        self._strings_at_undefined = []
        return self

    def _replace_with_undefined_string_address(self, state:ReachingDefinitionsState, codeloc, _def):
        if not any(isinstance(element, Undefined) for element in _def.data):
            return

        new_dataset = DataSet(set(), _def.data.bits)
        for data in _def.data:
            if isinstance(data, Undefined):
                idx = len(self._strings_at_undefined)
                self._strings_at_undefined.append("")
                new_addr = UndefinedStringAddress(idx)
                new_dataset.update(new_addr)
            else:
                new_dataset.update(data)

        state.kill_and_add_definition(_def.atom, codeloc, new_dataset)

    def _create_handler(self, data_handler, arg_order, dst_arg_ix=None, fmt_string_ix=None):

        def _handler(state, codeloc):
            max_arg_ix = max(arg_order)
            args = []
            n_fmt_args = 0
            for arg_ix in arg_order:
                arg_defs = utils.get_arg_defs(self.p.arch, state, arg_ix)
                if not arg_defs:
                    args.append(None)
                    log.error("No argument definitions found")

                if arg_ix == dst_arg_ix:
                    for arg_def in arg_defs:
                        self._replace_with_undefined_string_address(state, codeloc, arg_def)

                arg_defs = utils.get_arg_defs(self.p.arch, state, arg_ix)
                arg_data = set()
                for arg_def in arg_defs: arg_data.update(arg_def.data)
                args.append(arg_data)
                if arg_ix == fmt_string_ix:
                    fmt_string_data = self.load_string(state, arg_data)
                    fmt_str = fmt_string_data.pop()
                    n_fmt_args = fmt_str.count("%") - fmt_str.count("%%") * 2

            for i in range(n_fmt_args):
                arg_ix = max_arg_ix + 1 + i
                arg_defs = utils.get_arg_defs(self.p.arch, state, arg_ix)
                arg_data = set()
                for arg_def in arg_defs: arg_data.update(arg_def.data)
                args.append(arg_data)

            return data_handler(state, codeloc, *args)

        return _handler

    def _initialize_handlers(self):
        # memcpy
        for fn in ["memcpy", "__aeabi_memcpy"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_memcpy, [0, 1, 2]))

        # str* functions
        for fn in ["strcpy", "__strcpy_chk"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strcpy_like_function, [0, 1], dst_arg_ix=0))

        for fn in ["strncpy", "strlcpy", "__strncpy_chk", "__strlcpy_chk", "__strncpy_chk2"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strcpy_like_function, [0, 1, 2], dst_arg_ix=0))

        for fn in ["strcat", "__strcat_chk"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strcat_like_function, [0, 1], dst_arg_ix=0))

        for fn in ["strncat", "strlcat", "__strncat_chk", "__strlcat_chk"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strcat_like_function, [0, 1, 2], dst_arg_ix=0))

        # format strings
        self.handle_sprintf = self._create_handler(self._handle_format_function, [0, 1], fmt_string_ix=1, dst_arg_ix=0)
        self.handle___sprintf_chk = self._create_handler(self._handle_format_function, [0, 3], fmt_string_ix=3, dst_arg_ix=0)
        self.handle_snprintf = self._create_handler(self._handle_format_function, [0, 2], fmt_string_ix=2, dst_arg_ix=0)
        self.handle___snprintf_chk = self._create_handler(self._handle_format_function, [0, 4], fmt_string_ix=4, dst_arg_ix=0)

        # TODO: guessing using strstr and strcmp?
        
    def _store_dataset(self, state, codeloc, addr_dataset, dataset: DataSet):
        super(StringConstructionHandler, self)._store_dataset(state, codeloc, addr_dataset, dataset)
        for addr in addr_dataset:
            if isinstance(addr, UndefinedStringAddress):
                self._strings_at_undefined[addr.idx] = dataset
                if addr.offset:
                    log.critical("HANDLE OFFSETS!!")

    def load_data(self, state, addr_dataset, sz_dataset=None):
        data = super(StringConstructionHandler, self).load_data(state, addr_dataset, sz_dataset)
        for addr in addr_dataset:
            if isinstance(addr, UndefinedStringAddress):
                data.add(self._strings_at_undefined[addr.idx].encode("utf-8"))

        return data

    def _handle_memcpy(self, state: 'ReachingDefinitionsState',
                                     codeloc,
                                     dst_arg_dataset: 'DataSet',
                                     src_arg_dataset: 'DataSet',
                                     sz_dataset: 'DataSet'):
        src_data = self.load_data(state, src_arg_dataset, sz_dataset)
        max_size = -1
        for sz in sz_dataset:
            if isinstance(sz, int):
                max_size = sz if sz > max_size else max_size

        if max_size == -1:
            log.error("memcpy failed: undefined size")
            return False, state
        elif not src_data:
            log.error("memcpy failed: undefined src")
            return False, state

        src_dataset = DataSet(src_data, max_size * 8)
        self._store_dataset(state, codeloc, dst_arg_dataset, src_dataset)

        return False, state

    def _handle_strcat_like_function(self, state: 'ReachingDefinitionsState',
                                     codeloc,
                                     dst_arg_dataset: 'DataSet',
                                     src_arg_dataset: 'DataSet',
                                     sz_dataset=None):
        src_string_data = self.load_string(state, src_arg_dataset, sz_dataset)
        dst_string_data = self.load_string(state, dst_arg_dataset)
        if not src_string_data:
            log.error("strcat: No string_data at %s", src_arg_dataset)
            return False, state

        if not dst_string_data:
            log.warning("strcat: No string_data at %s", dst_arg_dataset)

        new_string_data = set()
        for src_string, dst_string in product(src_string_data, dst_string_data):
            new_string = dst_string + src_string
            new_string_data.add(new_string)

        string_dataset_bytes = max(len(s) for s in new_string_data)
        string_dataset = DataSet(new_string_data, string_dataset_bytes * 8)

        self._store_dataset(state, codeloc, dst_arg_dataset, string_dataset)
        return False, state

    def _handle_strcpy_like_function(self, state: 'ReachingDefinitionsState',
                                     codeloc,
                                     dst_arg_dataset: 'DataSet',
                                     src_arg_dataset: 'DataSet',
                                     sz_dataset=None):

        string_data = self.load_string(state, src_arg_dataset, sz_dataset)
        if not string_data:
            log.error("strcpy: No string_data at %s", src_arg_dataset)
            return False, state

        string_dataset_bytes = max(len(s) for s in string_data)
        string_dataset = DataSet(string_data, string_dataset_bytes * 8)

        self._store_dataset(state, codeloc, dst_arg_dataset, string_dataset)
        return False, state

    def _handle_format_function(self, state: 'ReachingDefinitionsState',
                                codeloc,
                                dst_arg_dataset: 'DataSet',
                                fmt_arg_dataset: 'DataSet',
                                *val_arg_datasets):

        fmt_string_data = self.load_string(state, fmt_arg_dataset)
        out_string_data = set()
        for fmt_string in fmt_string_data:
            fmt_strings = [fmt_string]
            for val_arg_dataset in val_arg_datasets:
                next_fmt_strings = []
                for fmt_string in fmt_strings:
                    perc_ix = fmt_string.find("%")
                    arg_type = fmt_string[perc_ix + 1]
                    # TODO: handle multiple values in dataset
                    if arg_type == 's':
                        str_arg_data = self.load_string(state, val_arg_dataset)
                        if str_arg_data:
                            for str_arg in str_arg_data:
                                next_fmt_string = fmt_string.replace("%s", str_arg)
                                next_fmt_strings.append(next_fmt_string)
                        else:
                            next_fmt_string = fmt_string.replace("%s", "<<UNKNOWN>>")
                            next_fmt_strings.append(next_fmt_string)

                    elif arg_type == 'd':
                        for int_arg in val_arg_dataset:
                            next_fmt_string = fmt_string.replace("%d", str(int_arg))
                            next_fmt_strings.append(next_fmt_string)
                    elif arg_type == '%':
                        next_fmt_strings.append(fmt_string)
                    else:
                        log.warning("Unrecognized arg_type '%s' in '%s'", arg_type, fmt_string)
                        next_fmt_strings.append(fmt_string)

                fmt_strings = next_fmt_strings.copy()

            out_string_data.update(fmt_strings)

        string_dataset_bytes = max(len(s) for s in out_string_data)
        string_dataset = DataSet(out_string_data, string_dataset_bytes * 8)

        self._store_dataset(state, codeloc, dst_arg_dataset, string_dataset)
        return False, state
