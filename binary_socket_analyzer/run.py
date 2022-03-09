import sys
import traceback
import json

import angr
import logging

from cle import ExternObject

import file_permission_extraction
from address_extraction.android_bind_api import AndroidSocketAddressExtractor
from address_extraction.posix_bind_api import PosixSocketAddressExtractor

FORMAT = "%(levelname) | %(asctime) | %(name) | %(msg)"
logging.basicConfig(format=FORMAT)
log = logging.getLogger("main")
log.setLevel(logging.DEBUG)

# logging.getLogger()
logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)
logging.getLogger("claripy").setLevel(logging.CRITICAL)
logging.getLogger("pyvex").setLevel(logging.CRITICAL)
logging.getLogger("archinfo").setLevel(logging.CRITICAL)

import address_extraction
import dac_check_extraction

SKIP_LIBS = {"libcutils.so",
             "libsysutils.so",
             "libc.so",
             "libc++.so"
             }

def repr_socket_addrs_as_json(analysis_result, ignore_unkown=True):
    socket_addresses = set()
    for callsite_details in analysis_result.values():
        addrs = callsite_details["addresses"]
        # ignore unkown namespaces because they're usually incomplete data
        for addr in addrs:
            if ignore_unkown and addr["namespace"] == "UNKOWN":
                log.info("Ignoring socket address with unkown namespace: %s", addr["address"])
                continue

            if not isinstance(addr["address"], str):
                addr["address"] = addr["address"].decode("utf-8", errors="backslashreplace")

            if addr["namespace"] == "FILESYSTEM":
                params = list(addr.keys())
                for k in params:
                    if k in {"namespace", "address"}:
                        continue

                    if not isinstance(addr[k], int):
                        del addr[k]

            socket_addresses.add(frozenset(addr.items()))

    socket_addresses = [dict(addr) for addr in socket_addresses]
    return json.dumps({"socket_addresses": socket_addresses})

def main():
    log.info("Loading %s" % sys.argv[1].split('/')[-1])
    if len(sys.argv) > 2:
        p = angr.Project(sys.argv[1], ld_path=sys.argv[2:], use_system_libs=False, skip_libs=SKIP_LIBS)
    else:
        p = angr.Project(sys.argv[1], use_system_libs=False, skip_libs=SKIP_LIBS)

    log.info("Loaded %s with missing dependencies %s", sys.argv[1].split('/')[-1], p.loader.missing_dependencies)

    log.info("Generating CFG...")
    p.analyses.CFG()

    result = {}

    try:
        log.info("Extracting socket addresses...")
        android_result = AndroidSocketAddressExtractor(p)
        posix_result = PosixSocketAddressExtractor(p)
        sock_addrs = {**android_result.socket_addresses, **posix_result.socket_addresses}
        bind_apis_available = len(sock_addrs.keys()) > 0

        log.info("Finding file permissions for FILESYSTEM sockets...")
        filesystem_addr_bind_sites_and_files = {}
        for callsite, details in sock_addrs.items():
            for sockaddr in details["addresses"]:
                if sockaddr["namespace"] == "FILESYSTEM":
                    filesystem_addr_bind_sites_and_files[callsite] = filesystem_addr_bind_sites_and_files.get(callsite,
                                                                                                              [])
                    filesystem_addr_bind_sites_and_files[callsite].append(sockaddr["address"])

        res = file_permission_extraction.FilePermissionExtractor(p, filesystem_addr_bind_sites_and_files)
        for cs_addr, perms in res.file_permissions.items():
            for addr in sock_addrs[cs_addr]["addresses"]:
                if addr["namespace"] == "FILESYSTEM":
                    addr.update(perms)

        print("sockets: %s" % repr_socket_addrs_as_json(sock_addrs))

    except Exception as e:
        print("Unhandled error while extracting socket addresses:")
        traceback.print_exc(file=sys.stdout)

    try:
        log.info("Extracting DAC checks...")
        cce_result = dac_check_extraction.CredCheckAnalysis(p)
        sec_optnames = cce_result.security_options
        dac_checks = cce_result.security_checks
        print("has_getsockopt: %s" % str(sec_optnames))
        print("checks: %s" % str(dac_checks))
    except Exception as e:
        print("Unhandled error while extracting DAC checks:")
        traceback.print_exc(file=sys.stdout)

if __name__ == "__main__":
    main()
