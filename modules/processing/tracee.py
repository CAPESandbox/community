import base64
import json
import logging
import os
import zlib

from lib.cuckoo.common.abstracts import CUCKOO_ROOT, Processing

log = logging.getLogger(__name__)

__author__ = "@theoleecj2"
__version__ = "1.1.0"

sec_events = {
    "sched_process_exec",
    "stdio_over_socket",
    "k8s_api_connection",
    "aslr_inspection",
    "proc_mem_code_injection",
    "docker_abuse",
    "scheduled_task_mod",
    "ld_preload",
    "cgroup_notify_on_release",
    "default_loader_mod",
    "sudoers_modification",
    "sched_debug_recon",
    "system_request_key_mod",
    "cgroup_release_agent",
    "rcd_modification",
    "core_pattern_modification",
    "proc_kcore_read",
    "proc_mem_access",
    "hidden_file_created",
    "anti_debugging",
    "ptrace_code_injection",
    "process_vm_write_inject",
    "disk_mount",
    "dynamic_code_loading",
    "fileless_execution",
    "illegitimate_shell",
    "kernel_module_loading",
    "k8s_cert_theft",
    "proc_fops_hooking",
    "syscall_hooking",
    "dropped_executable",
}


def load_syscalls_args():
    # Source: strace.py
    """
    Returns dictionary with syscall information indexed by syscall index.
    The values include the signature of the syscall and the category
    extracted from the definition location.
    """
    syscalls_path = os.path.join(CUCKOO_ROOT, "data", "linux", "linux-syscalls.json")
    try:
        with open(syscalls_path, "r") as syscalls_json:
            syscalls_dict = json.load(syscalls_json)
        return {
            syscall["name"]: {
                "signature": syscall["signature"],
                "category": "kernel" if "kernel" in syscall["file"] else syscall["file"].split("/")[0],
            }
            for syscall in syscalls_dict["syscalls"]
        }
    except Exception as e:
        log.error("Failed to load syscalls from %s: %s", syscalls_path, e)
        return {}


class ProcTree:
    def __init__(self, pid, details):
        self.children = {}
        self.pid = pid
        self.details = details

    def to_dict(self):
        output = {"pid": self.pid, "details": dict(self.details), "children": {}}
        for pid, child in self.children.items():
            output["children"][pid] = child.to_dict()
        return output


class TraceeAnalysis(Processing):
    """Tracee Analyzer v1."""

    order = 2
    os = "linux"

    def run(self):
        """
        Run analysis on tracee logs and files
        @return: results dict.
        """
        self.key = "tracee"
        log.info("Tracee Processor Running.")

        syscall_catalog = load_syscalls_args()

        # Initialize the process tree with a root node
        root = ProcTree(0, {"desc": "(ABSTRACTION) root process"})
        # Flat map for O(1) process lookup by PID
        process_map = {0: root}

        logpath = os.path.join(self.analysis_path, "logs", "tracee.log")
        if not os.path.exists(logpath):
            log.warning("Tracee log file not found at %s", logpath)
            return {}

        output = {"metadata": {"security_events": []}, "syscalls": []}
        all_syscalls = output["syscalls"]
        output_metadata = output["metadata"]
        ev_idx = -1

        try:
            # Read the log file directly, skipping the grep subprocess and temp file
            with open(logpath, "r", encoding="utf-8", errors="replace") as f:
                for ln in f:
                    # Filter out strace process lines (equivalent to grep -v "processName":"strace")
                    if '"processName":"strace"' in ln:
                        continue

                    ln = ln.strip()
                    if not ln:
                        continue

                    try:
                        # Parse the outer JSON
                        wrapper_json = json.loads(ln)
                        # Parse the inner "log" JSON string
                        lg = json.loads(wrapper_json["log"])
                    except (ValueError, KeyError, TypeError):
                        # Skip malformed lines
                        continue

                    # Process Syscalls
                    syscall_name = lg.get("syscall")
                    event_name = lg.get("eventName")

                    if syscall_name:
                        ev_idx += 1
                        lg["idx"] = ev_idx
                        lg["cat"] = syscall_catalog.get(syscall_name, {"category": "misc"})["category"]
                        all_syscalls.append(lg)

                        if syscall_name == "execve":
                            # Extract arguments
                            argv = None
                            env = []
                            for arg in lg.get("args", []):
                                if arg["name"] == "argv":
                                    argv = arg["value"]
                                elif "env" in arg["name"]:
                                    env = arg["value"]

                            if argv is not None:
                                parent_pid = lg.get("parentProcessId")
                                process_id = lg.get("processId")

                                # Ensure parent exists in the tree
                                if parent_pid not in process_map:
                                    parent_node = ProcTree(parent_pid, {"desc": "PARENT"})
                                    root.children[parent_pid] = parent_node
                                    process_map[parent_pid] = parent_node

                                # Create and add new process node
                                new_node = ProcTree(
                                    process_id,
                                    {
                                        "desc": argv,
                                        "cmdline": argv,
                                        "env": env,
                                    },
                                )

                                # Link to parent
                                process_map[parent_pid].children[process_id] = new_node
                                # Register in map
                                process_map[process_id] = new_node

                    elif event_name in sec_events:
                        ev_idx += 1
                        lg["idx"] = ev_idx
                        all_syscalls.append(lg)

                    if event_name in sec_events:
                        lg["idx"] = ev_idx
                        output_metadata["security_events"].append(lg)

        except Exception as e:
            log.error("Error analyzing Tracee logs: %s", e)

        output_metadata["proctree"] = root.to_dict()

        return str(base64.b64encode(zlib.compress(bytearray(json.dumps(output), "utf-8"))), "ascii")
