"""Run unprivileged script contracts; native fixtures remain in Workflow checks."""
import json
from pathlib import Path
import unittest

NATIVE_TEST_IDS = frozenset({
    'test_gitignore_audit_artifacts.GitignoreAuditArtifacts.test_audit_record_is_tracked',
    'test_export_qemu_evidence.DescriptorTests.test_root_owned_diagnostics_export_for_runner_without_changing_source',
    'test_qemu_doctor_turbo_oracle.CapabilityOracleTests.test_changed_copy_refuses_even_when_write_clears_capabilities',
    'test_qemu_doctor_turbo_oracle.CapabilityOracleTests.test_changed_original_refuses',
    'test_qemu_doctor_turbo_oracle.CapabilityOracleTests.test_empty_set_is_not_removed_xattr',
    'test_qemu_doctor_turbo_oracle.CapabilityOracleTests.test_linked_private_directory_refuses_without_touching_original',
    'test_qemu_doctor_turbo_oracle.CapabilityOracleTests.test_missing_matching_product_result_refuses',
    'test_qemu_doctor_turbo_oracle.CapabilityOracleTests.test_real_removal_positive_preserves_original',
    'test_qemu_doctor_turbo_oracle.CapabilityOracleTests.test_success_message_without_real_removal_refuses',
    'test_qemu_network_scope.NetworkScopeTests.test_actual_remote_wrapper_has_no_external_interface_and_preserves_user',
    'test_qemu_network_scope.NetworkScopeTests.test_root_remote_wrapper_also_drops_all_capabilities',
    'test_qemu_output_contracts.OutputContracts.test_doctor_turbo_requires_real_capability_removal',
})

def cases(suite):
    for entry in suite:
        if isinstance(entry, unittest.TestSuite):
            yield from cases(entry)
        else:
            yield entry

def partition(suite, native_ids):
    discovered = list(cases(suite))
    names = [case.id() for case in discovered]
    if len(names) != len(set(names)):
        raise ValueError("duplicate script test identity")
    missing = native_ids - set(names)
    if missing:
        raise ValueError("missing native script test identities: " + ", ".join(sorted(missing)))
    selected = [case for case in discovered if case.id() not in native_ids]
    if not selected:
        raise ValueError("empty portable script selection")
    return unittest.TestSuite(selected), sorted(native_ids)

def main():
    suite = unittest.defaultTestLoader.discover(str(Path.cwd() / "scripts"), pattern="test_*.py")
    selected, native = partition(suite, NATIVE_TEST_IDS)
    print("OMG_SCRIPT_SELECTION=" + json.dumps({
        "portable": [case.id() for case in selected],
        "native": native,
        "nativeGate": "Workflow checks",
        "nativeCommand": "make ci-workflow-quick",
        "nativeAcceptance": False,
    }, sort_keys=True), flush=True)
    return 0 if unittest.TextTestRunner(verbosity=1).run(selected).wasSuccessful() else 1

if __name__ == "__main__":
    raise SystemExit(main())
