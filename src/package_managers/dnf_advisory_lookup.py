"""Select advisory records from the cache refreshed by OMG's native DNF query."""

import json
import sys

try:
    import libdnf5
except ModuleNotFoundError as error:
    if error.name != "libdnf5":
        raise
    raise SystemExit("Install python3-libdnf5 for supplemental Fedora advisory lookups.") from None


def available_packages(base, security, mode, subjects):
    packages = libdnf5.rpm.PackageQuery(base)
    packages.filter_available()
    if mode == "proposed":
        packages.filter_nevra(subjects)
        return packages, libdnf5.common.QueryCmp_GT

    installed = libdnf5.rpm.PackageQuery(base)
    installed.filter_installed()
    architectures = {}
    for package in installed:
        architectures.setdefault(package.get_name(), set()).add(package.get_arch())

    packages.filter_upgrades()
    packages.filter_advisories(security, libdnf5.common.QueryCmp_GTE)
    transitions = set()
    for package in packages:
        arch = package.get_arch()
        if any(
            old != arch and (old == "noarch" or arch == "noarch")
            for old in architectures.get(package.get_name(), ())
        ):
            transitions.add(package.get_full_nevra())
    if transitions:
        packages.filter_nevra(sorted(transitions))
    else:
        packages.clear()
    return packages, libdnf5.common.QueryCmp_LTE


def metadata(advisory):
    return {
        "Name": advisory.get_name(),
        "Title": advisory.get_title(),
        "Severity": advisory.get_severity(),
        "Type": advisory.get_type(),
        "Description": advisory.get_description(),
        "Vendor": advisory.get_vendor(),
        "Status": advisory.get_status(),
        "Buildtime": advisory.get_buildtime(),
        "Message": advisory.get_message(),
        "Rights": advisory.get_rights(),
        "references": [
            {"Id": ref.get_id(), "Type": ref.get_type(), "Url": ref.get_url(),
             "Title": ref.get_title()}
            for ref in advisory.get_references()
        ],
        "collections": [
            {"packages": sorted(package.get_nevra() for package in collection.get_packages()),
             "modules": sorted(module.get_nsvca() for module in collection.get_modules())}
            for collection in advisory.get_collections()
        ],
    }


def main(cache, mode, expected_repositories, *subjects):
    base = libdnf5.base.Base()
    base.load_config()
    config = base.get_config()
    config.get_plugins_option().set(False)
    config.get_cachedir_option().set(cache)
    config.get_system_cachedir_option().set(cache)
    config.get_cacheonly_option().set("all")
    config.get_disable_excludes_option().set(["*"])
    config.get_optional_metadata_types_option().set(["updateinfo"])
    base.setup()

    repositories = base.get_repo_sack()
    repositories.create_repos_from_system_configuration()
    enabled = libdnf5.repo.RepoQuery(base)
    enabled.filter_enabled(True)
    if {repo.get_id() for repo in enabled} != set(json.loads(expected_repositories)):
        raise RuntimeError("Enabled repositories differ from the refreshed DNF scope")
    for repo in enabled:
        repo.get_config().get_skip_if_unavailable_option().set(False)
    if mode == "proposed":
        repositories.load_repos(libdnf5.repo.Repo.Type_AVAILABLE)
    else:
        repositories.load_repos()

    security = libdnf5.advisory.AdvisoryQuery(base)
    security.filter_type(["security"])
    packages, comparison = available_packages(base, security, mode, subjects)
    matches = security.get_advisory_packages_sorted(packages, comparison)
    if len(matches) > 10_000:
        raise RuntimeError("Supplemental advisory rows exceed their bound")

    applicable, details = [], {}
    for package in matches:
        advisory = package.get_advisory()
        key = advisory.get_id().id
        if key not in details:
            details[key] = metadata(advisory)
        applicable.append({
            "name": advisory.get_name(), "type": advisory.get_type(),
            "severity": advisory.get_severity(), "nevra": package.get_nevra(),
        })
    print(json.dumps({"applicable": applicable, "details": list(details.values())}))


if __name__ == "__main__":
    main(*sys.argv[1:])
