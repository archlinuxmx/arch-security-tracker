import tarfile
from operator import attrgetter
from os import chdir
from pathlib import Path
from time import time

from pyalpm import vercmp
from pycman.config import init_with_config

from config import PACMAN_HANDLE_CACHE_TIME
from config import basedir
from tracker.util import cmp_to_key

archs = ['x86_64']
primary_arch = 'x86_64'
repos = {'x86_64': ['core', 'core-testing', 'extra', 'extra-testing', 'multilib', 'multilib-testing']}
configpath = './pacman/arch/{}/pacman.conf'
handles = {}
chdir(basedir)


def get_configpath(arch):
    return configpath.format(arch)


def get_handle(arch, force_fresh_handle=False):
    if not force_fresh_handle and arch in handles:
        handle, creation_time = handles[arch]
        if creation_time > time() - PACMAN_HANDLE_CACHE_TIME:
            return handle
    handle = init_with_config(get_configpath(arch))
    handles[arch] = (handle, time())
    return handle


def update(arch=None, force=False):
    update_archs = [arch] if arch else archs
    for arch in update_archs:
        for syncdb in get_handle(arch).get_syncdbs():
            syncdb.update(force)


def get_pkg(pkgname, arch=None, testing=True, filter_arch=False, force_fresh_handle=False, sort_results=True, filter_duplicate_packages=True):
    get_archs = [arch] if arch else archs
    results = set()
    for arch in get_archs:
        for syncdb in get_handle(arch, force_fresh_handle=force_fresh_handle).get_syncdbs():
            if not testing and 'testing' in syncdb.name:
                continue
            result = syncdb.get_pkg(pkgname)
            if result:
                results.add(result)
    if sort_results:
        results = sort_packages(results)
    if filter_duplicate_packages:
        results = filter_duplicates(results, filter_arch)
    return results


def search(pkgname, arch=None, testing=True, filter_arch=False, force_fresh_handle=False,
           sort_results=True, filter_duplicate_packages=True, required_repositories=None):
    search_archs = [arch] if arch else archs
    results = []
    repositories = set()
    for arch in search_archs:
        handle = get_handle(arch, force_fresh_handle=force_fresh_handle)
        for syncdb in handle.get_syncdbs():
            if not testing and 'testing' in syncdb.name:
                continue
            if required_repositories is not None:
                try:
                    with tarfile.open(Path(handle.dbpath) / 'sync' / (syncdb.name + '.db')) as archive:
                        archive.getmembers()
                except (OSError, tarfile.TarError, EOFError) as error:
                    raise ValueError('Cannot read repository {}; keeping the existing cache.'
                                     .format(syncdb.name)) from error
            repositories.add(syncdb.name)
            result = syncdb.search(pkgname)
            if result:
                results.extend(result)
    if required_repositories is not None and required_repositories - repositories:
        raise ValueError('Repositories missing from refresh: {}; keeping the existing cache.'
                         .format(', '.join(sorted(required_repositories - repositories))))
    if sort_results:
        results = sort_packages(results)
    if filter_duplicate_packages:
        results = filter_duplicates(results, filter_arch)
    return results


def filter_duplicates(packages, filter_arch=False):
    filtered = []
    seen = set()
    for pkg in packages:
        key = (pkg.name, pkg.version, pkg.db.name, None if filter_arch else pkg.arch)
        if key not in seen:
            seen.add(key)
            filtered.append(pkg)
    return filtered


def sort_packages(packages):
    packages = sorted(packages, key=lambda item: item.arch)
    packages = sorted(packages, key=lambda item: item.db.name)
    packages = sorted(packages, key=cmp_to_key(vercmp, attrgetter('version')), reverse=True)
    return packages
