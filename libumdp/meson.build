project('umdp', 'c',
  version : '0.1',
  default_options : ['c_std=c11', 'buildtype=debugoptimized', 'warning_level=3'])

nl_dep = dependency('libnl-3.0', version: '>=3.5.0')
genl_dep = dependency('libnl-genl-3.0', version: '>=3.5.0')

# These arguments are only used to build the library
# not the executables that use the library.
lib_args = ['-DBUILDING_UMDP']

incdir = include_directories('include')
umdp_lib = library('umdp', 'src/umdp.c', 'src/handlers.c',
  c_args: lib_args,
  include_directories: incdir,
  dependencies: [nl_dep, genl_dep],
  gnu_symbol_visibility: 'hidden',
  install: true,
)

# Make this library usable as a Meson subproject.
umdp_dep = declare_dependency(
  include_directories: incdir,
  link_with : umdp_lib)

test_exe = executable('umdp_test', 'test/umdp_test.c',
  dependencies: umdp_dep)
test('umdp', test_exe)

# Make this library usable from the system's
# package manager.
install_headers('include/umdp.h', subdir : 'umdp')

pkg_mod = import('pkgconfig')
pkg_mod.generate(
  name: 'umdp',
  filebase: 'umdp',
  description: 'Linux Usermode Driver Platform',
  subdirs: 'umdp',
  libraries: umdp_lib,
  version: '0.1',
)
