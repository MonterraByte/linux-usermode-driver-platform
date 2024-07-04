project('umdp', 'c',
  version : '0.1',
  default_options : ['c_std=c11', 'buildtype=debugoptimized', 'b_lto=true', 'default_library=both', 'warning_level=3'])

nl_dep = dependency('libnl-3.0', version: '>=3.5.0')
genl_dep = dependency('libnl-genl-3.0', version: '>=3.5.0')

# These arguments are only used to build the library
# not the executables that use the library.
lib_args = ['-DBUILDING_UMDP']
if get_option('disable_error_printing')
  lib_args += '-DUMDP_DISABLE_ERROR_PRINTING'
endif

incdir = include_directories('include')
umdp_lib = library('umdp', 'src/umdp.c', 'src/connection.c', 'src/handlers.c', 'src/protocol-family.c',
  c_args: lib_args,
  include_directories: incdir,
  dependencies: [nl_dep, genl_dep],
  gnu_symbol_visibility: 'hidden',
  install: true,
)

# Make this library usable as a Meson subproject.
umdp_dep = declare_dependency(
  include_directories: incdir,
  link_with: umdp_lib,
)

# Make this library usable from the system's
# package manager.
install_headers('include/umdp.h')

pkg_mod = import('pkgconfig')
pkg_mod.generate(
  name: 'umdp',
  filebase: 'umdp',
  description: 'Linux Usermode Driver Platform',
  subdirs: 'umdp',
  libraries: umdp_lib,
  version: '0.1',
)

# Examples
if get_option('examples')
  devio_exe = executable('devio', 'examples/devio.c',
    dependencies: umdp_dep)
  interrupts_exe = executable('interrupts', 'examples/interrupts.c',
    dependencies: umdp_dep)
  keep_open_exe = executable('keep-open', 'examples/keep-open.c',
    dependencies: umdp_dep)
  keyboard_exe = executable('keyboard', 'examples/keyboard.c',
    dependencies: umdp_dep)
  timer_exe = executable('timer', 'examples/timer.c',
    dependencies: umdp_dep)
endif
