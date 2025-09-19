project('libcollider', 'c',
  version: '1.0.1',
  default_options: ['buildtype=release', 'default_library=shared']
)

src = ['src/libcollider.c']
inc = include_directories('src')

openssl_dep = dependency('openssl', required: true)

libcollider = library('collider',
  sources: src,
  include_directories: inc,
  dependencies: [openssl_dep],
  install: true
)

install_headers('src/collider.h', subdir: '.')
