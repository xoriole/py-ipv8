# -*- mode: python -*-

block_cipher = None

import imp
import os
import sys
import shutil

sys.path.insert(0, os.getcwdu())

version_str = '1.0.0'

# On macOS, we always show the console to prevent the double-dock bug (although the OS does not actually show the console).
# See https://github.com/Tribler/tribler/issues/3817
show_console = False
if sys.platform == 'darwin':
    show_console = True

data_to_copy = [('ipv8', '.')]
excluded_libs = []

a = Analysis(['generate_key.py'],
             pathex=[],
             binaries=None,
             datas=data_to_copy,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=excluded_libs,
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

# Add libsodium.dylib on OS X
if sys.platform == 'darwin':
    a.binaries = a.binaries - TOC([('/usr/local/lib/libsodium.so', None, None),])
    a.binaries = a.binaries + TOC([('libsodium.dylib', '/usr/local/lib/libsodium.dylib', None),])

exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='ipv8',
          debug=False,
          strip=False,
          upx=True,
          console=show_console,
          icon='build/win/tribler.ico')
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='ipv8')
app = BUNDLE(coll,
             name='ipv8.app',
             icon='build/mac/tribler.icns',
             bundle_identifier='nl.tudelft.ipv8',
             info_plist={'NSHighResolutionCapable': 'True', 'CFBundleInfoDictionaryVersion': 1.0, 'CFBundleVersion': version_str, 'CFBundleShortVersionString': version_str},
             console=show_console)

# Replace the Info.plist file on MacOS
if sys.platform == 'darwin':
    shutil.copy('build/mac/Info.plist', 'dist/ipv8.app/Contents/Info.plist')
