import cle
import logging
import angr

logging.basicConfig(level=logging.DEBUG)

classic = cle.Loader("test.elf", main_opts={'backend': 'elf'})

r2 = cle.Loader("test.elf", main_opts={'backend': 'r2', 'custom_arch': 'i386'})

# proj = angr.Project('crackme0x00a', load_options={"auto_load_libs": False},)

project = angr.Project("test.elf", load_options={
    'main_opts': {
        'backend': 'r2',
        #'custom_arch': 'i386',
    },
    "auto_load_libs": False,
})

print project

print classic
print r2

