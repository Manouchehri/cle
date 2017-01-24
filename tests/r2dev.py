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

path_group = project.factory.path_group()

FIND_ADDR = 0x08048533 # mov dword [esp], str.Congrats_ ; [0x8048654:4]=0x676e6f43 LEA str.Congrats_ ; "Congrats!" @ 0x8048654
AVOID_ADDR = 0x08048554 # mov dword [esp], str.Wrong_ ; [0x804865e:4]=0x6e6f7257 LEA str.Wrong_ ; "Wrong!" @ 0x804865e


path_group.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

print path_group.found[0].state.posix.dumps(0).split('\0')[0]
