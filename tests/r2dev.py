import cle
import logging

logging.basicConfig(level=logging.DEBUG)

classic = cle.Loader("test.elf", main_opts={'backend': 'elf', 'custom_arch': 'i386'})

r2 = cle.Loader("test.elf", main_opts={'backend': 'r2', 'custom_arch': 'i386'})

print classic
print r2




