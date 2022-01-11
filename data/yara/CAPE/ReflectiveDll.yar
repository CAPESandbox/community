rule ReflectiveDLLInjection
{
     meta:
        author = "Busra Yenidogan"
        description = "Reflective DLL injection"
        //"https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.h"

    strings:
        $KERNEL32DLL_HASH = {5B BC 4A 6A}
        $NTDLLDLL_HASH = {5D 68 FA 3C}
        $LOADLIBRARYA_HASH = {8E 4E 0E EC}
        $GETPROCADDRESS_HASH = {AA FC 0D 7C}
        $VIRTUALALLOC_HASH = {54 CA AF 91}
        $NTFLUSHINSTRUCTIONCACHE_HASH = {B8 0A 4C 53}

    condition:
        all of them 
}