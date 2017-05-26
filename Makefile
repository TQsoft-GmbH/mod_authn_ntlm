#APACHEDIR=C:\Apache_24_Module\httpd-2.4.10
#MSVCDIR=C:\Program Files (x86)\\Microsoft Visual Studio 11.0\VC
#PLATSDKDIR=C:\Program Files (x86)\Microsoft SDKs\Windows\v8.0A
#EXTRAARCH=.

#APACHEDIR=C:\Users\tomonori\Desktop\ntlm\src\httpd-2.4.4
#MSVCDIR=C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC
#PLATSDKDIR=C:\Program Files (x86)\Microsoft SDKs\Windows\v8.1A
#EXTRAARCH=.

APACHEDIR=E:\ntlm\src\httpd-2.4.4
MSVCDIR=C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC
PLATSDKDIR=C:\Program Files (x86)\Microsoft SDKs\Windows\v8.1A
EXTRAARCH=.


#Example for Apache Lounge VC10 Win32
#APACHEDIR=C:\Apache24
#MSVCDIR=C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC
#PLATSDKDIR=C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A
#EXTRAARCH=.

#Example for Apache Lounge VC11 Win64
#APACHEDIR=C:\Apache24
#MSVCDIR=C:\Program Files (x86)\Microsoft Visual Studio 11.0\VC
#PLATSDKDIR=C:\NOTHING123
#EXTRAARCH=amd64

LIBAPR=libapr-1.lib
LIBAPRUTIL=libaprutil-1.lib

AP_INCLUDES=\
	/I "$(APACHEDIR)\include" /I "$(APACHEDIR)\srclib\apr\include"\
	/I "$(APACHEDIR)\srclib\apr-util\include" /I "$(APACHEDIR)\os\win32"
	
AP_LIBPATH=\
	/LIBPATH:"$(APACHEDIR)\Release"\
	/LIBPATH:"$(APACHEDIR)\srclib\apr\Release"\
	/LIBPATH:"$(APACHEDIR)\srclib\apr-util\Release"\
	/LIBPATH:"$(APACHEDIR)\lib"

SRCDIR=src
BINDIR=bin

!ifndef DEBUG
DEBUG=0
!endif

CC=cl
CFLAGS=/nologo /W3 /WX
RCFLAGS=/nologo
LD=link
LDFLAGS=/nologo
DEFINES=/D WIN32

INCLUDES=$(AP_INCLUDES) /I "$(PLATSDKDIR)\include" /I "$(MSVCDIR)\include"
LIBPATH=$(AP_LIBPATH) /LIBPATH:"$(PLATSDKDIR)\lib" /LIBPATH:"$(MSVCDIR)\lib\$(EXTRAARCH)"
LIBRARIES=libhttpd.lib $(LIBAPR) $(LIBAPRUTIL) kernel32.lib advapi32.lib ole32.lib

!if ($(DEBUG) != 0)
OBJDIR=Debug
CFLAGS=$(CFLAGS) /LDd /MTd /Od /Z7
LDFLAGS=$(LDFLAGS) /debug
!else
OBJDIR=Release
CFLAGS=$(CFLAGS) /LD /MT /Ot /Ox /Oi /Oy /Ob2 /GF /Gy
LDFLAGS=$(LDFLAGS) /release /opt:ref /opt:icf,16
!endif

DLL_BASE_ADDRESS=0x6ED00000

OBJECTS=$(OBJDIR)\mod_ntlm.obj $(OBJDIR)\mod_ntlm_authentication.obj\
	$(OBJDIR)\mod_ntlm_authorization.obj $(OBJDIR)\mod_ntlm_interface.obj

OUTFILE=$(BINDIR)\mod_authn_ntlm.so
MAPFILE=$(BINDIR)\mod_authn_ntlm.map


dist: clean all
	-@del $(BINDIR)\*.exp $(BINDIR)\*.lib 2>NUL
	-@rd /s /q $(OBJDIR) 2>NUL

all: $(OUTFILE)

$(OUTFILE): dirs $(OBJECTS)
	$(LD) $(LDFLAGS) /noassembly /DLL /BASE:$(DLL_BASE_ADDRESS) $(LIBPATH) $(OBJECTS) $(LIBRARIES) /OUT:$@ /MAP:$(MAPFILE)

/OUT:$@

{$(SRCDIR)}.c{$(OBJDIR)}.obj:
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) /c %CD%\$< /Fo$@

{$(SRCDIR)}.rc{$(OBJDIR)}.res:
	$(RC) $(RCFLAGS) $(INCLUDES) $(DEFINES) /fo $@ %CD%\$<
	
dirs:
	@if not exist $(OBJDIR) mkdir $(OBJDIR)
	@if not exist $(BINDIR) mkdir $(BINDIR)

clean:
	-@rd /s /q $(OBJDIR) 2>NUL
	-@rd /s /q $(BINDIR) 2>NUL

