PC=fpc
RC=gorc

ifndef target
	rctarget=AMD64
	pctarget=x86_64
else
	rctarget=X86
	pctarget=i386
endif

source=zwamp.pas
exe=zwamp.exe
rcapp=zwamp.rc
rcman=manifest.rc
pfx=zwamp.pfx

delete=rm -f
compress=mpress -q
codesign=signtool sign /t http://time.certum.pl /f $(PFX) $(exe)

all: $(source)
	$(RC) /ni /machine $(rctarget) /r $(rcapp)
	$(RC) /ni /machine $(rctarget) /r $(rcman)
	$(PC) -P$(pctarget) -o$(exe) $(source)
	$(compress) -r $(exe)

clean:
	$(delete) $(exe) *.res *.a *.o??
