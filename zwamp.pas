{*
	Z-WAMP Server Pack
	Copyright © 2009-2012 F3::Factory/Bong Cosca
	All rights reserved
	Licensed under the terms of the GNU Public License v3
*}

{$AppType GUI}
{$Mode DELPHI}
{$Resource zwamp.res}
{$Resource manifest.res}

program ZWAMP;
uses
	ComObj,FileInfo,RegExpr,Registry,SysUtils,Variants,Windows;
type
	Service=Record
		exe,path,args:String;
	end;
	VersionInfo=Record
		owner,version,name,license:String;
	end;
 const
	// Globals
	GUID:String='{39d8c3af-1f05-4587-a217-5b6acbae4b9a}';
	CRLF:String=#13#10;
	// Services
	SVC_Apache:Service=(
		exe:'httpd.exe';
		path:'\.sys\apache2\bin';
		args:'';
	);
	SVC_MemCache:Service=(
		exe:'memcached.exe';
		path:'\.sys\memcache';
		args:'';
	);
	SVC_MongoDB:Service=(
		exe:'mongod.exe';
		path:'\.sys\mongodb';
		args:'--journal --dbpath \.sys\mongodb\data';
	);
	SVC_MySQL:Service=(
		exe:'mysqld.exe';
		path:'\.sys\mysql\bin';
		args:'--defaults-file=\.sys\mysql\my.ini --console'+'';
	);
	SVC_PHP:Service=(
		exe:'php.exe';
		path:'\.sys\php';
		args:'';
	);
	// Config files
	CFG_Apache:String='\.sys\apache2\conf\httpd.conf';
	CFG_vHosts:String='\.sys\apache2\conf\vhosts.conf';
	CFG_MySQL:String='\.sys\mysql\my.ini';
	CFG_PHP:String='\.sys\php\php.ini';
	CFG_Windows:String='\system32\drivers\etc\hosts';
	// Log files
	LOG_Access:String='\.sys\apache2\logs\access.log';
	LOG_Error:String='\.sys\apache2\logs\error.log';
	// URLs
	WEB_Adminer:String='http://localhost/adminer';
	WEB_APC:String='http://localhost/apc';
	WEB_MemCache:String='http://localhost/memcache';
	WEB_MongoDB:String='http://localhost/mongodb';
	WEB_PHPinfo:String='http://localhost/phpinfo';
	WEB_DONATE:String='https://www.paypal.com/cgi-bin/webscr?'+
		'cmd=_s-xclick&hosted_button_id=6HZ8WY96FZLKN';
	WEB_Home:String='http://zwamp.sourceforge.net';
	WEB_Download:String='http://sourceforge.net/projects/zwamp/files';
	WEB_VC10:String='http://support.microsoft.com/kb/2019667';
	// Documentation
	DOC_Path:String='\.sys\docs';
	DOC_Apache:String='apache24.chm';
	DOC_HTML5:String='html5.pdf';
	DOC_Javascript:String='javascript.pdf';
	DOC_MongoDB:String='mongodb.pdf';
	DOC_MySQL:String='mysql-5.5.pdf';
	DOC_PHP:String='php.chm';
	// Registry keys
	REG_Path:String='System\CurrentControlSet\Control\'+
		'Session Manager\Environment';
	REG_App:String='Software\ZWAMP';
	REG_UAC:String='Software\Microsoft\Windows\CurrentVersion\'+
		'Policies\System';
	REG_Auto:String='Software\Microsoft\Windows\CurrentVersion\Run';
	// Product codes for Visual C++ redistributable package
	MSVC:Array[1..6] of String=(
		// VC9
		'{350AA351-21FA-3270-8B7A-835434E766AD}',
		'{FF66E9F6-83E7-3A3E-AF14-8DE9A809A6A4}',
		// VC10
		'{196BB40D-1578-3D01-B289-BEFC77A11A1E}',
		'{DA5E371C-6333-3D8A-93A4-6FD5B20BCC6E}',
		'{F0C3E5D1-1ADE-321E-8167-68EF0DE699A5}',
		'{1D8E6291-B0D5-35EC-8441-6616F567A0F7}'
	);
	// Garbage collection cycle
	TIMEOUT:UINT=5000;
	// Externals
	NIF_MESSAGE:UINT=$0001;
	NIF_ICON:UINT=$0002;
	NIF_TIP:UINT=$0004;
	NIM_ADD:UINT=$0000;
	NIM_DELETE:UINT=$0002;
	INSTALLSTATE_DEFAULT=$0005;
var
	aMsg:MSG;
	app:VersionInfo;
	icon:NOTIFYICONDATA;
	iter:String;
	len:UINT;
	mDir,vDisk:String;
	mReg:TRegistry;
	mutex:HANDLE;
	mWindow:HWND;
	restart:UINT;
	wClass:WNDCLASS;

function EnumProcesses(pIDs:LPDWORD;cb:DWORD;var bytes:DWORD):BOOL;
	stdcall; external 'psapi.dll';

function GetProcessImageFileNameA(hProc:HANDLE;fName:LPSTR;nSize:DWORD):DWORD;
	stdcall; external 'psapi.dll';

function EmptyWorkingSet(hProcess:HANDLE):BOOL;
	stdcall; external 'psapi.dll';

function CheckTokenMembership(tHandle:HANDLE;sid:PSID;var isMember:BOOL):BOOL;
	stdcall; external 'advapi32.dll';

function MsiQueryProductStateA(product:LPSTR):LONG;
	stdcall; external 'msi.dll';

// Global exception handler
procedure ExHandler(obj:TObject);
begin
end;

// Remove virtual drive
procedure RemoveDrive;
begin
	if DirectoryExists(vDisk+'\') then
		DefineDosDevice(6,LPSTR(vDisk),LPSTR(mDir+'\vdrive'));
end;

// Create virtual drive
procedure CreateDrive;
const
	DRIVES:String='ZYXWVUTSRQPONMLKJIHGFEDCBA';
var
	i:UINT;
begin
	SetCurrentDir(mDir);
	// Remove any previously-defined virtual drive
	if not mReg.KeyExists(REG_App) then
		mReg.CreateKey(REG_App);
	mReg.OpenKey(REG_App,TRUE);
	if mReg.ValueExists('vDrive') then
	begin
		vDisk:=mReg.ReadString('vDrive');
		RemoveDrive;
	end;
	// Find first available drive and activate
	for i:=1 to SizeOf(DRIVES) do
	begin
		vDisk:=DRIVES[i]+':';
		if not DirectoryExists(vDisk+'\') then
		begin
			DefineDosDevice(0,LPSTR(vDisk),LPSTR(mDir+'\vdrive'));
			mReg.WriteString('vDrive',vDisk);
			break;
		end;
	end;
	mReg.CloseKey;
end;

// Return ID if process exists
function ProcessID(name:String):UINT;
var
	fName:Array[0..255] of Char;
	hProc:HANDLE;
	i:UINT;
	iSize:UINT=0;
	procIDs:Array[1..1024] of DWORD;
	regex:TRegExpr;
begin
	regex:=TRegExpr.Create;
	regex.Expression:='\b'+QuoteRegExprMetaChars(name)+'\b';
	EnumProcesses(@procIDs,SizeOf(procIDs),iSize);
	for i:=1 to (iSize div SizeOf(DWORD)) do
	begin
		hProc:=OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
			FALSE,procIDs[i]);
		if hProc>0 then
		begin
			fName:='';
			GetProcessImageFileNameA(hProc,fName,SizeOf(fName));
			CloseHandle(hProc);
			if regex.Exec(fName) then
			begin
				regex.Destroy;
				exit(procIDs[i]);
			end;
		end;
	end;
	regex.Destroy;
	exit(0);
end;

// Start specified service
procedure RunSvc(svc:Service);
begin
	ShellExecute(0,'open',
		LPSTR(svc.path+'\'+svc.exe),LPSTR(svc.args),LPSTR(svc.path),SW_HIDE);
end;

// Edit config file
procedure Notepad(path:String);
begin
	ShellExecute(0,'open','notepad.exe',LPSTR(path),'',SW_SHOW);
end;

// Open file using default handler
procedure Handler(path:String);
begin
	ShellExecute(0,'open',LPSTR(path),'','',SW_SHOW);
end;

// Close window
function EndProc(hWindow:HWND;lParam:LPARAM):BOOL;
	stdCall;
var
	procID:UINT;
begin
	GetWindowThreadProcessId(hWindow,@procID);
	if procID=LOWORD(lParam) then
		PostMessage(hWindow,WM_CLOSE,0,0);
	exit(TRUE);
end;

// Terminate specified service
procedure EndSvc(svc:Service);
var
	hProc:HANDLE;
	pID:UINT;
begin
	SetSystemCursor(LoadCursor(0,IDC_ARROW),OCR_APPSTARTING);
	while TRUE do
	begin
		pID:=ProcessID(svc.exe);
		if pID>0 then
		begin
			hProc:=OpenProcess(SYNCHRONIZE or PROCESS_TERMINATE,FALSE,pID);
			if hProc>0 then
			begin
				EnumWindows(@EndProc,LPARAM(pID));
				if WaitForSingleObject(hProc,TIMEOUT)<>WAIT_OBJECT_0 then
					TerminateProcess(hProc,0);
				CloseHandle(hProc);
			end;
		end
		else
			break;
	end;
	SetSystemCursor(LoadCursor(0,IDC_APPSTARTING),OCR_NORMAL);
end;

// Return TRUE if specified service is running
function Running(svc:Service):BOOL;
begin
	exit(ProcessID(svc.exe)>0);
end;

// Modify PATH environment variable
procedure ModPath(svc:Service);
var
	dummy:UINT=0;
	pReg:TRegistry;
	regex:TRegExpr;
begin
	pReg:=TRegistry.Create;
	pReg.RootKey:=HKEY_LOCAL_MACHINE;
	pReg.OpenKey(REG_Path,FALSE);
	regex:=TRegExpr.Create;
	regex.Expression:='^(.+;)?.*?'+QuoteRegExprMetaChars(svc.path)+';?(.+)?$';
	pReg.WriteExpandString('Path',vDisk+svc.path+';'+
		regex.Replace(pReg.ReadString('Path'),'$1$2',TRUE));
	regex.Destroy;
	pReg.CloseKey;
	pReg.Destroy;
	SendMessageTimeout(HWND_BROADCAST,WM_SETTINGCHANGE,0,
		LPARAM(LPSTR('Environment')),SMTO_ABORTIFHUNG,TIMEOUT,dummy);
end;

// Toggle specified service
procedure Toggle(svc:Service);
var
	state:BOOL;
begin
	if Running(svc) then
		EndSvc(svc)
	else
		RunSvc(svc);
	if not mReg.KeyExists(REG_App) then
		mReg.CreateKey(REG_App);
	mReg.OpenKey(REG_App,TRUE);
	state:=Running(svc);
	mReg.WriteBool(svc.exe,state);
	if state then
		ModPath(svc);
	mReg.CloseKey;
end;

// Toggle auto-start
procedure AutoExec;
begin
	mReg.OpenKey(REG_Auto,TRUE);
	if not mReg.ValueExists('ZWAMP') then
		mReg.WriteString('ZWAMP',ParamStr(0))
	else
		mReg.DeleteValue('ZWAMP');
	mReg.CloseKey;
end;

// Show copyright notice
procedure About;
begin
	MessageBox(0,
		LPSTR(app.name+' is a lightweight zero-install'+CRLF+
			'Web server package for Windows.'+CRLF+CRLF+
			'Version '+app.version+' ('+{$I %FPCTARGETCPU%}+' build)'+CRLF+
			'Copyright (c) 2009-2012 '+app.owner+CRLF+
			'All rights reserved.'+CRLF+CRLF+
			'This software is licensed under the terms of the '+
				app.license+'.'),
		'About Z-WAMP',MB_OK or MB_ICONINFORMATION or MB_SYSTEMMODAL);
end;

// Return checked/unchecked flag for context menu item
function Checked(cond:BOOL):UINT;
begin
	if cond then
		exit(MF_CHECKED);
	exit(MF_UNCHECKED);
end;

// Return enabled/grayed flag for context menu item
function Enabled(cond:BOOL):UINT;
begin
	if cond then
		exit(MF_ENABLED);
	exit(MF_GRAYED);
end;

// Return context menu flag for Z-WAMP
function FlagApp:UINT;
var
	state:BOOL;
begin
	mReg.OpenKeyReadOnly(REG_Auto);
	state:=mReg.ValueExists('ZWAMP');
	mReg.CloseKey;
	exit(Checked(state));
end;

// Control services
procedure Server(op:String);
begin
	// Terminate running processes
	EndSvc(SVC_Apache);
	EndSvc(SVC_MemCache);
	EndSvc(SVC_MongoDB);
	EndSvc(SVC_MySQL);
	if op='start' then
	begin
		SetCurrentDir(vDisk+'\');
		if not mReg.KeyExists(REG_App) then
			mReg.CreateKey(REG_App);
		mReg.OpenKey(REG_App,TRUE);
		// Apache
		if not mReg.ValueExists(SVC_Apache.exe) then
			mReg.WriteBool(SVC_Apache.exe,TRUE);
		if mReg.ReadBool(SVC_Apache.exe) and not Running(SVC_Apache) then
			RunSvc(SVC_Apache);
		// MemCache
		if not mReg.ValueExists(SVC_MemCache.exe) then
			mReg.WriteBool(SVC_MemCache.exe,TRUE);
		if mReg.ReadBool(SVC_MemCache.exe) and not Running(SVC_MemCache) then
			RunSvc(SVC_MemCache);
		// MongoDB
		if not mReg.ValueExists(SVC_MongoDB.exe) then
			mReg.WriteBool(SVC_MongoDB.exe,TRUE);
		if mReg.ReadBool(SVC_MongoDB.exe) and not Running(SVC_MongoDB) then
			RunSvc(SVC_MongoDB);
		// MySQL
		if not mReg.ValueExists(SVC_MySQL.exe) then
			mReg.WriteBool(SVC_MySQL.exe,TRUE);
		if mReg.ReadBool(SVC_MySQL.exe) and not Running(SVC_MySQL) then
			RunSvc(SVC_MySQL);
		mReg.CloseKey;
	end;
end;

// Return TRUE if specified service is enabled in registry
function Registered(svc:Service):BOOL;
var
	state:BOOL;
begin
	mReg.OpenKeyReadOnly(REG_App);
	state:=mReg.ReadBool(svc.exe);
	mReg.CloseKey;
	exit(state);
end;

// Display context menu
procedure ShowMenu(hWindow:HWND);
var
	opApache,opMemCache,opMongoDB,opMySQL:BOOL;
	mMenu,cMenu:HMENU;
	pos:POINT=(X:0;Y:0);
begin
	mMenu:=LoadMenu(system.MainInstance,MakeIntResource(3));
	cMenu:=GetSubMenu(mMenu,0);
	opApache:=Running(SVC_Apache);
	opMemCache:=Running(SVC_MemCache);
	opMongoDB:=Running(SVC_MongoDB);
	opMySQL:=Running(SVC_MySQL);
	// Restart
	EnableMenuItem(cMenu,11,MF_BYCOMMAND or
		Enabled(Registered(SVC_Apache) or Registered(SVC_MemCache) or
			Registered(SVC_MongoDB) or Registered(SVC_MySQL)));
	// Stop
	EnableMenuItem(cMenu,12,MF_BYCOMMAND or
		Enabled(opApache or opMemCache or opMongoDB or opMySQL));
	// Services
	CheckMenuItem(cMenu,21,MF_BYCOMMAND or Checked(opApache));
	CheckMenuItem(cMenu,22,MF_BYCOMMAND or Checked(opMemCache));
	CheckMenuItem(cMenu,23,MF_BYCOMMAND or Checked(opMongoDB));
	CheckMenuItem(cMenu,24,MF_BYCOMMAND or Checked(opMySQL));
	// Documentation
	EnableMenuItem(cMenu,61,MF_BYCOMMAND or
		Enabled(FileExists(DOC_Path+'\'+DOC_Apache)));
	EnableMenuItem(cMenu,62,MF_BYCOMMAND or
		Enabled(FileExists(DOC_Path+'\'+DOC_HTML5)));
	EnableMenuItem(cMenu,63,MF_BYCOMMAND or
		Enabled(FileExists(DOC_Path+'\'+DOC_Javascript)));
	EnableMenuItem(cMenu,64,MF_BYCOMMAND or
		Enabled(FileExists(DOC_Path+'\'+DOC_MongoDB)));
	EnableMenuItem(cMenu,65,MF_BYCOMMAND or
		Enabled(FileExists(DOC_Path+'\'+DOC_MySQL)));
	EnableMenuItem(cMenu,66,MF_BYCOMMAND or
		Enabled(FileExists(DOC_Path+'\'+DOC_PHP)));
	// Run on Windows startup?
	CheckMenuItem(cMenu,70,MF_BYCOMMAND or FlagApp);
	// Show context menu
	SetForegroundWindow(hWindow);
	GetCursorPos(pos);
	TrackPopupMenu(cMenu,
		TPM_LEFTALIGN or TPM_LEFTBUTTON,pos.x,pos.y,0,hWindow,NIL);
	DestroyMenu(cMenu);
	DestroyMenu(mMenu);
end;

// Display message box if new version is available
procedure CheckVersion(notify:BOOL=FALSE);
var
	http:Variant;
	response:String;
begin
	try
		http:=CreateOLEObject('WinHTTP.WinHTTPRequest.5.1');
		http.Open('GET','http://zwamp.sourceforge.net/release',FALSE);
		http.SetRequestHeader('User-Agent','Mozilla/5.0 (compatible)');
		http.Send;
		response:=http.responseText;
		if http.status<>'200' then
			MessageBox(0,LPSTR('Connection failed -'+CRLF+
				'Unable to determine latest version.'),LPSTR(app.name),
				MB_OK or MB_ICONERROR or MB_SYSTEMMODAL)
		else if response>app.version then
		begin
			if MessageBox(0,LPSTR(app.name+' ('+
				response+') is now available.'+CRLF+
				'Visit SourceForge to download this new version?'),
				LPSTR(app.name),
				MB_YESNO or MB_ICONQUESTION or MB_SYSTEMMODAL)=IDYES then
				Handler(WEB_Download);
		end
		else if notify then
			MessageBox(0,LPSTR('Your '+app.name+' '+
				'('+app.version+') is up-to-date.'),LPSTR(app.name),
				MB_OK or MB_ICONINFORMATION or MB_SYSTEMMODAL);
		http:=Unassigned;
	except
		if notify then
			MessageBox(0,LPSTR('Connection to SourceForge timed out -'+CRLF+
				'Unable to determine latest version.'),LPSTR(app.name),
				MB_OK or MB_ICONERROR or MB_SYSTEMMODAL);
	end;
end;

// Windows callback
function WinProc(hWindow:HWND;aMsg:UINT;wParam:WPARAM;lParam:LPARAM):LRESULT;
	stdCall;
var
	iSize:UINT;
begin
	case aMsg of
		WM_USER:
			case lParam of
				WM_RBUTTONUP:
					// Display context menu
					ShowMenu(hWindow);
				WM_LBUTTONDBLCLK:
					// Z-WAMP home page
					Handler(WEB_Home);
			end;
		WM_COMMAND:
			// Process menu choice
			case LOWORD(wParam) of
				11: Server('start');
				12: Server('stop');
				21: Toggle(SVC_Apache);
				22: Toggle(SVC_MemCache);
				23: Toggle(SVC_MongoDB);
				24: Toggle(SVC_MySQL);
				31: Notepad(CFG_Apache);
				32: Notepad(CFG_vHosts);
				33: Notepad(CFG_MySQL);
				34: Notepad(CFG_PHP);
				35: Notepad({$I %SystemRoot%}+CFG_Windows);
				41: Notepad(LOG_Access);
				42: Notepad(LOG_Error);
				51: Handler(WEB_Adminer);
				52: Handler(WEB_APC);
				53: Handler(WEB_MemCache);
				54: Handler(WEB_MongoDB);
				55: Handler(WEB_PHPinfo);
				61: Handler(DOC_Path+'\'+DOC_Apache);
				62: Handler(DOC_Path+'\'+DOC_HTML5);
				63: Handler(DOC_Path+'\'+DOC_Javascript);
				64: Handler(DOC_Path+'\'+DOC_MongoDB);
				65: Handler(DOC_Path+'\'+DOC_MySQL);
				66: Handler(DOC_Path+'\'+DOC_PHP);
				70: AutoExec;
				81: CheckVersion(TRUE);
				82: Handler(WEB_DONATE);
				83: About;
				90: DestroyWindow(hWindow);
			end;
		WM_CREATE:
			begin
				SetSystemCursor(LoadCursor(0,IDC_ARROW),OCR_APPSTARTING);
				restart:=RegisterWindowMessage('TaskbarCreated');
				// Link to registry
				mReg:=TRegistry.Create;
				mReg.RootKey:=HKEY_LOCAL_MACHINE;
				// Create virtual drive
				CreateDrive;
				// Activate services
				Server('start');
				// Add PHP binary to PATH
				ModPath(SVC_PHP);
				// Add icon
				iSize:=SizeOf(NOTIFYICONDATA);
				ZeroMemory(@icon,iSize);
				icon.cbSize:=iSize;
				icon.hIcon:=LoadIcon(System.MainInstance,MakeIntResource(2));
				icon.szTip:=LPSTR(app.name+' '+app.version+' ('+
					{$I %FPCTARGETCPU%}+' build)');
				icon.uCallbackMessage:=WM_USER;
				icon.uFlags:=NIF_ICON or NIF_MESSAGE or NIF_TIP;
				icon.Wnd:=hWindow;
				Shell_NotifyIcon(NIM_ADD,@icon);
				// Check SF for new version
				CheckVersion;
				SetSystemCursor(LoadCursor(0,IDC_APPSTARTING),OCR_NORMAL);
			end;
		WM_DESTROY:
			begin
				// Deactivate services
				Server('stop');
				// Remove virtual drive
				RemoveDrive;
				// Unlink from registry
				mReg.Destroy;
				// Remove icon
				Shell_NotifyIcon(NIM_DELETE,@icon);
				// Terminate app
				PostQuitMessage(0);
			end;
	else if aMsg=restart then
		// Repaint icon
		Shell_NotifyIcon(NIM_ADD,@icon);
	end;
	exit(DefWindowProc(hWindow,aMsg,wParam,lParam));
end;

// Garbage collection
procedure ReduceRAM;
	stdCall;
begin
	EmptyWorkingSet(GetCurrentProcess);
end;

// Return TRUE if current user has administrator privilege
function IsAdmin:BOOL;
const
	SECURITY_NT_AUTHORITY:TSIDIdentifierAuthority=(Value:(0,0,0,0,0,5));
	SECURITY_BUILTIN_DOMAIN_RID=$00000020;
	DOMAIN_ALIAS_RID_ADMINS=$00000220;
var
	sid:PSID=NIL;
	state:BOOL;
begin
	if Win32Platform<>VER_PLATFORM_WIN32_NT then
		exit(TRUE);
	state:=AllocateAndInitializeSid(SECURITY_NT_AUTHORITY,2,
		SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,sid);
	if state then
	begin
		state:=CheckTokenMembership(0,sid,state);
		FreeSid(sid);
	end;
	exit(state);
end;

procedure GetInfo;
var
	version:TFileVersionInfo;
begin
	version:=TFileVersionInfo.Create(NIL);
	version.FileName:=ParamStr(0);
	app.name:=version.GetVersionSetting('ProductName');
	app.version:=version.GetVersionSetting('ProductVersion');
	app.owner:=version.GetVersionSetting('CompanyName');
	app.license:=version.GetVersionSetting('LegalCopyright');
	version.Destroy;
end;

// Restart computer
procedure Reboot;
var
	token:HANDLE;
	uniqID:TTokenPrivileges;
begin
	// Set privilege
	OpenProcessToken(GetCurrentProcess,
		TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,@token);
	LookupPrivilegeValue(NIL,SE_SHUTDOWN_NAME,@uniqID.Privileges[0].Luid);
	uniqID.Privileges[0].Attributes:=SE_PRIVILEGE_ENABLED;
	uniqID.PrivilegeCount:=1;
	AdjustTokenPrivileges(token,FALSE,@uniqID,0,
		PTOKEN_PRIVILEGES(NIL),NIL);
	CloseHandle(token);
	// Restart
	ExitWindowsEx(EWX_REBOOT,0);
end;

function VCInstalled:BOOL;
var
	found:BOOL;
begin
	found:=FALSE;
	for iter in MSVC do
		if (MsiQueryProductStateA(LPSTR(iter))=INSTALLSTATE_DEFAULT) then
		begin
			found:=TRUE;
			break;
		end;
	exit(found);
end;

// Main routine
begin
	ExceptProc:=@ExHandler;
	// Limit application to a single instance
	mutex:=CreateMutex(NIL,FALSE,LPSTR(GUID));
	if GetLastError<>ERROR_ALREADY_EXISTS then
	begin
		// Get file version info
		GetInfo;
		// Get current directory
		mDir:=ExtractFileDir(ParamStr(0));
		if IsAdmin then
		begin
			if (Win32MajorVersion>5) then
				if VCInstalled then
				begin
					mReg:=TRegistry.Create;
					mReg.RootKey:=HKEY_LOCAL_MACHINE;
					mReg.OpenKey(REG_UAC,FALSE);
					if (mReg.ValueExists('EnableLUA')) and
						(mReg.ReadInteger('EnableLUA')>0) then
					begin
						if MessageBox(0,LPSTR(app.name+' requires full '+
							'administrative privilege'+CRLF+
							'to run properly.'+CRLF+CRLF+
							'Modify Windows settings and restart '+
							'the computer?'),LPSTR(app.name),
							MB_OKCANCEL or MB_ICONEXCLAMATION or
							MB_SYSTEMMODAL)=IDOK then
						begin
							mReg.WriteInteger('ConsentPromptBehaviorAdmin',0);
							mReg.WriteInteger('EnableLUA',0);
							Reboot;
						end;
						Halt;
					end;
					mReg.CloseKey;
					mReg.Destroy;
					SetTimer(0,0,TIMEOUT,@ReduceRAM);
					// Define hidden window
					wClass.cbClsExtra:=0;
					wClass.cbWndExtra:=0;
					wClass.hInstance:=0;
					wClass.hIcon:=LoadIcon(0,IDI_APPLICATION);
					wClass.lpfnWndProc:=@WinProc;
					wClass.lpszMenuName:=NIL;
					wClass.lpszClassName:=LPSTR(app.name);
					wClass.style:=0;
					if (RegisterClass(wClass)>0) and
						(CreateWindow(LPSTR(app.name),'',
							0,0,0,0,0,0,0,0,NIL)>0) then
						// Process window messages
						while GetMessage(@aMsg,0,0,0) do
						begin
							TranslateMessage(@aMsg);
							DispatchMessage(@aMsg);
						end;
				end
				else
				begin
					MessageBox(0,
						LPSTR('The Visual C++ 2008 and 2010 '+
						'redistributable '+CRLF+
						'packages are not installed on your computer.'),
						LPSTR(app.name),
						MB_OK or MB_ICONINFORMATION or MB_SYSTEMMODAL);
					Handler(WEB_VC10);
				end
			else
				// Pre-Windows Vista/Server 2008
				MessageBox(0,
					LPSTR('Apache 2.4.1 does not support this Windows '+
					'version.'+CRLF+
					'Please upgrade to a new operating system or use'+CRLF+
					'an earlier '+app.name+' release.'),
					LPSTR(app.name),MB_OK or MB_ICONEXCLAMATION or
					MB_SYSTEMMODAL);
		end
		else
			ShellExecute(0,'runas',LPSTR(ParamStr(0)),'',LPSTR(mDir),SW_SHOW);
		ReleaseMutex(mutex);
	end
end.
