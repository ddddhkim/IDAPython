#-*-coding: utf-8


from idc       import *
from idaapi    import *
from idautils  import *
from struct    import *
from ioTracing import *


# Python 으로 활성화
RunPlugin("python", 3)  # https://github.com/tmr232/idapython

fd = []


# unpack 32 bit
u32 = lambda x : unpack("<I", x)[0]


# 레지스터 값을 가져옴.
def GetRegVal(reg):
	GetDebuggerEvent(WFNE_SUSP, -1) #IDA SUSPEND Mode  
	reg = GetRegValue(reg)

	return reg


# Api 이름으로 주소를 찾음.
def GetAPInfo(api):
	info = {}

	for name in api:
		addr = LocByName(name)

		info[name] = addr
		print "%s: 0x%08x" % (name, addr)

	return info


def ListBptCnd(addrs, cnd):
	for addr in addrs:
		AddBpt(addr)
		SetBptCnd(addr, cnd)


def DelBptList(addrs):
	for addr in addrs: 
		DelBpt(addr)


def GetDefaultReg():
	eip      = GetRegVal("eip")
	esp 	 = GetRegVal("esp")
	argv_0   = u32(DbgRead(esp+4, 4))
	argv_1   = u32(DbgRead(esp+8, 4))
	ret_addr = u32(DbgRead(esp, 4))

	return eip, esp, argv_0, argv_1, ret_addr


def FindFuncEndAddr(addr):
	end_addr = FindFuncEnd(addr) - 1

	if DbgRead(end_addr, 1) != "\xC3":
		mem      = DbgRead(end_addr-0x30, 0x30)[::-1]
		end_addr = end_addr - (mem.find("\xC2") + 1) 

	return end_addr


def WriteLog():
	print ""
	for idx in range(len(fd)):
		print fd[idx][1]

	print ""


def TraceBuf():
	print "---------------------------------------------------------"
	print "|                   버퍼가 사용되었습니다.                |"
	print "---------------------------------------------------------"
	suspend_process()


def GetRetAddr():	
	eip, esp, argv_0, argv_1, ret_addr = GetDefaultReg()
	DelBpt(eip)

	cmt = int("%s" % Comment(eip))
	MakeComm(eip, "")

	for idx in range(len(fd)):
		if cmt == fd[idx][0]:
			fd[idx][1] += " -> \"%s\" 0x%08x" % (SegName(ret_addr), ret_addr)

			if fd[idx][2] != 0:
				ret_addr = FindFuncEndAddr(ret_addr)
				MakeComm(ret_addr, str(fd[idx][0]))	
				ListBptCnd([ret_addr], "GetRetAddr()")

				fd[idx][2] -= 1
				WriteLog()
	else:
		continue_process()



def ReadFile():
	eip, esp, argv_0, argv_1, ret_addr = GetDefaultReg()

	for idx in range(len(fd)):
		if argv_0 == fd[idx][0]:
			fd[idx][1] = "[*] 파일 입출력 트레이싱 FD:%x | " % (argv_0) 
			ret_addr = FindFuncEndAddr(ret_addr)
			MakeComm(ret_addr, str(argv_0))
			ListBptCnd([ret_addr], "GetRetAddr()")


			ListBptCnd([argv_1], "TraceBuf()")
			SetBptAttr(argv_1, BPTATTR_SIZE, 1)
			SetBptAttr(argv_1, BPTATTR_TYPE, 3)
	else:
		continue_process()



def GetFD():
	fd.append([GetRegVal("eax"), "", 4])
	eip = GetRegVal("eip")

	ListBptCnd([io_info["kernel32_ReadFile"]], "ReadFile()")


def CreatFile():
	eip, esp, argv_0, argv_1, ret_addr = GetDefaultReg()
	uni_path = DbgRead(argv_0, len(PARAMETERS)*2).replace("\x00", "")

	print "********************************* : %s : %s : %d" % (uni_path, PARAMETERS, uni_path.find(PARAMETERS))

	if uni_path == PARAMETERS:
		print uni_path, PARAMETERS, hex(ret_addr)
		ListBptCnd([ret_addr], "GetFD()")
	else:
		continue_process()


def RunTrace():
	global io_info

	io_info = GetAPInfo(API) 
	ListBptCnd([io_info["kernel32_CreateFileA"], io_info["kernel32_CreateFileW"]], "CreatFile()")
	continue_process()