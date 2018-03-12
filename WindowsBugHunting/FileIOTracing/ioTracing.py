#-*-coding: utf-8

# Windows Application Bug hunting support script  
# Copyright (c) 2018 Team f1ay - ddddh
#
# All rights reserved.


from idaapi 	   import *
from idc           import *
from idautils      import *
from threading     import *

from ddddh         import *


# ALSee, DaView 등으로 테스트 해봄. 
# CreateFilew API로 fd를 받지 않으면 작동이 안됌. 향후 업데이트 예정이나 군대 때문에 언제 될지 모름.ㅋㅋㅋㅋ

# Python 으로 활성화
RunPlugin("python", 3)  # https://github.com/tmr232/idapython


# 사용전에 타겟을 셋팅을 해주십시오.
PARAMETERS   = r"C:\Users\ddddh\Desktop\LAST_EXPLOIT\ex\not_kitty.bmp" # 해당 애플리케이션에서 처리할 파일
API          = ["kernel32_ReadFile", "kernel32_CreateFileW", "kernel32_CreateFileA", "kernel32_CloseHandle"]


def Run():
	while GetProcessState() != -1:
		pass

	RunTrace()


def Main():
	RefreshDebuggerMemory()

	try:
		if debughook:
			print("Removing previous hook ...")
			debughook.unhook()
	except:
		pass

	ep = GetLongPrm(INF_START_IP)

	RunTo(ep)
	GetDebuggerEvent(WFNE_SUSP, -1)

	t = Thread(target=Run, args=())
	t.daemon = True
	t.start()


if __name__ == "__main__":
	Main()