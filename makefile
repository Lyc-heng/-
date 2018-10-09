filename  = main
format = c

all : main.exe

$(filename).exe: $(filename).obj
         echo $(format)
         link /nologo User32.lib kernel32.lib ucrt.lib /entry:main /align:16 /subsystem:console $(filename).obj

$(filename).obj: $(filename).$(format)
          cl.exe /nologo /c /TC $(filename).$(format)

clean :
      del $(filename).obj $(filename).exe

rebuild: clean $(filename).exe	  
#-c: 编译但不链接
#/NOLOGO： 取消显示启动版权标志
#/SUBSYSTEM：指定子系统，在PC桌面程序上一般是两个选项：console(控制台程序)和WINDOWS(非控制台程序)。