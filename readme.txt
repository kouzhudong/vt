/*
要使KdPrintEx((DPFLTR_IHVNETWORK_ID,...生效的两种种办法:
1.先加nt的载符号文件，
  然后运行windbg命令：ed nt!Kd_IHVNETWORK_Mask f; ed nt!Kd_DEFAULT_Mask f;ed nt!Kd_FLTMGR_Mask f
  这个办法立即生效，同时也是关闭的办法, 只需再次设置这个值为0即可。
2.另一种办法使修改注册表.
  如果用reg文件，内容如下：
  Windows Registry Editor Version 5.00

  [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter]
  "IHVNETWORK"=dword:0000000f
  但是需要重启.
*/


https://github.com/DeDf/nbp-0.32-plus
http://bbs.pediy.com/showthread.php?t=207075&highlight=vt+64
https://github.com/jonomango/hv.git


64位“最”简VT Demo code 一枚(1)


amd的虚拟化指令，如：
__svm_vmload https://msdn.microsoft.com/zh-cn/library/aa983397.aspx
__svm_vmrun https://msdn.microsoft.com/zh-cn/library/aa983395.aspx
等。


__vmx_vmlaunch https://msdn.microsoft.com/zh-cn/library/aa983377.aspx
