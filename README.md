# sander

Command line utility for interfacing with the Adobe Reader sandbox. Allows one to monitor, dump, and send IPC requests to the Adobe Reader broker process. See the blogpost [here](TODO) for more information.

## Usage

```
$ sander.exe -h
[-] sander: [action] <pid>
          -m   -  Monitor mode
          -d   -  Dump channels
          -t   -  Trigger test call (tag 62)
          -h   -  Print this menu
```

The provided PID should be that of the broker process and not a sandboxed child. Example monitor mode output:

```
$ sander.exe -m 4200
[5184] ESP: 02e1f764    Buffer 029f0134 Tag 266 1 Parameters
      WCHAR_TYPE: _WVWT*&^$
[5184] ESP: 02e1f764    Buffer 029f0134 Tag 34  1 Parameters
      WCHAR_TYPE: C:\Users\bja\desktop\test.pdf
[5184] ESP: 02e1f764    Buffer 029f0134 Tag 247 2 Parameters
      WCHAR_TYPE: C:\Users\bja\desktop\test.pdf
      ULONG_TYPE: 00000000
[5184] ESP: 02e1f764    Buffer 029f0134 Tag 16  6 Parameters
      WCHAR_TYPE: Software\Adobe\Acrobat Reader\DC\SessionManagement
      ULONG_TYPE: 00000040
      VOIDPTR_TYPE: 00000434
      ULONG_TYPE: 000f003f
      ULONG_TYPE: 00000000
      ULONG_TYPE: 00000000
[6020] ESP: 037dfca4    Buffer 029f0134 Tag 16  6 Parameters
      WCHAR_TYPE: cWindowsCurrent
      ULONG_TYPE: 00000040
      VOIDPTR_TYPE: 0000043c
      ULONG_TYPE: 000f003f
      ULONG_TYPE: 00000000
      ULONG_TYPE: 00000000
[5184] ESP: 02e1f764    Buffer 029f0134 Tag 16  6 Parameters
      WCHAR_TYPE: cWin0
      ULONG_TYPE: 00000040
      VOIDPTR_TYPE: 00000434
      ULONG_TYPE: 000f003f
      ULONG_TYPE: 00000000
      ULONG_TYPE: 00000000
[5184] ESP: 02e1f764    Buffer 029f0134 Tag 17  4 Parameters
      WCHAR_TYPE: cTab0
      ULONG_TYPE: 00000040
      VOIDPTR_TYPE: 00000298
      ULONG_TYPE: 000f003f
[2572] ESP: 0335fd5c    Buffer 029f0134 Tag 17  4 Parameters
      WCHAR_TYPE: cPathInfo
      ULONG_TYPE: 00000040
      VOIDPTR_TYPE: 000003cc
      ULONG_TYPE: 000f003f
```

The output is formatted in a way to be helpful at-a-glance as well as aid in more aggressive reversing/investigation.

The `-d` flag will provide a dump of all 16 sandbox channels in a format similar to monitor mode.

## Building

Compiled using Visual Studio 2017. Ensure you clone for submodules.

```
git clone --recurse-submodules -j8 
```

Only supports x86 since there's only an x86 Adobe Reader.