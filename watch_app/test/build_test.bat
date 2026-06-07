@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
cd /d "C:\Users\East-Yang\PrivateGallery\watch_app\test"
cl.exe /nologo /std:c11 /W3 /O2 /Fe:test_core.exe test_core.c 2>&1
