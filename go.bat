@REM GO.BAT, Itzik Kotler, See: https://github.com/SafeBreach-Labs/spacebin
@REM ----------------------------------------------------------------------
@REM
@REM Copyright (c) 2016, SafeBreach
@REM All rights reserved.
@REM
@REM Redistribution and use in source and binary forms, with or without
@REM modification, are permitted provided that the following conditions are
@REM met:
@REM
@REM  1. Redistributions of source code must retain the above
@REM copyright notice, this list of conditions and the following
@REM disclaimer.
@REM
@REM  2. Redistributions in binary form must reproduce the
@REM above copyright notice, this list of conditions and the following
@REM disclaimer in the documentation and/or other materials provided with
@REM the distribution.
@REM
@REM  3. Neither the name of the copyright holder
@REM nor the names of its contributors may be used to endorse or promote
@REM products derived from this software without specific prior written
@REM permission.
@REM
@REM THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
@REM AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
@REM INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
@REM MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
@REM IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
@REM ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
@REM DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
@REM GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
@REM INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
@REM IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
@REM OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
@REM ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
@ECHO OFF

CLS

ECHO **************************
ECHO * Running mkbinrocket.py *
ECHO **************************
ECHO.
IF EXIST .\binsatellite\Release\binsatellite.exe (SET BinSatellitePath=".\binsatellite\Release") ELSE (SET BinSatellitePath=".\binsatellite\x64\Release")
python .\binrocket\mkbinrocket.py %BinSatellitePath%\binsatellite.exe houston.c

ECHO.
ECHO ***********************
ECHO * Compiling houston.c *
ECHO ***********************
ECHO.
CL /MT houston.c

ECHO.
ECHO *********************
ECHO * Running houston.c *
ECHO *********************
ECHO.
houston.exe /D
IF [%1] == [] (houston.exe) ELSE (houston.exe %*)

ECHO.
ECHO ****************************
ECHO * Houston, We Have Liftoff *
ECHO ****************************
