@echo off
setlocal

echo ============================================
echo MACsec unit test regression
echo ============================================

call :RunProfile 1 1 || goto :RegressionFail
call :RunProfile 1 0 || goto :RegressionFail
call :RunProfile 0 1 || goto :RegressionFail

echo.
echo ============================================
echo ALL CONFIGURATIONS PASSED
echo ============================================

exit /b 0


:RunProfile
set "mka_server=%1"
set "mka_client=%2"
rem All combinations with self-tests enabled
call :RunTests 1 0 0 0 || exit /b 1
call :RunTests 1 3 0 0 || exit /b 1

call :RunTests 1 0 0 1 || exit /b 1
call :RunTests 1 3 0 1 || exit /b 1

call :RunTests 1 0 1 0 || exit /b 1
call :RunTests 1 3 1 0 || exit /b 1

call :RunTests 1 0 1 1 || exit /b 1
call :RunTests 1 3 1 1 || exit /b 1

rem Verify that the project also builds with self-tests disabled
call :BuildOnly 0 0 0 0 || exit /b 1

exit /b 0


:RunTests
echo.
echo ============================================
echo SELF_TEST=%1 DEBUG=%2 ROM=%3 FEWER=%4 SERVER=%mka_server% CLIENT=%mka_client%
echo ============================================

make clean
if errorlevel 1 goto :ConfigurationFail

make tests -j ^
    MACSEC_SELF_TEST=%1 ^
    MACSEC_MKA_SERVER_SUPPORT=%mka_server% ^
    MACSEC_MKA_CLIENT_SUPPORT=%mka_client% ^
    MACSEC_DEBUG_LEVEL=%2 ^
    MATH_AES_ROM_TABLES=%3 ^
    MATH_AES_FEWER_TABLES=%4

if errorlevel 1 goto :ConfigurationFail

echo Running tests...
build\macsec_tests.exe

if errorlevel 1 goto :ConfigurationFail

echo Configuration passed.
exit /b 0


:BuildOnly
echo.
echo ============================================
echo SELF_TEST=%1 DEBUG=%2 ROM=%3 FEWER=%4 SERVER=%mka_server% CLIENT=%mka_client%
echo BUILD ONLY
echo ============================================

make clean
if errorlevel 1 goto :ConfigurationFail

make tests -j ^
    MACSEC_SELF_TEST=%1 ^
    MACSEC_MKA_SERVER_SUPPORT=%mka_server% ^
    MACSEC_MKA_CLIENT_SUPPORT=%mka_client% ^
    MACSEC_DEBUG_LEVEL=%2 ^
    MATH_AES_ROM_TABLES=%3 ^
    MATH_AES_FEWER_TABLES=%4

if errorlevel 1 goto :ConfigurationFail

echo Configuration built successfully.
exit /b 0


:ConfigurationFail
echo.
echo ============================================
echo CONFIGURATION FAILED
echo SELF_TEST=%1 DEBUG=%2 ROM=%3 FEWER=%4 SERVER=%mka_server% CLIENT=%mka_client%
echo ============================================

exit /b 1


:RegressionFail
echo.
echo ============================================
echo REGRESSION FAILED
echo ============================================

exit /b 1
