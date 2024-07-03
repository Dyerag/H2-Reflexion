REM denne batch filer opretter en masse filer i mapperne under 
REM folder

set folder=d:\firm
set ftyp= meeting,plan,inven,ref,todo,done,urgent,status
set files=100


REM ********************************************************************************************************


if not exist %folder%\nul goto err


for /f %%a in ( 'dir %folder% /S/AD/b ' ) do (
  for %%c in ( %ftyp% ) do (
    for /l %%b in ( 1,1,%files%) do echo  test file > %%a\%%~na-%%c-%%b.txt     
    )
  )


goto :eof


:err
cls
@echo thefolder   %folder% dos not exist
@pause


rem for /f %a in ( 'dir d:\Files\*.txt /s/b') do del %a