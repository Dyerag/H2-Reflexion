@Echo Husk at rename domain og server foer koersel
pause

ldifde -i -f source-ou.txt
pause
ldifde -i -f source-usr.txt
pause
ldifde -i -f source-grp.txt
pause




dsquery user -name * -limit 9999 | find /v "krbtgt" | dsmod user -disabled no -pwd Passw0rd -mustchpwd no