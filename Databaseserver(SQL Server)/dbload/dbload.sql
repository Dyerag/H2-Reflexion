use master 
if exists (select * from sys.databases where name = 'DBLoad')
begin
	drop database DBLoad
end
create database DBLoad
go
use DBLoad
go
Create table Dummy
(
	idex int primary key,
	Dummy1 varchar(100) not null,
	Dummy2 varchar(100) not null,
	Kommentar varchar(100) not null,
	Dato datetime not null
)
go
Create table DummyUdenIndex
(
	idex int,
	Dummy1 varchar(100) not null,
	Dummy2 varchar(100) not null,
	Kommentar varchar(100) not null,
	Dato datetime not null
)
/*
insert into dummy values (1,'xGGzGvCtKKsACzBDxHCqsDGFFopKBvLEDvDGstEwpyoBnDHLwqGFvHHqEyoCEBCKxsMKsLFMrDvwuzpsFFEsKIvtFIwCpqwJvqxM','DFJBBqInvvFnHrnFIoCEtLDKFvBpFJDouHsEDIoCnzEInwyqMHEIGCADxyqpLssrryMHIxGMtrsrJpEEvtEvzCEGrIxyzMKvsnvA','Test af DB','02-17-2015 15:40:19'),
						(2,'BGBvMGADFptsGHJEMFHvJDzEFKuBtIwvqBpEpxEFLqKJqDuwCEywvsAsnHpJsnuIpDoLyzJKLosDxosMFuwLCJEFJxKvnnsyGHqt','ntsIrCLBzwFoHxsnxIoECCxMCMvICHLDEMLKnBEEtJMorGEFJwKCEnuIGuIwLwppvLrHKEpMDHrCvotLGIuMxBrKArGGswvEKyoK','Test af DB','02-17-2015 15:40:19')

insert into dummy values(3,'AICErpsEwtGqsrJCGqCIrGtCGEJGBJFvJLMuxFsrxtunpMqGsKEEyyBtLwLqzDHtCnDDLJKKpCoyCsuCJBssKJpxMHpCzyGEqLpE','CHwwJnFyCsxFMKMyyrpCtFLqxFIpLxoxuIKpowLoLtGCnGCynGEtsKqJsCqowtrLLsBDpxvvEDvGxHFtAILMssxFIyJpItqsytzy','Test af DB','02-17-2015 16:23:44')
*/
select count(*) from dummy
select count(*) from dummy where dummy1 like '%JJDtsDzGGq%'
select count(*) from DummyUdenIndex where dummy1 like '%JJDtsDzGGq%'