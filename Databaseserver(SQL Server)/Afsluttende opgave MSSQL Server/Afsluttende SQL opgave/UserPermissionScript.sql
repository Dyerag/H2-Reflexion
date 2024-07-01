USE Filmdb
GO

grant insert on Film to FilmProvider
GO

grant insert on schema:: dbo to FilmManager
GO
grant update on schema::dbo to FilmManager
GO