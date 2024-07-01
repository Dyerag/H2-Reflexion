Bulk insert Filmdb.dbo.Skuespiller
from 'C:\Users\Tec\Downloads\Afsluttende SQL opgave\Data\Skuespiller.txt'
with
(
codepage = 'ACP',
batchsize = 250,
datafiletype = 'char',
Fieldterminator = ',',
rowterminator = '\n',
maxerrors = 50,
tablock)
go

Bulk insert Filmdb.dbo.Genre
from 'C:\Users\Tec\Downloads\Afsluttende SQL opgave\Data\Genre.txt'
with
(
codepage = 'ACP',
batchsize = 250,
datafiletype = 'char',
Fieldterminator = ',',
rowterminator = '\n',
maxerrors = 50,
tablock)
go

Bulk insert Filmdb.dbo.Film
from 'C:\Users\Tec\Downloads\Afsluttende SQL opgave\Data\Film.txt'
with
(
codepage = 'ACP',
batchsize = 250,
datafiletype = 'char',
Fieldterminator = ',',
rowterminator = '\n',
maxerrors = 50,
tablock)
go