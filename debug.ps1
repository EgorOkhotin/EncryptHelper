cd ./EncryptHelper
gulp build-debug
cd ..
dotnet restore
dotnet build -c Debug
cd ./EncryptHelper
dotnet run -c Debug
