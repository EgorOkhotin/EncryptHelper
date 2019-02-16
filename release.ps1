cd ./EncryptHelper
gulp build-release
cd ..
dotnet restore
dotnet build -c Release
cd ./EncryptHelper
electronize build /target win