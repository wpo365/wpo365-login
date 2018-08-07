$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$config = (Get-Content -Raw -Path "$scriptDir\plugin-archive.json" | ConvertFrom-Json).config

$distFolder = Join-Path (Get-Item $scriptDir).Parent.FullName "dist"
$tmpFolder = Join-Path $distFolder $config.slug
$pluginArchive = Join-Path $distFolder "$($config.slug).zip"

if($false -eq (Test-Path -Path $distFolder)) {
    Write-Host "Created 'dist' folder"
    New-Item -ItemType directory -Path $distFolder
}

if($false -eq (Test-Path -Path $tmpFolder)) {
    Write-Host "Created temporary 'dist\$($config.slug)' folder"
    New-Item -ItemType directory -Path $tmpFolder
}

Write-Host "Cleaning temporary 'dist\$($config.slug)' folder"
Remove-Item $distFolder\* -Recurse -Force

ForEach($item in $config.folders) {
    Write-Host "Copying folder '$item' to temporary 'dist\$($config.slug)' folder"
    $source = Join-Path (Get-Item $scriptDir).Parent.FullName $item
    $destination = Join-Path $tmpFolder $item
    Copy-Item $source -Destination $destination -Recurse
}

ForEach($item in $config.files) {
    Write-Host "Copying file '$item' to temporary 'dist\$($config.slug)' folder"
    $source = Join-Path (Get-Item $scriptDir).Parent.FullName $item
    $destination = Join-Path $tmpFolder $item
    Copy-Item $source -Destination $destination
}

Write-Host "Creating plugin archive $pluginArchive"

# Add-Type -Assembly System.IO.Compression.FileSystem
# $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
# [System.IO.Compression.ZipFile]::CreateFromDirectory($tmpFolder, $pluginArchive, $compressionLevel, $false)

& "C:\Program Files\7-Zip\7z.exe" -mx=9 a $pluginArchive $tmpFolder

Write-Host "Cleaning temporary 'dist\$($config.slug)' folder"
Remove-Item $tmpFolder -Recurse -Force

if($true -eq (Test-Path -Path $config.copyTo)) {
    Write-Host "Copying $pluginArchive to $($config.copyTo)"
    Copy-Item $pluginArchive -Destination $($config.copyTo) -Force
}

Write-Host "Done..."