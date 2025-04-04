#addin nuget:?package=Cake.FileHelpers&version=5.0.0

var target = Argument("target", "Default");
var configuration = Argument("configuration", "Release");

// Build properties
var buildDate = EnvironmentVariable("BUILD_DATE") ?? "2025-04-04 04:55:49";
var buildUser = EnvironmentVariable("BUILD_USER") ?? "AnmiTaliDev";
var projectFile = "../src/ATE.csproj";
var outputDir = "../artifacts";

Setup(context =>
{
    Information("Building ATE...");
    Information($"Build User: {buildUser}");
});

Task("Clean")
    .Does(() =>
    {
        CleanDirectory(outputDir);
        CleanDirectories("../src/**/bin");
        CleanDirectories("../src/**/obj");
    });

Task("UpdateBuildInfo")
    .Does(() =>
    {
        var file = ReplaceTextInFiles(projectFile, 
            @"<BuildDate>.*<\/BuildDate>", 
            $"<BuildDate>{buildDate}</BuildDate>");
            
        ReplaceTextInFiles(projectFile, 
            @"<BuildUser>.*<\/BuildUser>", 
            $"<BuildUser>{buildUser}</BuildUser>");
    });

Task("Restore")
    .Does(() =>
    {
        DotNetRestore(projectFile, new DotNetRestoreSettings 
        {
            Runtime = "linux-x64"
        });
    });

Task("Build")
    .IsDependentOn("Clean")
    .IsDependentOn("UpdateBuildInfo")
    .IsDependentOn("Restore")
    .Does(() =>
    {
        DotNetPublish(projectFile, new DotNetPublishSettings 
        {
            Configuration = configuration,
            Runtime = "linux-x64",
            SelfContained = true,
            PublishSingleFile = true,
            OutputDirectory = outputDir,
            ArgumentCustomization = args => args
                .Append("/p:DebugType=None")
                .Append("/p:DebugSymbols=false")
        });
    });

Task("Install")
    .IsDependentOn("Build")
    .Does(() =>
    {
        if (IsRunningOnUnix())
        {
            var binPath = "/usr/local/bin/ate";
            var exePath = $"{outputDir}/ate";
            
            if (FileExists(binPath))
            {
                DeleteFile(binPath);
            }
            
            Information("Creating symbolic link...");
            StartProcess("sudo", new ProcessSettings 
            { 
                Arguments = $"ln -sf {exePath} {binPath}" 
            });
        }
        else
        {
            Warning("Installation is only supported on Linux.");
        }
    });

Task("Default")
    .IsDependentOn("Build");

RunTarget(target);