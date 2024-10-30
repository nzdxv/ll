workspace "ll"

architecture "x86_64"

configurations { "dev", "rel" }

project "ll"

kind "consoleapp"

language "c++"
cppdialect "c++20"

targetdir "%{wks.location}/build/"
objdir "%{wks.location}/build/obj/%{prj.name}-%{cfg.buildcfg}/"

targetname "ll"

files {
    "src/**.h",
    "src/**.cpp"
}

includedirs {
    "src/"
}

links {

}

filter "configurations:dev"
defines { "_DEV" }
symbols "on"
optimize "off"

filter "configurations:rel"
defines { "_REL" }
symbols "off"
optimize "full"
