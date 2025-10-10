# ReVanced Magisk Module

[![CI](https://github.com/j-hc/revanced-magisk-module/actions/workflows/ci.yml/badge.svg?event=schedule)](https://github.com/Viole403/revanced-magisk-module/actions/workflows/ci.yml)

Extensive ReVanced builder

Get the [latest CI release](https://github.com/Viole403/revanced-magisk-module/releases).

Use [**zygisk-detach**](https://github.com/j-hc/zygisk-detach) to detach YouTube and YT Music from Play Store if you are using magisk modules.

## Features

- Support all present and future ReVanced and [ReVanced Extended](https://github.com/inotia00/revanced-patches) apps
- Can build Magisk modules and non-root APKs
- Updated daily with the latest versions of apps and patches
- Optimize APKs and modules for size
- Modules:
  - recompile invalidated odex for faster usage
  - receive updates from Magisk app
  - do not break safetynet or trigger root detections
  - handle installation of the correct version of the stock app and all that
  - support Magisk and KernelSU

Note: that the [CI workflow](../../actions/workflows/ci.yml) is scheduled to build the modules and APKs everyday using GitHub Actions if there is a change in ReVanced patches. You may want to disable it.

## To include/exclude patches or patch other apps

- Star the repo :eyes:
- Use the repo as a [template](https://github.com/new?template_name=revanced-magisk-module&template_owner=Viole403)
- Run the build [workflow](../../actions/workflows/build.yml)
- Grab your modules and APKs from [releases](../../releases)

also see here [`CONFIG.md`](./CONFIG.md)

## Building Locally

### On Termux

```console
bash <(curl -sSf https://raw.githubusercontent.com/Viole403/revanced-magisk-module/main/build-termux.sh)
```

### On Desktop

```console
git clone https://github.com/Viole403/revanced-magisk-module
cd revanced-magisk-module
./build.sh
```
